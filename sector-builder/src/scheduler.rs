use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use filecoin_proofs::error::ExpectWithBacktrace;
use filecoin_proofs::{generate_post, PrivateReplicaInfo, SealOutput};
use storage_proofs::sector::SectorId;

use crate::error::{err_piecenotfound, err_unrecov, Result};
use crate::helpers::SnapshotKey;
use crate::kv_store::KeyValueStore;
use crate::metadata::{SealStatus, SealedSectorMetadata, StagedSectorMetadata};
use crate::state::SectorBuilderState;
use crate::store::SectorStore;
use crate::worker::WorkerTask;
use crate::GetSealedSectorResult::WithHealth;
use crate::{
    GetSealedSectorResult, PaddedBytesAmount, PieceMetadata, SecondsSinceEpoch, UnpaddedBytesAmount,
};
use filecoin_proofs::pieces::get_piece_start_byte;

const FATAL_NORECV: &str = "could not receive task";
const FATAL_NOSEND: &str = "could not send";
const FATAL_SNPSHT: &str = "could not snapshot";
const FATAL_SLRSND: &str = "could not send to sealer";
const FATAL_HUNGUP: &str = "could not send to ret channel";
const FATAL_NOSECT: &str = "could not find sector";

pub struct Scheduler {
    pub thread: Option<thread::JoinHandle<()>>,
}

#[derive(Debug)]
pub struct PerformHealthCheck(pub bool);

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SchedulerTask {
    AddPiece(
        String,
        u64,
        String,
        SecondsSinceEpoch,
        mpsc::SyncSender<Result<SectorId>>,
    ),
    GetSealedSectors(
        PerformHealthCheck,
        mpsc::SyncSender<Result<Vec<GetSealedSectorResult>>>,
    ),
    GetStagedSectors(mpsc::SyncSender<Result<Vec<StagedSectorMetadata>>>),
    GetSealStatus(SectorId, mpsc::SyncSender<Result<SealStatus>>),
    GeneratePoSt(
        Vec<[u8; 32]>,
        [u8; 32],      // seed
        Vec<SectorId>, // faults
        mpsc::SyncSender<Result<Vec<u8>>>,
    ),
    RetrievePiece(String, mpsc::SyncSender<Result<Vec<u8>>>),
    SealAllStagedSectors(mpsc::SyncSender<Result<()>>),
    HandleSealResult(SectorId, String, PathBuf, Result<SealOutput>),
    HandleRetrievePieceResult(
        Result<(UnpaddedBytesAmount, PathBuf)>,
        mpsc::SyncSender<Result<Vec<u8>>>,
    ),
    Shutdown,
}

impl Scheduler {
    #[allow(clippy::too_many_arguments)]
    pub fn start<T: 'static + KeyValueStore, S: 'static + SectorStore>(
        scheduler_input_rx: mpsc::Receiver<SchedulerTask>,
        mut m: SectorMetadataManager<T, S>,
    ) -> Scheduler {
        let thread = thread::spawn(move || {
            loop {
                let task = scheduler_input_rx.recv().expects(FATAL_NORECV);

                // Dispatch to the appropriate task-handler.
                match task {
                    SchedulerTask::AddPiece(key, amt, path, store_until, tx) => {
                        tx.send(m.add_piece(key, amt, path, store_until))
                            .expects(FATAL_NOSEND);
                    }
                    SchedulerTask::GetSealStatus(sector_id, tx) => {
                        tx.send(m.get_seal_status(sector_id)).expects(FATAL_NOSEND);
                    }
                    SchedulerTask::RetrievePiece(piece_key, tx) => m.retrieve_piece(piece_key, tx),
                    SchedulerTask::GetSealedSectors(check_health, tx) => {
                        tx.send(m.get_sealed_sectors(check_health.0))
                            .expects(FATAL_NOSEND);
                    }
                    SchedulerTask::GetStagedSectors(tx) => {
                        tx.send(m.get_staged_sectors()).expect(FATAL_NOSEND);
                    }
                    SchedulerTask::SealAllStagedSectors(tx) => {
                        tx.send(m.seal_all_staged_sectors()).expects(FATAL_NOSEND);
                    }
                    SchedulerTask::HandleSealResult(sector_id, access, path, result) => {
                        m.handle_seal_result(sector_id, access, path, result);
                    }
                    SchedulerTask::HandleRetrievePieceResult(result, tx) => {
                        m.handle_retrieve_piece_result(result, tx);
                    }
                    SchedulerTask::GeneratePoSt(comm_rs, chg_seed, faults, tx) => {
                        m.generate_post(&comm_rs, &chg_seed, faults, tx)
                    }
                    SchedulerTask::Shutdown => break,
                }
            }
        });

        Scheduler {
            thread: Some(thread),
        }
    }
}

// The SectorBuilderStateManager is the owner of all sector-related metadata.
// It dispatches expensive operations (e.g. unseal and seal) to the sealer
// worker-threads. Other, inexpensive work (or work which needs to be performed
// serially) is handled by the SectorBuilderStateManager itself.
pub struct SectorMetadataManager<T: KeyValueStore, S: SectorStore> {
    pub kv_store: T,
    pub sector_store: S,
    pub state: SectorBuilderState,
    pub sealer_input_tx: mpsc::Sender<WorkerTask>,
    pub scheduler_input_tx: mpsc::SyncSender<SchedulerTask>,
    pub max_num_staged_sectors: u8,
    pub max_user_bytes_per_staged_sector: UnpaddedBytesAmount,
    pub prover_id: [u8; 31],
    pub sector_size: PaddedBytesAmount,
}

impl<T: KeyValueStore, S: SectorStore> SectorMetadataManager<T, S> {
    pub fn generate_post(
        &self,
        comm_rs: &[[u8; 32]],
        challenge_seed: &[u8; 32],
        faults: Vec<SectorId>,
        return_channel: mpsc::SyncSender<Result<Vec<u8>>>,
    ) {
        let fault_set: HashSet<SectorId> = faults.into_iter().collect();

        let comm_rs_set: HashSet<&[u8; 32]> = comm_rs.iter().collect();

        let mut replicas: BTreeMap<SectorId, PrivateReplicaInfo> = Default::default();

        for sector in self.state.sealed.sectors.values() {
            if comm_rs_set.contains(&sector.comm_r) {
                let path_str = self
                    .sector_store
                    .manager()
                    .sealed_sector_path(&sector.sector_access)
                    .to_str()
                    .map(str::to_string)
                    .unwrap();

                let info = if fault_set.contains(&sector.sector_id) {
                    PrivateReplicaInfo::new_faulty(path_str, sector.comm_r)
                } else {
                    PrivateReplicaInfo::new(path_str, sector.comm_r)
                };

                replicas.insert(sector.sector_id, info);
            }
        }

        let output = generate_post(
            self.sector_store.proofs_config().post_config(),
            challenge_seed,
            &replicas,
        );

        // TODO: Where should this work be scheduled? New worker type?
        return_channel.send(output).expects(FATAL_HUNGUP);
    }

    // Schedules unseal on worker thread. Any errors encountered while
    // retrieving are send to done_tx.
    pub fn retrieve_piece(&self, piece_key: String, done_tx: mpsc::SyncSender<Result<Vec<u8>>>) {
        let done_tx_c = done_tx.clone();

        let task = Ok(()).and_then(|_| {
            let opt_sealed_sector = self.state.sealed.sectors.values().find(|sector| {
                sector
                    .pieces
                    .iter()
                    .any(|piece| piece.piece_key == piece_key)
            });

            opt_sealed_sector
                .ok_or_else(|| err_piecenotfound(piece_key.to_string()).into())
                .and_then(|sealed_sector| {
                    let piece = sealed_sector
                        .pieces
                        .iter()
                        .find(|p| p.piece_key == piece_key)
                        .ok_or_else(|| err_piecenotfound(piece_key.clone()))?;

                    let piece_lengths: Vec<_> = sealed_sector
                        .pieces
                        .iter()
                        .take_while(|p| p.piece_key != piece_key)
                        .map(|p| p.num_bytes)
                        .collect();

                    let staged_sector_access = self
                        .sector_store
                        .manager()
                        .new_staging_sector_access(sealed_sector.sector_id)
                        .map_err(failure::Error::from)?;

                    Ok(WorkerTask::Unseal {
                        porep_config: self.sector_store.proofs_config().porep_config(),
                        source_path: self
                            .sector_store
                            .manager()
                            .sealed_sector_path(&sealed_sector.sector_access),
                        destination_path: self
                            .sector_store
                            .manager()
                            .staged_sector_path(&staged_sector_access),
                        sector_id: sealed_sector.sector_id,
                        piece_start_byte: get_piece_start_byte(&piece_lengths, piece.num_bytes),
                        piece_len: piece.num_bytes,
                        caller_done_tx: done_tx_c,
                        done_tx: self.scheduler_input_tx.clone(),
                    })
                })
        });

        match task {
            Ok(task) => self
                .sealer_input_tx
                .clone()
                .send(task)
                .expects(FATAL_SLRSND),
            Err(err) => {
                self.scheduler_input_tx
                    .send(SchedulerTask::HandleRetrievePieceResult(Err(err), done_tx))
                    .expects(FATAL_SLRSND);
            }
        }
    }

    // Returns sealing status for the sector with specified id. If no sealed or
    // staged sector exists with the provided id, produce an error.
    pub fn get_seal_status(&self, sector_id: SectorId) -> Result<SealStatus> {
        crate::helpers::get_seal_status(&self.state.staged, &self.state.sealed, sector_id)
    }

    // Write the piece to storage, obtaining the sector id with which the
    // piece-bytes are now associated.
    pub fn add_piece(
        &mut self,
        piece_key: String,
        piece_bytes_amount: u64,
        piece_path: String,
        store_until: SecondsSinceEpoch,
    ) -> Result<SectorId> {
        let destination_sector_id = crate::helpers::add_piece(
            &self.sector_store,
            &mut self.state.staged,
            piece_key,
            piece_bytes_amount,
            piece_path,
            store_until,
        )?;

        self.check_and_schedule(false)?;
        self.checkpoint()?;

        Ok(destination_sector_id)
    }

    // For demo purposes. Schedules sealing of all staged sectors.
    pub fn seal_all_staged_sectors(&mut self) -> Result<()> {
        self.check_and_schedule(true)?;
        self.checkpoint()
    }

    // Produces a vector containing metadata for all sealed sectors that this
    // SectorBuilder knows about. Includes sector health-information on request.
    pub fn get_sealed_sectors(&self, check_health: bool) -> Result<Vec<GetSealedSectorResult>> {
        use rayon::prelude::*;

        let sectors_iter = self.state.sealed.sectors.values().cloned();

        if !check_health {
            return Ok(sectors_iter
                .map(GetSealedSectorResult::WithoutHealth)
                .collect());
        }

        let with_path: Vec<(PathBuf, SealedSectorMetadata)> = sectors_iter
            .map(|meta| {
                let pbuf = self
                    .sector_store
                    .manager()
                    .sealed_sector_path(&meta.sector_access);

                (pbuf, meta)
            })
            .collect();

        // compute sector health in parallel using workers from rayon global
        // thread pool
        with_path
            .into_par_iter()
            .map(|(pbuf, meta)| {
                let health = crate::helpers::get_sealed_sector_health(&pbuf, &meta)?;
                Ok(WithHealth(health, meta))
            })
            .collect()
    }

    // Produces a vector containing metadata for all staged sectors that this
    // SectorBuilder knows about.
    pub fn get_staged_sectors(&self) -> Result<Vec<StagedSectorMetadata>> {
        Ok(self.state.staged.sectors.values().cloned().collect())
    }

    // Update metadata to reflect the sealing results.
    pub fn handle_retrieve_piece_result(
        &mut self,
        result: Result<(UnpaddedBytesAmount, PathBuf)>,
        return_channel: mpsc::SyncSender<Result<Vec<u8>>>,
    ) {
        let result = result.and_then(|(n, pbuf)| {
            let buffer = self.sector_store.manager().read_raw(
                pbuf.to_str()
                    .ok_or_else(|| format_err!("conversion failed"))?,
                0,
                n,
            )?;

            Ok(buffer)
        });

        return_channel.send(result).expects(FATAL_NOSEND);
    }

    // Update metadata to reflect the sealing results.
    pub fn handle_seal_result(
        &mut self,
        sector_id: SectorId,
        sector_access: String,
        sector_path: PathBuf,
        result: Result<SealOutput>,
    ) {
        // scope exists to end the mutable borrow of self so that we can
        // checkpoint
        {
            let staged_state = &mut self.state.staged;
            let sealed_state = &mut self.state.sealed;

            let staged_sector = staged_state
                .sectors
                .get_mut(&sector_id)
                .expect("missing staged sector");

            let _ = result
                .and_then(|output| {
                    let SealOutput {
                        comm_r,
                        comm_r_star,
                        comm_d,
                        proof,
                        comm_ps,
                        piece_inclusion_proofs,
                    } = output;

                    // generate checksum
                    let blake2b_checksum = crate::helpers::calculate_checksum(&sector_path)?
                        .as_ref()
                        .to_vec();

                    // get number of bytes in sealed sector-file
                    let len = std::fs::metadata(&sector_path)?.len();

                    // combine the piece commitment, piece inclusion proof, and other piece
                    // metadata into a single struct (to be persisted to metadata store)
                    let pieces = staged_sector
                        .clone()
                        .pieces
                        .into_iter()
                        .zip(comm_ps.iter())
                        .zip(piece_inclusion_proofs.into_iter())
                        .map(|((piece, &comm_p), piece_inclusion_proof)| PieceMetadata {
                            piece_key: piece.piece_key,
                            num_bytes: piece.num_bytes,
                            comm_p: Some(comm_p),
                            piece_inclusion_proof: Some(piece_inclusion_proof.into()),
                        })
                        .collect();

                    let meta = SealedSectorMetadata {
                        sector_id: staged_sector.sector_id,
                        sector_access,
                        pieces,
                        comm_r_star,
                        comm_r,
                        comm_d,
                        proof,
                        blake2b_checksum,
                        len,
                    };

                    Ok(meta)
                })
                .map_err(|err| {
                    staged_sector.seal_status = SealStatus::Failed(format!("{}", err_unrecov(err)));
                })
                .map(|meta| {
                    sealed_state.sectors.insert(sector_id, meta.clone());
                    staged_sector.seal_status = SealStatus::Sealed(Box::new(meta));
                });
        }

        self.checkpoint().expects(FATAL_SNPSHT);
    }

    // Check for sectors which should no longer receive new user piece-bytes and
    // schedule them for sealing.
    fn check_and_schedule(&mut self, seal_all_staged_sectors: bool) -> Result<()> {
        let staged_state = &mut self.state.staged;

        let to_be_sealed = crate::helpers::get_sectors_ready_for_sealing(
            staged_state,
            self.max_user_bytes_per_staged_sector,
            self.max_num_staged_sectors,
            seal_all_staged_sectors,
        );

        // Mark the to-be-sealed sectors as no longer accepting data and then
        // schedule sealing.
        for sector_id in to_be_sealed {
            let mut staged_sector = staged_state
                .sectors
                .get_mut(&sector_id)
                .expects(FATAL_NOSECT);

            // Provision a new sealed sector access through the manager.
            let sealed_sector_access = self
                .sector_store
                .manager()
                .new_sealed_sector_access(staged_sector.sector_id)
                .map_err(failure::Error::from)?;

            let sealed_sector_path = self
                .sector_store
                .manager()
                .sealed_sector_path(&sealed_sector_access);

            let staged_sector_path = self
                .sector_store
                .manager()
                .staged_sector_path(&staged_sector.sector_access);

            let piece_lens = staged_sector
                .pieces
                .iter()
                .map(|p| p.num_bytes)
                .collect::<Vec<UnpaddedBytesAmount>>();

            // mutate staged sector state such that we don't try to write any
            // more pieces to it
            staged_sector.seal_status = SealStatus::Sealing;

            self.sealer_input_tx
                .clone()
                .send(WorkerTask::Seal {
                    piece_lens,
                    porep_config: self.sector_store.proofs_config().porep_config(),
                    sealed_sector_access,
                    sealed_sector_path,
                    sector_id,
                    staged_sector_path,
                    done_tx: self.scheduler_input_tx.clone(),
                })
                .expects(FATAL_SLRSND);
        }

        Ok(())
    }

    // Create and persist metadata snapshot.
    fn checkpoint(&self) -> Result<()> {
        crate::helpers::persist_snapshot(
            &self.kv_store,
            &SnapshotKey::new(self.prover_id, self.sector_size),
            &self.state,
        )?;

        Ok(())
    }
}
