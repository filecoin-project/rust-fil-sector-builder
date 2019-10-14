use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use filecoin_proofs::error::ExpectWithBacktrace;
use filecoin_proofs::SealOutput;
use storage_proofs::sector::SectorId;

use crate::error::Result;
use crate::kv_store::KeyValueStore;
use crate::metadata::{SealStatus, StagedSectorMetadata};
use crate::store::SectorStore;
use crate::worker::WorkerTask;
use crate::{
    GetSealedSectorResult, SealTicket, SecondsSinceEpoch, SectorMetadataManager,
    UnpaddedBytesAmount,
};

const FATAL_NORECV: &str = "could not receive task";
const FATAL_NOSEND: &str = "could not send";

pub struct Scheduler {
    pub thread: Option<thread::JoinHandle<()>>,
}

#[derive(Debug)]
pub struct PerformHealthCheck(pub bool);

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SchedulerTask<T> {
    AddPiece(
        String,
        u64,
        T,
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
    SetCurrentSealTicket(SealTicket, mpsc::SyncSender<Result<()>>),
    HandleSealResult {
        sector_id: SectorId,
        sector_access: String,
        sector_path: PathBuf,
        seal_ticket: SealTicket,
        result: Result<SealOutput>,
    },
    HandleRetrievePieceResult(
        Result<(UnpaddedBytesAmount, PathBuf)>,
        mpsc::SyncSender<Result<Vec<u8>>>,
    ),
    Shutdown,
}

impl Scheduler {
    #[allow(clippy::too_many_arguments)]
    pub fn start<
        T: 'static + KeyValueStore,
        S: 'static + SectorStore,
        U: 'static + std::io::Read + Send,
    >(
        scheduler_tx: mpsc::SyncSender<SchedulerTask<U>>,
        scheduler_rx: mpsc::Receiver<SchedulerTask<U>>,
        worker_tx: mpsc::Sender<WorkerTask<U>>,
        mut m: SectorMetadataManager<T, S>,
    ) -> Result<Scheduler> {
        // If a previous instance of the SectorBuilder was shut down mid-seal,
        // its metadata store will contain staged sectors who are still
        // "Sealing." If we do have any of those when we start the Scheduler,
        // we should immediately restart sealing.
        //
        // For more information, see rust-fil-sector-builder/17.
        let protos = m.create_seal_task_protos(|x| {
            x.seal_status == SealStatus::Sealing(Default::default())
        })?;

        for p in protos {
            worker_tx
                .send(WorkerTask::from_seal_proto(p, scheduler_tx.clone()))
                .expects(FATAL_NOSEND);
        }

        let thread = thread::spawn(move || {
            loop {
                let task = scheduler_rx.recv().expects(FATAL_NORECV);

                // Dispatch to the appropriate task-handler.
                match task {
                    SchedulerTask::AddPiece(key, amt, file, store_until, tx) => {
                        match m.add_piece(key, amt, file, store_until) {
                            Ok(sector_id) => {
                                tx.send(Ok(sector_id)).expects(FATAL_NOSEND);
                            }
                            Err(err) => {
                                tx.send(Err(err)).expects(FATAL_NOSEND);
                            }
                        }
                    }
                    SchedulerTask::GetSealStatus(sector_id, tx) => {
                        tx.send(m.get_seal_status(sector_id)).expects(FATAL_NOSEND);
                    }
                    SchedulerTask::RetrievePiece(piece_key, tx) => {
                        match m.create_retrieve_piece_task_proto(piece_key) {
                            Ok(proto) => {
                                worker_tx
                                    .send(WorkerTask::from_unseal_proto(
                                        proto,
                                        tx.clone(),
                                        scheduler_tx.clone(),
                                    ))
                                    .expects(FATAL_NOSEND);
                            }
                            Err(err) => {
                                tx.send(Err(err)).expects(FATAL_NOSEND);
                            }
                        }
                    }
                    SchedulerTask::GetSealedSectors(check_health, tx) => {
                        tx.send(m.get_sealed_sectors(check_health.0))
                            .expects(FATAL_NOSEND);
                    }
                    SchedulerTask::GetStagedSectors(tx) => {
                        tx.send(Ok(m
                            .get_staged_sectors_filtered(|_| true)
                            .into_iter()
                            .cloned()
                            .collect()))
                            .expect(FATAL_NOSEND);
                    }
                    SchedulerTask::SealAllStagedSectors(tx) => {
                        m.mark_all_sectors_for_sealing();

                        match m.create_seal_task_protos(|x| {
                            x.seal_status == SealStatus::ReadyForSealing
                        }) {
                            Ok(protos) => {
                                for p in protos {
                                    m.commit_sector_to_ticket(&p.sector_id, &p.seal_ticket);

                                    worker_tx
                                        .send(WorkerTask::from_seal_proto(
                                            p.clone(),
                                            scheduler_tx.clone(),
                                        ))
                                        .expects(FATAL_NOSEND);
                                }

                                tx.send(Ok(())).expects(FATAL_NOSEND);
                            }
                            Err(err) => {
                                tx.send(Err(err)).expects(FATAL_NOSEND);
                            }
                        }
                    }
                    SchedulerTask::SetCurrentSealTicket(seal_ticket, tx) => {
                        m.set_current_seal_ticket(seal_ticket);

                        match m.create_seal_task_protos(|x| {
                            x.seal_status == SealStatus::ReadyForSealing
                        }) {
                            Ok(protos) => {
                                for p in protos {
                                    m.commit_sector_to_ticket(&p.sector_id, &p.seal_ticket);

                                    worker_tx
                                        .send(WorkerTask::from_seal_proto(
                                            p.clone(),
                                            scheduler_tx.clone(),
                                        ))
                                        .expects(FATAL_NOSEND);
                                }

                                tx.send(Ok(())).expects(FATAL_NOSEND);
                            }
                            Err(err) => {
                                tx.send(Err(err)).expects(FATAL_NOSEND);
                            }
                        }
                    }
                    SchedulerTask::HandleSealResult {
                        sector_id,
                        sector_access,
                        sector_path,
                        seal_ticket,
                        result,
                    } => {
                        m.handle_seal_result(
                            sector_id,
                            sector_access,
                            sector_path,
                            seal_ticket,
                            result,
                        );
                    }
                    SchedulerTask::HandleRetrievePieceResult(result, tx) => {
                        tx.send(m.read_unsealed_bytes_from(result))
                            .expects(FATAL_NOSEND);
                    }
                    SchedulerTask::GeneratePoSt(comm_rs, chg_seed, faults, tx) => {
                        let proto = m.create_generate_post_task_proto(&comm_rs, &chg_seed, faults);

                        worker_tx
                            .send(WorkerTask::from_generate_post_proto(proto, tx.clone()))
                            .expects(FATAL_NOSEND);
                    }
                    SchedulerTask::Shutdown => break,
                }
            }
        });

        Ok(Scheduler {
            thread: Some(thread),
        })
    }
}
