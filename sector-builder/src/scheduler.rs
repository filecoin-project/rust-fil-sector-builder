use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use filecoin_proofs::error::ExpectWithBacktrace;
use storage_proofs::sector::SectorId;

use crate::error::Result;
use crate::kv_store::KeyValueStore;
use crate::metadata::{SealStatus, StagedSectorMetadata};
use crate::store::SectorStore;
use crate::worker::WorkerTask;
use crate::{
    GetSealedSectorResult, SealTicket, SealedSectorMetadata, SecondsSinceEpoch,
    SectorMetadataManager, UnpaddedBytesAmount,
};

const FATAL_NORECV: &str = "could not receive task";
const FATAL_NOSEND: &str = "could not send";

pub struct Scheduler {
    pub thread: Option<thread::JoinHandle<()>>,
}

#[derive(Debug)]
pub struct PerformHealthCheck(pub bool);

#[derive(Debug)]
pub struct SealResult {
    pub sector_id: SectorId,
    pub sector_access: String,
    pub sector_path: PathBuf,
    pub seal_ticket: SealTicket,
    pub proofs_api_call_result: Result<filecoin_proofs::SealOutput>,
}

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
    SealAllStagedSectors(
        SealTicket,
        mpsc::SyncSender<Result<Vec<SealedSectorMetadata>>>,
    ),
    ResumeSealSector(
        SectorId,
        mpsc::SyncSender<Result<Vec<SealedSectorMetadata>>>,
    ),
    SealSector(
        SectorId,
        SealTicket,
        mpsc::SyncSender<Result<Vec<SealedSectorMetadata>>>,
    ),
    OnSealMultipleComplete {
        output: Vec<SealResult>,
        caller_done_tx: mpsc::SyncSender<Result<Vec<SealedSectorMetadata>>>,
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
                        tx.send(m.get_sealed_sectors_filtered(check_health.0, |_| true))
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
                    SchedulerTask::SealAllStagedSectors(seal_ticket, tx) => {
                        m.mark_all_sectors_for_sealing();

                        let r_protos = m.create_seal_task_protos(seal_ticket, |x| {
                            x.seal_status.is_ready_for_sealing()
                        });

                        match r_protos {
                            Ok(protos) => {
                                for p in &protos {
                                    m.commit_sector_to_ticket(
                                        p.sector_id.clone(),
                                        p.seal_ticket.clone(),
                                    );
                                }

                                worker_tx
                                    .send(WorkerTask::from_seal_protos(
                                        protos,
                                        tx,
                                        scheduler_tx.clone(),
                                    ))
                                    .expects(FATAL_NOSEND);
                            }
                            Err(err) => {
                                tx.send(Err(err)).expects(FATAL_NOSEND);
                            }
                        }
                    }
                    SchedulerTask::ResumeSealSector(sector_id, tx) => {
                        let r_protos = m.create_resume_seal_task_protos(|x| {
                            x.seal_status.is_paused() && x.sector_id == sector_id
                        });

                        match r_protos {
                            Ok(protos) => {
                                for p in &protos {
                                    m.commit_sector_to_ticket(
                                        p.sector_id.clone(),
                                        p.seal_ticket.clone(),
                                    );
                                }

                                worker_tx
                                    .send(WorkerTask::from_seal_protos(
                                        protos,
                                        tx,
                                        scheduler_tx.clone(),
                                    ))
                                    .expects(FATAL_NOSEND);
                            }
                            Err(err) => {
                                tx.send(Err(err)).expects(FATAL_NOSEND);
                            }
                        }
                    }
                    SchedulerTask::SealSector(sector_id, seal_ticket, tx) => {
                        m.mark_all_sectors_for_sealing();

                        let r_protos = m.create_seal_task_protos(seal_ticket, |x| {
                            x.sector_id == sector_id && x.seal_status.is_ready_for_sealing()
                        });

                        match r_protos {
                            Ok(protos) => {
                                for p in &protos {
                                    m.commit_sector_to_ticket(
                                        p.sector_id.clone(),
                                        p.seal_ticket.clone(),
                                    );
                                }

                                worker_tx
                                    .send(WorkerTask::from_seal_protos(
                                        protos,
                                        tx,
                                        scheduler_tx.clone(),
                                    ))
                                    .expects(FATAL_NOSEND);
                            }
                            Err(err) => {
                                tx.send(Err(err)).expects(FATAL_NOSEND);
                            }
                        }
                    }
                    SchedulerTask::OnSealMultipleComplete {
                        output,
                        caller_done_tx,
                    } => {
                        let r: Result<Vec<SealedSectorMetadata>> = output
                            .into_iter()
                            .map(|o| m.handle_seal_result(o))
                            .collect();

                        caller_done_tx.send(r).expects(FATAL_NOSEND);
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
