use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use filecoin_proofs::error::ExpectWithBacktrace;

use crate::error::Result;
use crate::scheduler::SchedulerTask;
use crate::{PoRepConfig, SealTicket, UnpaddedByteIndex, UnpaddedBytesAmount};
use std::path::PathBuf;
use storage_proofs::sector::SectorId;

const FATAL_NOLOCK: &str = "error acquiring task lock";
const FATAL_RCVTSK: &str = "error receiving seal task";
const FATAL_SNDRLT: &str = "error sending result";

pub struct Worker {
    pub id: usize,
    pub thread: Option<thread::JoinHandle<()>>,
}

pub struct UnsealTaskPrototype {
    pub(crate) comm_d: [u8; 32],
    pub(crate) destination_path: PathBuf,
    pub(crate) piece_len: UnpaddedBytesAmount,
    pub(crate) piece_start_byte: UnpaddedByteIndex,
    pub(crate) porep_config: PoRepConfig,
    pub(crate) seal_ticket: SealTicket,
    pub(crate) sector_id: SectorId,
    pub(crate) source_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SealTaskPrototype {
    pub(crate) piece_lens: Vec<UnpaddedBytesAmount>,
    pub(crate) porep_config: PoRepConfig,
    pub(crate) seal_ticket: SealTicket,
    pub(crate) sealed_sector_access: String,
    pub(crate) sealed_sector_path: PathBuf,
    pub(crate) sector_id: SectorId,
    pub(crate) staged_sector_path: PathBuf,
}

pub enum WorkerTask<T> {
    Seal {
        piece_lens: Vec<UnpaddedBytesAmount>,
        porep_config: PoRepConfig,
        seal_ticket: SealTicket,
        sealed_sector_access: String,
        sealed_sector_path: PathBuf,
        sector_id: SectorId,
        staged_sector_path: PathBuf,
        done_tx: mpsc::SyncSender<SchedulerTask<T>>,
    },
    Unseal {
        caller_done_tx: mpsc::SyncSender<Result<Vec<u8>>>,
        comm_d: [u8; 32],
        destination_path: PathBuf,
        piece_len: UnpaddedBytesAmount,
        piece_start_byte: UnpaddedByteIndex,
        porep_config: PoRepConfig,
        seal_ticket: SealTicket,
        sector_id: SectorId,
        source_path: PathBuf,
        done_tx: mpsc::SyncSender<SchedulerTask<T>>,
    },
    Shutdown,
}

impl<T> WorkerTask<T> {
    pub fn from_seal_proto(
        proto: SealTaskPrototype,
        done_tx: mpsc::SyncSender<SchedulerTask<T>>,
    ) -> WorkerTask<T> {
        let SealTaskPrototype {
            piece_lens,
            porep_config,
            seal_ticket,
            sealed_sector_access,
            sealed_sector_path,
            sector_id,
            staged_sector_path,
        } = proto;

        WorkerTask::Seal {
            piece_lens,
            porep_config,
            seal_ticket,
            sealed_sector_access,
            sealed_sector_path,
            sector_id,
            staged_sector_path,
            done_tx,
        }
    }

    pub fn from_unseal_proto(
        proto: UnsealTaskPrototype,
        caller_done_tx: mpsc::SyncSender<Result<Vec<u8>>>,
        done_tx: mpsc::SyncSender<SchedulerTask<T>>,
    ) -> WorkerTask<T> {
        let UnsealTaskPrototype {
            comm_d,
            destination_path,
            piece_len,
            piece_start_byte,
            porep_config,
            seal_ticket,
            sector_id,
            source_path,
        } = proto;

        WorkerTask::Unseal {
            caller_done_tx,
            comm_d,
            destination_path,
            piece_len,
            piece_start_byte,
            porep_config,
            seal_ticket,
            sector_id,
            source_path,
            done_tx,
        }
    }
}

impl Worker {
    pub fn start<T: 'static + Send>(
        id: usize,
        seal_task_rx: Arc<Mutex<mpsc::Receiver<WorkerTask<T>>>>,
        prover_id: [u8; 32],
    ) -> Worker {
        let thread = thread::spawn(move || loop {
            // Acquire a lock on the rx end of the channel, get a task,
            // relinquish the lock and return the task. The receiver is mutexed
            // for coordinating reads across multiple worker-threads.
            let task = {
                let rx = seal_task_rx.lock().expects(FATAL_NOLOCK);
                rx.recv().expects(FATAL_RCVTSK)
            };

            // Dispatch to the appropriate task-handler.
            match task {
                WorkerTask::Seal {
                    porep_config,
                    sector_id,
                    seal_ticket,
                    sealed_sector_access,
                    sealed_sector_path,
                    staged_sector_path,
                    piece_lens,
                    done_tx,
                } => {
                    let result = filecoin_proofs::seal(
                        porep_config,
                        &staged_sector_path,
                        &sealed_sector_path,
                        prover_id,
                        sector_id,
                        seal_ticket.bytes,
                        &piece_lens,
                    );

                    done_tx
                        .send(SchedulerTask::HandleSealResult {
                            sector_id,
                            sector_access: sealed_sector_access,
                            sector_path: sealed_sector_path,
                            seal_ticket,
                            result,
                        })
                        .expects(FATAL_SNDRLT);
                }
                WorkerTask::Unseal {
                    caller_done_tx,
                    comm_d,
                    destination_path,
                    piece_len,
                    piece_start_byte,
                    porep_config,
                    seal_ticket,
                    sector_id,
                    source_path,
                    done_tx,
                } => {
                    let result = filecoin_proofs::get_unsealed_range(
                        porep_config,
                        &source_path,
                        &destination_path,
                        prover_id,
                        sector_id,
                        comm_d,
                        seal_ticket.bytes,
                        piece_start_byte,
                        piece_len,
                    )
                    .map(|num_bytes_unsealed| (num_bytes_unsealed, destination_path));

                    done_tx
                        .send(SchedulerTask::HandleRetrievePieceResult(
                            result,
                            caller_done_tx,
                        ))
                        .expects(FATAL_SNDRLT);
                }
                WorkerTask::Shutdown => break,
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}
