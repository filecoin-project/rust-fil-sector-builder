use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use filecoin_proofs::error::ExpectWithBacktrace;

use crate::error::Result;
use crate::scheduler::SchedulerTask;
use crate::{PoRepConfig, UnpaddedByteIndex, UnpaddedBytesAmount};
use nix::unistd::ForkResult;
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
    pub(crate) destination_path: PathBuf,
    pub(crate) piece_len: UnpaddedBytesAmount,
    pub(crate) piece_start_byte: UnpaddedByteIndex,
    pub(crate) porep_config: PoRepConfig,
    pub(crate) sector_id: SectorId,
    pub(crate) source_path: PathBuf,
}

pub struct SealTaskPrototype {
    pub(crate) piece_lens: Vec<UnpaddedBytesAmount>,
    pub(crate) porep_config: PoRepConfig,
    pub(crate) sealed_sector_access: String,
    pub(crate) sealed_sector_path: PathBuf,
    pub(crate) sector_id: SectorId,
    pub(crate) staged_sector_path: PathBuf,
}

pub enum WorkerTask<T> {
    Seal {
        piece_lens: Vec<UnpaddedBytesAmount>,
        porep_config: PoRepConfig,
        sealed_sector_access: String,
        sealed_sector_path: PathBuf,
        sector_id: SectorId,
        staged_sector_path: PathBuf,
        done_tx: mpsc::SyncSender<SchedulerTask<T>>,
    },
    Unseal {
        porep_config: PoRepConfig,
        source_path: PathBuf,
        destination_path: PathBuf,
        sector_id: SectorId,
        piece_start_byte: UnpaddedByteIndex,
        piece_len: UnpaddedBytesAmount,
        caller_done_tx: mpsc::SyncSender<Result<Vec<u8>>>,
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
            sealed_sector_access,
            sealed_sector_path,
            sector_id,
            staged_sector_path,
        } = proto;

        WorkerTask::Seal {
            piece_lens,
            porep_config,
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
            porep_config,
            source_path,
            destination_path,
            sector_id,
            piece_start_byte,
            piece_len,
        } = proto;

        WorkerTask::Unseal {
            porep_config,
            source_path,
            destination_path,
            sector_id,
            piece_start_byte,
            piece_len,
            caller_done_tx,
            done_tx,
        }
    }
}

impl Worker {
    pub fn start<T: 'static + Send>(
        id: usize,
        seal_task_rx: Arc<Mutex<mpsc::Receiver<WorkerTask<T>>>>,
        prover_id: [u8; 31],
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
                    sealed_sector_access,
                    sealed_sector_path,
                    staged_sector_path,
                    piece_lens,
                    done_tx,
                } => {
                    let (mut inner_done_tx, mut inner_done_rx) = pipe_channel::channel();

                    match nix::unistd::fork() {
                        Ok(ForkResult::Parent { child, .. }) => {
                            let result = inner_done_rx.recv().unwrap();

                            // send SIGTERM to the child process
                            nix::sys::signal::kill(child, nix::sys::signal::SIGTERM).unwrap();

                            // wait for the child process to die
                            nix::sys::wait::waitpid(child, None).unwrap();

                            done_tx
                                .send(SchedulerTask::HandleSealResult(
                                    sector_id,
                                    sealed_sector_access,
                                    sealed_sector_path,
                                    result,
                                ))
                                .expects(FATAL_SNDRLT);
                        }
                        Ok(ForkResult::Child) => {
                            // make this thread a low priority
                            unsafe { libc::nice(19) };

                            let result = filecoin_proofs::seal(
                                porep_config,
                                &staged_sector_path,
                                &sealed_sector_path,
                                &prover_id,
                                sector_id,
                                &piece_lens,
                            );

                            // send the completion signal
                            inner_done_tx.send(result).expect("failed to send");
                        }
                        Err(err) => panic!(err),
                    }
                }
                WorkerTask::Unseal {
                    porep_config,
                    source_path,
                    destination_path,
                    sector_id,
                    piece_start_byte,
                    piece_len,
                    caller_done_tx,
                    done_tx,
                } => {
                    let result = filecoin_proofs::get_unsealed_range(
                        porep_config,
                        &source_path,
                        &destination_path,
                        &prover_id,
                        sector_id,
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
