use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use filecoin_proofs::error::ExpectWithBacktrace;

use crate::error::Result;
use crate::scheduler::Request;
use crate::{PoRepConfig, UnpaddedByteIndex, UnpaddedBytesAmount};
use std::path::PathBuf;
use storage_proofs::sector::SectorId;

const FATAL_NOLOCK: &str = "error acquiring task lock";
const FATAL_RCVTSK: &str = "error receiving seal task";
const FATAL_SNDRLT: &str = "error sending result";

pub struct SealerWorker {
    pub id: usize,
    pub thread: Option<thread::JoinHandle<()>>,
}

pub enum SealerInput {
    Seal {
        piece_lens: Vec<UnpaddedBytesAmount>,
        porep_config: PoRepConfig,
        sealed_sector_access: String,
        sealed_sector_path: PathBuf,
        sector_id: SectorId,
        staged_sector_path: PathBuf,
        done_tx: mpsc::SyncSender<Request>,
    },
    Unseal {
        porep_config: PoRepConfig,
        source_path: PathBuf,
        destination_path: PathBuf,
        sector_id: SectorId,
        piece_start_byte: UnpaddedByteIndex,
        piece_len: UnpaddedBytesAmount,
        caller_done_tx: mpsc::SyncSender<Result<Vec<u8>>>,
        done_tx: mpsc::SyncSender<Request>,
    },
    Shutdown,
}

impl SealerWorker {
    pub fn start(
        id: usize,
        seal_task_rx: Arc<Mutex<mpsc::Receiver<SealerInput>>>,
        prover_id: [u8; 31],
    ) -> SealerWorker {
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
                SealerInput::Seal {
                    porep_config,
                    sector_id,
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
                        &prover_id,
                        sector_id,
                        &piece_lens,
                    );

                    done_tx
                        .send(Request::HandleSealResult(
                            sector_id,
                            sealed_sector_access,
                            sealed_sector_path,
                            result,
                        ))
                        .expects(FATAL_SNDRLT);
                }
                SealerInput::Unseal {
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
                        .send(Request::HandleRetrievePieceResult(result, caller_done_tx))
                        .expects(FATAL_SNDRLT);
                }
                SealerInput::Shutdown => break,
            }
        });

        SealerWorker {
            id,
            thread: Some(thread),
        }
    }
}
