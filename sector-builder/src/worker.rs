use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use filecoin_proofs::error::ExpectWithBacktrace;

use crate::error::Result;
use crate::scheduler::{SchedulerTask, SealResult};
use crate::{
    PoRepConfig, SealTicket, SealedSectorMetadata, UnpaddedByteIndex, UnpaddedBytesAmount,
};
use filecoin_proofs::{PoStConfig, PrivateReplicaInfo};
use std::collections::btree_map::BTreeMap;
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
pub struct GeneratePoStTaskPrototype {
    pub(crate) challenge_seed: [u8; 32],
    pub(crate) private_replicas: BTreeMap<SectorId, PrivateReplicaInfo>,
    pub(crate) post_config: PoStConfig,
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

pub struct SealInput {
    piece_lens: Vec<UnpaddedBytesAmount>,
    porep_config: PoRepConfig,
    seal_ticket: SealTicket,
    sealed_sector_access: String,
    sealed_sector_path: PathBuf,
    sector_id: SectorId,
    staged_sector_path: PathBuf,
}

pub enum WorkerTask<T> {
    GeneratePoSt {
        challenge_seed: [u8; 32],
        private_replicas: BTreeMap<SectorId, PrivateReplicaInfo>,
        post_config: PoStConfig,
        done_tx: mpsc::SyncSender<Result<Vec<u8>>>,
    },
    SealMultiple {
        seal_inputs: Vec<SealInput>,
        caller_done_tx: mpsc::SyncSender<Result<Vec<SealedSectorMetadata>>>,
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
    pub fn from_generate_post_proto(
        proto: GeneratePoStTaskPrototype,
        done_tx: mpsc::SyncSender<Result<Vec<u8>>>,
    ) -> WorkerTask<T> {
        WorkerTask::GeneratePoSt {
            challenge_seed: proto.challenge_seed,
            done_tx,
            post_config: proto.post_config,
            private_replicas: proto.private_replicas,
        }
    }

    pub fn from_seal_protos(
        protos: Vec<SealTaskPrototype>,
        caller_done_tx: mpsc::SyncSender<Result<Vec<SealedSectorMetadata>>>,
        done_tx: mpsc::SyncSender<SchedulerTask<T>>,
    ) -> WorkerTask<T> {
        WorkerTask::SealMultiple {
            caller_done_tx,
            done_tx,
            seal_inputs: protos
                .into_iter()
                .map(|proto| SealInput {
                    piece_lens: proto.piece_lens,
                    porep_config: proto.porep_config,
                    seal_ticket: proto.seal_ticket,
                    sealed_sector_access: proto.sealed_sector_access,
                    sealed_sector_path: proto.sealed_sector_path,
                    sector_id: proto.sector_id,
                    staged_sector_path: proto.staged_sector_path,
                })
                .collect(),
        }
    }

    pub fn from_unseal_proto(
        proto: UnsealTaskPrototype,
        caller_done_tx: mpsc::SyncSender<Result<Vec<u8>>>,
        done_tx: mpsc::SyncSender<SchedulerTask<T>>,
    ) -> WorkerTask<T> {
        WorkerTask::Unseal {
            caller_done_tx,
            comm_d: proto.comm_d,
            destination_path: proto.destination_path,
            done_tx,
            piece_len: proto.piece_len,
            piece_start_byte: proto.piece_start_byte,
            porep_config: proto.porep_config,
            seal_ticket: proto.seal_ticket,
            sector_id: proto.sector_id,
            source_path: proto.source_path,
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
                WorkerTask::GeneratePoSt {
                    challenge_seed,
                    private_replicas,
                    post_config,
                    done_tx,
                } => {
                    done_tx
                        .send(filecoin_proofs::generate_post(
                            post_config,
                            &challenge_seed,
                            &private_replicas,
                        ))
                        .expects(FATAL_SNDRLT);
                }
                WorkerTask::SealMultiple {
                    seal_inputs,
                    caller_done_tx,
                    done_tx,
                } => {
                    let mut output: Vec<SealResult> = Vec::with_capacity(seal_inputs.len());

                    for input in seal_inputs {
                        let result = filecoin_proofs::seal(
                            input.porep_config,
                            &input.staged_sector_path,
                            &input.sealed_sector_path,
                            prover_id,
                            input.sector_id,
                            input.seal_ticket.ticket_bytes,
                            &input.piece_lens,
                        );

                        output.push(SealResult {
                            sector_id: input.sector_id,
                            sector_access: input.sealed_sector_access,
                            sector_path: input.sealed_sector_path,
                            seal_ticket: input.seal_ticket,
                            proofs_api_call_result: result,
                        });
                    }

                    done_tx
                        .send(SchedulerTask::OnSealMultipleComplete {
                            output,
                            caller_done_tx,
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
                        seal_ticket.ticket_bytes,
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
