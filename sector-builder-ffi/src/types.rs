use std::ffi::CString;
use std::mem;
use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
use failure::Error;
use ffi_toolkit::{free_c_str, rust_str_to_c_str};
use filecoin_proofs::SectorClass;
use libc;
use sector_builder::{
    PieceMetadata, SealSeed, SealStatus, SealTicket, SealedSectorHealth, SealedSectorMetadata,
    SectorBuilderErr, SectorManagerErr,
};

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum FFISealedSectorHealth {
    Unknown = 0,
    Ok = 1,
    ErrorInvalidChecksum = 2,
    ErrorInvalidLength = 3,
    ErrorMissing = 4,
}

impl From<SealedSectorHealth> for FFISealedSectorHealth {
    fn from(status: SealedSectorHealth) -> Self {
        match status {
            SealedSectorHealth::Ok => FFISealedSectorHealth::Ok,
            SealedSectorHealth::ErrorInvalidChecksum => FFISealedSectorHealth::ErrorInvalidChecksum,
            SealedSectorHealth::ErrorInvalidLength => FFISealedSectorHealth::ErrorInvalidLength,
            SealedSectorHealth::ErrorMissing => FFISealedSectorHealth::ErrorMissing,
        }
    }
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum FCPResponseStatus {
    // Don't use FCPSuccess, since that complicates description of 'successful' verification.
    FCPNoError = 0,
    FCPUnclassifiedError = 1,
    FCPCallerError = 2,
    FCPReceiverError = 3,
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum FFISealStatus {
    AcceptingPieces = 0,
    Committed = 1,
    Committing = 2,
    CommittingPaused = 3,
    Failed = 4,
    FullyPacked = 5,
    PreCommitted = 6,
    PreCommitting = 7,
    PreCommittingPaused = 8,
}

impl From<SealStatus> for FFISealStatus {
    fn from(ss: SealStatus) -> Self {
        match ss {
            SealStatus::AcceptingPieces => FFISealStatus::AcceptingPieces,
            SealStatus::Committed(_) => FFISealStatus::Committed,
            SealStatus::Committing(_, _, _, _) => FFISealStatus::Committing,
            SealStatus::CommittingPaused(_, _, _, _) => FFISealStatus::CommittingPaused,
            SealStatus::Failed(_) => FFISealStatus::Failed,
            SealStatus::PreCommitted(_, _, _) => FFISealStatus::PreCommitted,
            SealStatus::PreCommitting(_) => FFISealStatus::PreCommitting,
            SealStatus::PreCommittingPaused(_) => FFISealStatus::PreCommittingPaused,
            SealStatus::FullyPacked => FFISealStatus::FullyPacked,
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GeneratePoStResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub proof_len: libc::size_t,
    pub proof_ptr: *const u8,
}

impl Default for GeneratePoStResponse {
    fn default() -> GeneratePoStResponse {
        GeneratePoStResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            proof_len: 0,
            proof_ptr: ptr::null(),
        }
    }
}

// err_code_and_msg accepts an Error struct and produces a tuple of response
// status code and a pointer to a C string, both of which can be used to set
// fields in a response struct to be returned from an FFI call.
pub fn err_code_and_msg(err: &Error) -> (FCPResponseStatus, *const libc::c_char) {
    use crate::types::FCPResponseStatus::*;

    let msg = CString::new(format!("{}", err)).unwrap();
    let ptr = msg.as_ptr();
    mem::forget(msg);

    match err.downcast_ref() {
        Some(SectorBuilderErr::OverflowError { .. }) => return (FCPCallerError, ptr),
        Some(SectorBuilderErr::IncompleteWriteError { .. }) => return (FCPReceiverError, ptr),
        Some(SectorBuilderErr::Unrecoverable(_, _)) => return (FCPReceiverError, ptr),
        Some(SectorBuilderErr::PieceNotFound(_)) => return (FCPCallerError, ptr),
        None => (),
    }

    match err.downcast_ref() {
        Some(SectorManagerErr::UnclassifiedError(_)) => return (FCPUnclassifiedError, ptr),
        Some(SectorManagerErr::CallerError(_)) => return (FCPCallerError, ptr),
        Some(SectorManagerErr::ReceiverError(_)) => return (FCPReceiverError, ptr),
        None => (),
    }

    (FCPUnclassifiedError, ptr)
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct InitSectorBuilderResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_builder: *mut SectorBuilder,
}

impl Default for InitSectorBuilderResponse {
    fn default() -> InitSectorBuilderResponse {
        InitSectorBuilderResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_builder: ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct ResumeSealPreCommitResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for ResumeSealPreCommitResponse {
    fn default() -> ResumeSealPreCommitResponse {
        ResumeSealPreCommitResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct ResumeSealCommitResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub meta: FFISealedSectorMetadata,
}

impl Default for ResumeSealCommitResponse {
    fn default() -> ResumeSealCommitResponse {
        ResumeSealCommitResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            meta: unsafe { mem::zeroed() },
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealPreCommitResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for SealPreCommitResponse {
    fn default() -> SealPreCommitResponse {
        SealPreCommitResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealCommitResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub meta: FFISealedSectorMetadata,
}

impl Default for SealCommitResponse {
    fn default() -> SealCommitResponse {
        SealCommitResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            meta: unsafe { mem::zeroed() },
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct AddPieceResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_id: u64,
}

impl Default for AddPieceResponse {
    fn default() -> AddPieceResponse {
        AddPieceResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_id: 0,
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct ReadPieceFromSealedSectorResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub data_len: libc::size_t,
    pub data_ptr: *const u8,
}

impl Default for ReadPieceFromSealedSectorResponse {
    fn default() -> ReadPieceFromSealedSectorResponse {
        ReadPieceFromSealedSectorResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            data_len: 0,
            data_ptr: ptr::null(),
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealAllStagedSectorsResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub meta_len: libc::size_t,
    pub meta_ptr: *const FFISealedSectorMetadata,
}

impl Default for SealAllStagedSectorsResponse {
    fn default() -> SealAllStagedSectorsResponse {
        SealAllStagedSectorsResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            meta_len: 0,
            meta_ptr: ptr::null(),
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GetSealStatusResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub seal_status_code: FFISealStatus,

    // sealing failed - here's the error
    pub seal_error_msg: *const libc::c_char,

    // sealed sector metadata
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
    pub seal_ticket: FFISealTicket,
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub proof_len: libc::size_t,
    pub proof_ptr: *const u8,
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct FFIPieceMetadata {
    pub piece_key: *const libc::c_char,
    pub num_bytes: u64,
    pub comm_p: [u8; 32],
}

impl From<PieceMetadata> for FFIPieceMetadata {
    fn from(meta: PieceMetadata) -> Self {
        FFIPieceMetadata {
            piece_key: rust_str_to_c_str(meta.piece_key.to_string()),
            num_bytes: meta.num_bytes.into(),
            comm_p: meta.comm_p,
        }
    }
}

impl Default for GetSealStatusResponse {
    fn default() -> GetSealStatusResponse {
        GetSealStatusResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            comm_d: Default::default(),
            comm_r: Default::default(),
            pieces_len: 0,
            pieces_ptr: ptr::null(),
            proof_len: 0,
            proof_ptr: ptr::null(),
            seal_error_msg: ptr::null(),
            seal_status_code: FFISealStatus::Failed,
            sector_access: ptr::null(),
            sector_id: 0,
            seal_ticket: FFISealTicket {
                block_height: 0,
                ticket_bytes: Default::default(),
            },
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct FFIStagedSectorMetadata {
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,
    pub seal_status_code: FFISealStatus,
    // if sealing failed - here's the error
    pub seal_error_msg: *const libc::c_char,
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct FFISealedSectorMetadata {
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
    pub health: FFISealedSectorHealth,
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,
    pub proofs_len: libc::size_t,
    pub proofs_ptr: *const u8,
    pub seal_ticket: FFISealTicket,
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
}

impl From<SealedSectorMetadata> for FFISealedSectorMetadata {
    fn from(meta: SealedSectorMetadata) -> Self {
        let pieces = meta
            .pieces
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<FFIPieceMetadata>>();

        let snark_proof = meta.proof.clone();

        let sector = FFISealedSectorMetadata {
            seal_ticket: FFISealTicket {
                block_height: meta.ticket.block_height,
                ticket_bytes: meta.ticket.ticket_bytes,
            },
            comm_d: meta.comm_d,
            comm_r: meta.comm_r,
            pieces_len: pieces.len(),
            pieces_ptr: pieces.as_ptr(),
            proofs_len: snark_proof.len(),
            proofs_ptr: snark_proof.as_ptr(),
            sector_access: rust_str_to_c_str(meta.sector_access.clone()),
            sector_id: u64::from(meta.sector_id),
            health: FFISealedSectorHealth::Unknown,
        };

        mem::forget(snark_proof);
        mem::forget(pieces);

        sector
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GetSealedSectorsResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub meta_len: libc::size_t,
    pub meta_ptr: *const FFISealedSectorMetadata,
}

impl Default for GetSealedSectorsResponse {
    fn default() -> GetSealedSectorsResponse {
        GetSealedSectorsResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            meta_len: 0,
            meta_ptr: ptr::null(),
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GetStagedSectorsResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub sectors_len: libc::size_t,
    pub sectors_ptr: *const FFIStagedSectorMetadata,
}

impl Default for GetStagedSectorsResponse {
    fn default() -> GetStagedSectorsResponse {
        GetStagedSectorsResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sectors_len: 0,
            sectors_ptr: ptr::null(),
        }
    }
}

#[repr(C)]
pub struct FFISectorClass {
    sector_size: u64,
    porep_proof_partitions: u8,
}

impl From<FFISectorClass> for SectorClass {
    fn from(fsc: FFISectorClass) -> Self {
        let FFISectorClass {
            sector_size,
            porep_proof_partitions,
        } = fsc;

        SectorClass(
            filecoin_proofs::SectorSize(sector_size),
            filecoin_proofs::PoRepProofPartitions(porep_proof_partitions),
        )
    }
}

pub type SectorBuilder = sector_builder::SectorBuilder<FileDescriptorRef>;

/// Filedescriptor, that does not drop the file descriptor when dropped.
pub struct FileDescriptorRef(nodrop::NoDrop<std::fs::File>);

impl FileDescriptorRef {
    #[cfg(not(target_os = "windows"))]
    pub unsafe fn new(raw: std::os::unix::io::RawFd) -> Self {
        use std::os::unix::io::FromRawFd;
        FileDescriptorRef(nodrop::NoDrop::new(std::fs::File::from_raw_fd(raw)))
    }
}

impl std::io::Read for FileDescriptorRef {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

#[repr(C)]
pub struct FFISealSeed {
    /// the height at which we chose the ticket
    pub block_height: u64,

    /// bytes of the minimum ticket chosen from a block with given height
    pub ticket_bytes: [u8; 32],
}

impl From<FFISealSeed> for SealSeed {
    fn from(fss: FFISealSeed) -> Self {
        match fss {
            FFISealSeed {
                block_height,
                ticket_bytes,
            } => sector_builder::SealSeed {
                block_height,
                ticket_bytes,
            },
        }
    }
}

#[repr(C)]
pub struct FFISealTicket {
    /// the height at which we chose the ticket
    pub block_height: u64,

    /// bytes of the minimum ticket chosen from a block with given height
    pub ticket_bytes: [u8; 32],
}

impl From<FFISealTicket> for SealTicket {
    fn from(fst: FFISealTicket) -> Self {
        match fst {
            FFISealTicket {
                block_height,
                ticket_bytes,
            } => sector_builder::SealTicket {
                block_height,
                ticket_bytes,
            },
        }
    }
}