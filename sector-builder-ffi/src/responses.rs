use std::ffi::CString;
use std::mem;
use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
use failure::Error;
use ffi_toolkit::{free_c_str, rust_str_to_c_str};
use libc;
use sector_builder::{
    PieceMetadata, SealedSectorHealth, SealedSectorMetadata, SectorBuilderErr, SectorManagerErr,
};

use crate::api::{FFISealTicket, SectorBuilder};

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
    Sealed = 0,
    Pending = 1,
    Failed = 2,
    Sealing = 3,
    ReadyForSealing = 4,
    Paused = 5,
}

///////////////////////////////////////////////////////////////////////////////
/// GeneratePoSTResult
//////////////////////

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
    use crate::responses::FCPResponseStatus::*;

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

///////////////////////////////////////////////////////////////////////////////
/// InitSectorBuilderResponse
/////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
/// ResumeSealSectorResponse
////////////////////////////

#[repr(C)]
#[derive(DropStructMacro)]
pub struct ResumeSealSectorResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub meta: FFISealedSectorMetadata,
}

impl Default for ResumeSealSectorResponse {
    fn default() -> ResumeSealSectorResponse {
        ResumeSealSectorResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            meta: unsafe { mem::zeroed() },
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// SealSectorResponse
//////////////////////

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealSectorResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub meta: FFISealedSectorMetadata,
}

impl Default for SealSectorResponse {
    fn default() -> SealSectorResponse {
        SealSectorResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            meta: unsafe { mem::zeroed() },
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// AddPieceResponse
////////////////////

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

////////////////////////////////////////////////////////////////////////////////
/// ReadPieceFromSealedSectorResponse
/////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
/// SealAllStagedSectorsResponse
////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
/// GetSealStatusResponse
/////////////////////////

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
    pub piece_inclusion_proof_ptr: *const u8,
    pub piece_inclusion_proof_len: libc::size_t,
}

impl From<PieceMetadata> for FFIPieceMetadata {
    fn from(meta: PieceMetadata) -> Self {
        let (len, ptr) = match &meta.piece_inclusion_proof {
            Some(proof) => {
                let buf = proof.clone();

                let len = buf.len();
                let ptr = buf.as_ptr();

                mem::forget(buf);

                (len, ptr)
            }
            None => (0, ptr::null()),
        };

        FFIPieceMetadata {
            piece_key: rust_str_to_c_str(meta.piece_key.to_string()),
            num_bytes: meta.num_bytes.into(),
            comm_p: meta.comm_p.unwrap_or([0; 32]),
            piece_inclusion_proof_len: len,
            piece_inclusion_proof_ptr: ptr,
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

///////////////////////////////////////////////////////////////////////////////
/// FFIStagedSectorMetadata
///////////////////////////

#[repr(C)]
#[derive(DropStructMacro)]
pub struct FFIStagedSectorMetadata {
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,

    // must be one of: Pending, Failed, Sealing
    pub seal_status_code: FFISealStatus,

    // if sealing failed - here's the error
    pub seal_error_msg: *const libc::c_char,
}

///////////////////////////////////////////////////////////////////////////////
/// FFISealedSectorMetadata
///////////////////////////

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
                block_height: meta.seal_ticket.block_height,
                ticket_bytes: meta.seal_ticket.ticket_bytes,
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

///////////////////////////////////////////////////////////////////////////////
/// GetSealedSectorsResponse
////////////////////////////

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GetSealedSectorsResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub sectors_len: libc::size_t,
    pub sectors_ptr: *const FFISealedSectorMetadata,
}

impl Default for GetSealedSectorsResponse {
    fn default() -> GetSealedSectorsResponse {
        GetSealedSectorsResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sectors_len: 0,
            sectors_ptr: ptr::null(),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// GetStagedSectorsResponse
////////////////////////////

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
