use std::mem;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::slice::from_raw_parts;

use libc;
use slog::*;

use ffi_toolkit::rust_str_to_c_str;
use ffi_toolkit::{c_str_to_rust_str, raw_ptr};
use sector_builder::{SealStatus, SectorBuilder};

use crate::responses::{
    self, err_code_and_msg, AddPieceResponse, FCPResponseStatus, FFIPieceMetadata, FFISealStatus,
    GeneratePoStResponse, GetSealStatusResponse, GetSealedSectorsResponse,
    GetStagedSectorsResponse, InitSectorBuilderResponse, ReadPieceFromSealedSectorResponse,
    SealAllStagedSectorsResponse,
};
use crate::singletons::FCP_LOG;

macro_rules! ffi_catch_panic {
    ($(#[$outer:meta])*
     fn $name:ident($($arg_ident:ident: $arg_ty:ty),* $(,)?) -> *mut $resp_ty:ty $body:block) => {
        $(#[$outer])*
        #[no_mangle]
        pub unsafe extern "C" fn $name( $($arg_ident : $arg_ty,)* ) -> *mut $resp_ty {
            // Using AssertUnwindSafe is code smell. Though catching our panics here is really
            // last resort, so it should be OK.
            let maybe_panic = panic::catch_unwind(AssertUnwindSafe(||
                $body
            ));
            match maybe_panic {
                Ok(no_panic) => no_panic,
                Err(panic) => {
                    let error_msg = match panic.downcast_ref::<&'static str>() {
                        Some(message) => message,
                        _ => "no unwind information"
                    };
                    let mut response = <$resp_ty>::default();
                    let full_message = format!("rust-fil-proofs panic: {}", error_msg);
                    let (code, ptr) = err_code_and_msg(&failure::err_msg(full_message));
                    response.status_code = code;
                    response.error_msg = ptr;
                    raw_ptr(response)
                }
            }
        }
    };
    // Function with simple (non-*mut) return value (e.g. getting some stats)
    ($(#[$outer:meta])*
     fn $name:ident($($arg_ident:ident: $arg_ty:ty),* $(,)?) -> $resp_ty:ty $body:block) => {
        $(#[$outer])*
        #[no_mangle]
        pub unsafe extern "C" fn $name( $($arg_ident : $arg_ty,)* ) -> $resp_ty {
            // Using AssertUnwindSafe is code smell. Though catching our panics here is really
            // last resort, so it should be OK.
            let maybe_panic = panic::catch_unwind(AssertUnwindSafe(||
                $body
            ));
            match maybe_panic {
                Ok(no_panic) => no_panic,
                Err(panic) => {
                    let error_msg = match panic.downcast_ref::<&'static str>() {
                        Some(message) => message,
                        _ => "no unwind information"
                    };
                    // There's no status to return, hence log the error
                    let full_message = format!("rust-fil-proofs panic: {}", error_msg);
                    info!(FCP_LOG, "destruct: {}", full_message; "target" => "FFI");
                    0
                }
            }
        }
    };
    // Function without return value (e.g. destructors)
    ($(#[$outer:meta])*
     fn $name:ident($($arg_ident:ident: $arg_ty:ty),* $(,)?) $body:block) => {
        $(#[$outer])*
        #[no_mangle]
        pub unsafe extern "C" fn $name( $($arg_ident : $arg_ty,)* ) {
            // Using AssertUnwindSafe is code smell. Though catching our panics here is really
            // last resort, so it should be OK.
            let maybe_panic = panic::catch_unwind(AssertUnwindSafe(||
                $body
            ));
            match maybe_panic {
                Ok(no_panic) => no_panic,
                Err(panic) => {
                    let error_msg = match panic.downcast_ref::<&'static str>() {
                        Some(message) => message,
                        _ => "no unwind information"
                    };
                    // There's nothing to return, hence log the error
                    let full_message = format!("rust-fil-proofs panic: {}", error_msg);
                    info!(FCP_LOG, "destruct: {}", full_message; "target" => "FFI");
                }
            }
        }
    };
}

#[repr(C)]
pub struct FFISectorClass {
    sector_size: u64,
    porep_proof_partitions: u8,
    post_proof_partitions: u8,
}

ffi_catch_panic!(
    /// Writes user piece-bytes to a staged sector and returns the id of the sector
    /// to which the bytes were written.
    ///
    fn sector_builder_ffi_add_piece(
        ptr: *mut SectorBuilder,
        piece_key: *const libc::c_char,
        piece_bytes_amount: u64,
        piece_path: *const libc::c_char,
    ) -> *mut responses::AddPieceResponse {
        let piece_key = c_str_to_rust_str(piece_key);
        let piece_path = c_str_to_rust_str(piece_path);

        let mut response: responses::AddPieceResponse = Default::default();

        match (*ptr).add_piece(
            String::from(piece_key),
            piece_bytes_amount,
            String::from(piece_path),
        ) {
            Ok(sector_id) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.sector_id = sector_id;
            }
            Err(err) => {
                let (code, ptr) = err_code_and_msg(&err);
                response.status_code = code;
                response.error_msg = ptr;
            }
        }

        raw_ptr(response)
    }
);

ffi_catch_panic!(
    /// Returns the number of user bytes (before bit-padding has been added) which
    /// will fit into a sector of the given size.
    ///
    fn sector_builder_ffi_get_max_user_bytes_per_staged_sector(
        sector_size: u64,
    ) -> u64 {
        filecoin_proofs_ffi::api::get_max_user_bytes_per_staged_sector(sector_size)
    }
);

ffi_catch_panic!(
    /// Returns sector sealing status for the provided sector id if it exists. If
    /// we don't know about the provided sector id, produce an error.
    ///
    fn sector_builder_ffi_get_seal_status(
        ptr: *mut SectorBuilder,
        sector_id: u64,
    ) -> *mut responses::GetSealStatusResponse {
        let mut response: responses::GetSealStatusResponse = Default::default();

        match (*ptr).get_seal_status(sector_id) {
            Ok(seal_status) => {
                response.status_code = FCPResponseStatus::FCPNoError;

                match seal_status {
                    SealStatus::Sealed(meta) => {
                        let meta = *meta;

                        let pieces = meta
                            .pieces
                            .iter()
                            .map(|p| FFIPieceMetadata {
                                piece_key: rust_str_to_c_str(p.piece_key.to_string()),
                                num_bytes: p.num_bytes.into(),
                            })
                            .collect::<Vec<FFIPieceMetadata>>();

                        response.comm_d = meta.comm_d;
                        response.comm_r = meta.comm_r;
                        response.comm_r_star = meta.comm_r_star;
                        response.pieces_len = pieces.len();
                        response.pieces_ptr = pieces.as_ptr();
                        response.proof_len = meta.proof.len();
                        response.proof_ptr = meta.proof.as_ptr();
                        response.seal_status_code = FFISealStatus::Sealed;
                        response.sector_access = rust_str_to_c_str(meta.sector_access);
                        response.sector_id = meta.sector_id;

                        mem::forget(meta.proof);
                        mem::forget(pieces);
                    }
                    SealStatus::Sealing => {
                        response.seal_status_code = FFISealStatus::Sealing;
                    }
                    SealStatus::Pending => {
                        response.seal_status_code = FFISealStatus::Pending;
                    }
                    SealStatus::Failed(err) => {
                        response.seal_status_code = FFISealStatus::Failed;
                        response.seal_error_msg = rust_str_to_c_str(err);
                    }
                }
            }
            Err(err) => {
                let (code, ptr) = err_code_and_msg(&err);
                response.status_code = code;
                response.error_msg = ptr;
            }
        }

        raw_ptr(response)
    }
);

ffi_catch_panic!(
    fn sector_builder_ffi_get_sealed_sectors(
        ptr: *mut SectorBuilder,
    ) -> *mut responses::GetSealedSectorsResponse {
        let mut response: responses::GetSealedSectorsResponse = Default::default();

        match (*ptr).get_sealed_sectors() {
            Ok(sealed_sectors) => {
                response.status_code = FCPResponseStatus::FCPNoError;

                let sectors = sealed_sectors
                    .iter()
                    .map(|meta| {
                        let pieces = meta
                            .pieces
                            .iter()
                            .map(|p| FFIPieceMetadata {
                                piece_key: rust_str_to_c_str(p.piece_key.to_string()),
                                num_bytes: p.num_bytes.into(),
                            })
                            .collect::<Vec<FFIPieceMetadata>>();

                        let snark_proof = meta.proof.clone();

                        let sector = responses::FFISealedSectorMetadata {
                            comm_d: meta.comm_d,
                            comm_r: meta.comm_r,
                            comm_r_star: meta.comm_r_star,
                            pieces_len: pieces.len(),
                            pieces_ptr: pieces.as_ptr(),
                            proofs_len: snark_proof.len(),
                            proofs_ptr: snark_proof.as_ptr(),
                            sector_access: rust_str_to_c_str(meta.sector_access.clone()),
                            sector_id: meta.sector_id,
                        };

                        mem::forget(snark_proof);
                        mem::forget(pieces);

                        sector
                    })
                    .collect::<Vec<responses::FFISealedSectorMetadata>>();

                response.sectors_len = sectors.len();
                response.sectors_ptr = sectors.as_ptr();

                mem::forget(sectors);
            }
            Err(err) => {
                let (code, ptr) = err_code_and_msg(&err);
                response.status_code = code;
                response.error_msg = ptr;
            }
        }

        raw_ptr(response)
    }
);

ffi_catch_panic!(
    fn sector_builder_ffi_get_staged_sectors(
        ptr: *mut SectorBuilder,
    ) -> *mut responses::GetStagedSectorsResponse {
        let mut response: responses::GetStagedSectorsResponse = Default::default();

        match (*ptr).get_staged_sectors() {
            Ok(staged_sectors) => {
                response.status_code = FCPResponseStatus::FCPNoError;

                let sectors = staged_sectors
                    .iter()
                    .map(|meta| {
                        let pieces = meta
                            .pieces
                            .iter()
                            .map(|p| FFIPieceMetadata {
                                piece_key: rust_str_to_c_str(p.piece_key.to_string()),
                                num_bytes: p.num_bytes.into(),
                            })
                            .collect::<Vec<FFIPieceMetadata>>();

                        let mut sector = responses::FFIStagedSectorMetadata {
                            sector_access: rust_str_to_c_str(meta.sector_access.clone()),
                            sector_id: meta.sector_id,
                            pieces_len: pieces.len(),
                            pieces_ptr: pieces.as_ptr(),
                            seal_status_code: FFISealStatus::Pending,
                            seal_error_msg: ptr::null(),
                        };

                        match meta.seal_status {
                            SealStatus::Failed(ref s) => {
                                sector.seal_status_code = FFISealStatus::Failed;
                                sector.seal_error_msg = rust_str_to_c_str(s.clone());
                            }
                            SealStatus::Sealing => {
                                sector.seal_status_code = FFISealStatus::Sealing;
                            }
                            SealStatus::Pending => {
                                sector.seal_status_code = FFISealStatus::Pending;
                            }
                            SealStatus::Sealed(_) => {
                                sector.seal_status_code = FFISealStatus::Sealed;
                            }
                        };

                        mem::forget(pieces);

                        sector
                    })
                    .collect::<Vec<responses::FFIStagedSectorMetadata>>();

                response.sectors_len = sectors.len();
                response.sectors_ptr = sectors.as_ptr();

                mem::forget(sectors);
            }
            Err(err) => {
                let (code, ptr) = err_code_and_msg(&err);
                response.status_code = code;
                response.error_msg = ptr;
            }
        }

        raw_ptr(response)
    }
);

ffi_catch_panic!(
    /// Generates a proof-of-spacetime for the given replica commitments.
    ///
    fn sector_builder_ffi_generate_post(
        ptr: *mut SectorBuilder,
        flattened_comm_rs_ptr: *const u8,
        flattened_comm_rs_len: libc::size_t,
        challenge_seed: &[u8; 32],
    ) -> *mut responses::GeneratePoStResponse {
        info!(FCP_LOG, "generate_post: {}", "start"; "target" => "FFI");

        let comm_rs = into_commitments(flattened_comm_rs_ptr, flattened_comm_rs_len);

        let result = (*ptr).generate_post(&comm_rs, challenge_seed);

        let mut response = responses::GeneratePoStResponse::default();

        match result {
            Ok(filecoin_proofs::post_adapter::GeneratePoStDynamicSectorsCountOutput {
                proofs,
                faults,
            }) => {
                response.status_code = FCPResponseStatus::FCPNoError;

                let flattened_proofs: Vec<u8> =
                    proofs.iter().flat_map(|x| x.iter().cloned()).collect();
                response.flattened_proofs_len = flattened_proofs.len();
                response.flattened_proofs_ptr = flattened_proofs.as_ptr();

                let class = (*ptr).get_sector_class();
                let filecoin_proofs::PoStProofPartitions(n) =
                    filecoin_proofs::PoStProofPartitions::from(filecoin_proofs::PoStConfig::from(
                        class,
                    ));
                response.proof_partitions = n;

                response.faults_len = faults.len();
                response.faults_ptr = faults.as_ptr();

                // we'll free this stuff when we free the GeneratePoSTResponse
                mem::forget(flattened_proofs);
                mem::forget(faults);
            }
            Err(err) => {
                let (code, ptr) = err_code_and_msg(&err);
                response.status_code = code;
                response.error_msg = ptr;
            }
        }

        info!(FCP_LOG, "generate_post: {}", "finish"; "target" => "FFI");

        raw_ptr(response)
    }
);

ffi_catch_panic!(
    /// Initializes and returns a SectorBuilder.
    ///
    fn sector_builder_ffi_init_sector_builder(
        sector_class: FFISectorClass,
        last_used_sector_id: u64,
        metadata_dir: *const libc::c_char,
        prover_id: &[u8; 31],
        sealed_sector_dir: *const libc::c_char,
        staged_sector_dir: *const libc::c_char,
        max_num_staged_sectors: u8,
    ) -> *mut responses::InitSectorBuilderResponse {
        let result = SectorBuilder::init_from_metadata(
            from_ffi_sector_class(sector_class),
            last_used_sector_id,
            c_str_to_rust_str(metadata_dir).to_string(),
            *prover_id,
            c_str_to_rust_str(sealed_sector_dir).to_string(),
            c_str_to_rust_str(staged_sector_dir).to_string(),
            max_num_staged_sectors,
        );

        let mut response = responses::InitSectorBuilderResponse::default();

        match result {
            Ok(sb) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.sector_builder = raw_ptr(sb);
            }
            Err(err) => {
                let (code, ptr) = err_code_and_msg(&err);
                response.status_code = code;
                response.error_msg = ptr;
            }
        }

        raw_ptr(response)
    }
);

ffi_catch_panic!(
    /// Unseals and returns the bytes associated with the provided piece key.
    ///
    fn sector_builder_ffi_read_piece_from_sealed_sector(
        ptr: *mut SectorBuilder,
        piece_key: *const libc::c_char,
    ) -> *mut responses::ReadPieceFromSealedSectorResponse {
        let mut response: responses::ReadPieceFromSealedSectorResponse = Default::default();

        let piece_key = c_str_to_rust_str(piece_key);

        match (*ptr).read_piece_from_sealed_sector(String::from(piece_key)) {
            Ok(piece_bytes) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.data_ptr = piece_bytes.as_ptr();
                response.data_len = piece_bytes.len();
                mem::forget(piece_bytes);
            }
            Err(err) => {
                let (code, ptr) = err_code_and_msg(&err);
                response.status_code = code;
                response.error_msg = ptr;
            }
        }

        raw_ptr(response)
    }
);

ffi_catch_panic!(
    /// For demo purposes. Seals all staged sectors.
    ///
    fn sector_builder_ffi_seal_all_staged_sectors(
        ptr: *mut SectorBuilder,
    ) -> *mut responses::SealAllStagedSectorsResponse {
        let mut response: responses::SealAllStagedSectorsResponse = Default::default();

        match (*ptr).seal_all_staged_sectors() {
            Ok(_) => {
                response.status_code = FCPResponseStatus::FCPNoError;
            }
            Err(err) => {
                let (code, ptr) = err_code_and_msg(&err);
                response.status_code = code;
                response.error_msg = ptr;
            }
        }

        raw_ptr(response)
    }
);

// NOTE vmx 2019-06-22: Add panic catcher once
// https://github.com/filecoin-project/rust-fil-proofs-ffi/issues/8 is fixed
/// Verifies the output of seal.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_verify_seal(
    sector_size: u64,
    comm_r: &[u8; 32],
    comm_d: &[u8; 32],
    comm_r_star: &[u8; 32],
    prover_id: &[u8; 31],
    sector_id: &[u8; 31],
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> *mut filecoin_proofs_ffi::responses::VerifySealResponse {
    filecoin_proofs_ffi::api::verify_seal(
        sector_size,
        comm_r,
        comm_d,
        comm_r_star,
        prover_id,
        sector_id,
        proof_ptr,
        proof_len,
    )
}

// NOTE vmx 2019-06-22: Add panic catcher once
// https://github.com/filecoin-project/rust-fil-proofs-ffi/issues/8 is fixed
/// Verifies that a proof-of-spacetime is valid.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_verify_post(
    sector_size: u64,
    proof_partitions: u8,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    challenge_seed: &[u8; 32],
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
    faults_ptr: *const u64,
    faults_len: libc::size_t,
) -> *mut filecoin_proofs_ffi::responses::VerifyPoStResponse {
    filecoin_proofs_ffi::api::verify_post(
        sector_size,
        proof_partitions,
        flattened_comm_rs_ptr,
        flattened_comm_rs_len,
        challenge_seed,
        flattened_proofs_ptr,
        flattened_proofs_len,
        faults_ptr,
        faults_len,
    )
}

////////////////////////////////////////////////////////////////////////////////
// DESTRUCTORS
//////////////

ffi_catch_panic!(
    fn sector_builder_ffi_destroy_add_piece_response(ptr: *mut AddPieceResponse) {
        let _ = Box::from_raw(ptr);
    }
);

ffi_catch_panic!(
    fn sector_builder_ffi_destroy_generate_post_response(ptr: *mut GeneratePoStResponse) {
        let _ = Box::from_raw(ptr);
    }
);

ffi_catch_panic!(
    fn sector_builder_ffi_destroy_get_seal_status_response(ptr: *mut GetSealStatusResponse) {
        let _ = Box::from_raw(ptr);
    }
);

ffi_catch_panic!(
    fn sector_builder_ffi_destroy_get_sealed_sectors_response(ptr: *mut GetSealedSectorsResponse) {
        let _ = Box::from_raw(ptr);
    }
);

ffi_catch_panic!(
    fn sector_builder_ffi_destroy_get_staged_sectors_response(ptr: *mut GetStagedSectorsResponse) {
        let _ = Box::from_raw(ptr);
    }
);

ffi_catch_panic!(
    fn sector_builder_ffi_destroy_init_sector_builder_response(
        ptr: *mut InitSectorBuilderResponse,
    ) {
        let _ = Box::from_raw(ptr);
    }
);

ffi_catch_panic!(
    fn sector_builder_ffi_destroy_read_piece_from_sealed_sector_response(
        ptr: *mut ReadPieceFromSealedSectorResponse,
    ) {
        let _ = Box::from_raw(ptr);
    }
);

ffi_catch_panic!(
    fn sector_builder_ffi_destroy_seal_all_staged_sectors_response(
        ptr: *mut SealAllStagedSectorsResponse,
    ) {
        let _ = Box::from_raw(ptr);
    }
);

ffi_catch_panic!(
    /// Deallocates a VerifySealResponse.
    ///
    fn sector_builder_ffi_destroy_verify_seal_response(
        ptr: *mut filecoin_proofs_ffi::responses::VerifySealResponse,
    ) {
        filecoin_proofs_ffi::api::destroy_verify_seal_response(ptr)
    }
);

ffi_catch_panic!(
    /// Deallocates a VerifyPoStResponse.
    ///
    fn sector_builder_ffi_destroy_verify_post_response(
        ptr: *mut filecoin_proofs_ffi::responses::VerifyPoStResponse,
    ) {
        filecoin_proofs_ffi::api::destroy_verify_post_response(ptr)
    }
);

ffi_catch_panic!(
    /// Destroys a SectorBuilder.
    ///
    fn sector_builder_ffi_destroy_sector_builder(ptr: *mut SectorBuilder) {
        let _ = Box::from_raw(ptr);
    }
);

////////////////////////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
///////////////////

unsafe fn into_commitments(
    flattened_comms_ptr: *const u8,
    flattened_comms_len: libc::size_t,
) -> Vec<[u8; 32]> {
    from_raw_parts(flattened_comms_ptr, flattened_comms_len)
        .iter()
        .step_by(32)
        .fold(Default::default(), |mut acc: Vec<[u8; 32]>, item| {
            let sliced = from_raw_parts(item, 32);
            let mut x: [u8; 32] = Default::default();
            x.copy_from_slice(&sliced[..32]);
            acc.push(x);
            acc
        })
}

pub fn from_ffi_sector_class(fsc: FFISectorClass) -> filecoin_proofs::SectorClass {
    match fsc {
        FFISectorClass {
            sector_size,
            porep_proof_partitions,
            post_proof_partitions,
        } => filecoin_proofs::SectorClass(
            filecoin_proofs::SectorSize(sector_size),
            filecoin_proofs::PoRepProofPartitions(porep_proof_partitions),
            filecoin_proofs::PoStProofPartitions(post_proof_partitions),
        ),
    }
}
