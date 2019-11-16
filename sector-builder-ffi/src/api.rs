use std::mem;
use std::ptr;
use std::slice::from_raw_parts;

// The `CodeAndMessage` trait is needed for `catch_panic_response`
use ffi_toolkit::{
    c_str_to_pbuf, c_str_to_rust_str, catch_panic_response, raw_ptr, rust_str_to_c_str,
    CodeAndMessage, FCPResponseStatus,
};
use libc;
use once_cell::sync::OnceCell;
use sector_builder::{GetSealedSectorResult, PieceMetadata, SealStatus, SecondsSinceEpoch};
use storage_proofs::sector::SectorId;

use crate::types::{
    self, err_code_and_msg, FFIPieceMetadata, FFISealSeed, FFISealStatus, FFISealTicket,
    FFISealedSectorHealth, FFISealedSectorMetadata, FileDescriptorRef, SectorBuilder,
};
use filecoin_proofs::{Candidate, UnpaddedBytesAmount};
use filecoin_proofs_ffi::types::FFICandidate;
use storage_proofs::hasher::pedersen::PedersenDomain;
use storage_proofs::hasher::Domain;
use storage_proofs::stacked::PersistentAux;

/// Writes user piece-bytes to a staged sector and returns the id of the sector
/// to which the bytes were written.
/// The caller is responsible for closing the file descriptor.
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn sector_builder_ffi_add_piece(
    ptr: *mut SectorBuilder,
    piece_key: *const libc::c_char,
    piece_fd_raw: libc::c_int,
    piece_bytes_amount: u64,
    store_until_utc_secs: u64,
) -> *mut types::AddPieceResponse {
    catch_panic_response(|| {
        init_log();

        info!("add_piece: {}", "start");

        let piece_key = c_str_to_rust_str(piece_key);
        let piece_fd = FileDescriptorRef::new(piece_fd_raw);

        let mut response: types::AddPieceResponse = Default::default();

        match (*ptr).add_piece(
            piece_key.into(),
            piece_fd,
            piece_bytes_amount,
            SecondsSinceEpoch(store_until_utc_secs),
        ) {
            Ok(sector_id) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.sector_id = sector_id.into();
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        info!("add_piece: {}", "finish");

        raw_ptr(response)
    })
}

/// Returns sector sealing status for the provided sector id if it exists. If
/// we don't know about the provided sector id, produce an error.
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_get_seal_status(
    ptr: *mut SectorBuilder,
    sector_id: u64,
) -> *mut types::GetSealStatusResponse {
    catch_panic_response(|| {
        init_log();

        let mut response: types::GetSealStatusResponse = Default::default();

        match (*ptr).get_seal_status(SectorId::from(sector_id)) {
            Ok(seal_status) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.seal_status_code = seal_status.clone().into();

                match seal_status {
                    SealStatus::Committed(meta) => {
                        let meta = *meta;

                        let pieces = meta
                            .pieces
                            .into_iter()
                            .map(|x| x.into())
                            .collect::<Vec<FFIPieceMetadata>>();

                        response.comm_d = meta.comm_d;
                        response.comm_r = meta.comm_r;
                        response.pieces_len = pieces.len();
                        response.pieces_ptr = pieces.as_ptr();
                        response.proof_len = meta.proof.len();
                        response.proof_ptr = meta.proof.as_ptr();
                        response.sector_access = rust_str_to_c_str(meta.sector_access);
                        response.sector_id = u64::from(meta.sector_id);
                        response.seal_ticket = FFISealTicket {
                            block_height: meta.ticket.block_height,
                            ticket_bytes: meta.ticket.ticket_bytes,
                        };
                        response.seal_seed = FFISealSeed {
                            block_height: meta.seed.block_height,
                            ticket_bytes: meta.seed.ticket_bytes,
                        };

                        mem::forget(meta.proof);
                        mem::forget(pieces);
                    }
                    SealStatus::Failed(ref err) => {
                        response.seal_error_msg = rust_str_to_c_str(err);
                    }
                    _ => (),
                }
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_get_sealed_sectors(
    ptr: *mut SectorBuilder,
    check_health: bool,
) -> *mut types::GetSealedSectorsResponse {
    catch_panic_response(|| {
        init_log();

        let mut response: types::GetSealedSectorsResponse = Default::default();

        match (*ptr).get_sealed_sectors(check_health) {
            Ok(sealed_sectors) => {
                response.status_code = FCPResponseStatus::FCPNoError;

                let sectors = sealed_sectors
                    .into_iter()
                    .map(|wrapped_meta| {
                        let (ffi_health, meta) = match wrapped_meta {
                            GetSealedSectorResult::WithHealth(h, m) => (h.into(), m),
                            GetSealedSectorResult::WithoutHealth(m) => {
                                (FFISealedSectorHealth::Unknown, m)
                            }
                        };

                        let mut sector: FFISealedSectorMetadata = meta.into();
                        sector.health = ffi_health;
                        sector
                    })
                    .collect::<Vec<types::FFISealedSectorMetadata>>();

                response.meta_len = sectors.len();
                response.meta_ptr = sectors.as_ptr();

                mem::forget(sectors);
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        raw_ptr(response)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_get_staged_sectors(
    ptr: *mut SectorBuilder,
) -> *mut types::GetStagedSectorsResponse {
    catch_panic_response(|| {
        init_log();

        let mut response: types::GetStagedSectorsResponse = Default::default();

        match (*ptr).get_staged_sectors() {
            Ok(staged_sectors) => {
                response.status_code = FCPResponseStatus::FCPNoError;

                let sectors = staged_sectors
                    .iter()
                    .map(|meta| {
                        let pieces = meta
                            .pieces
                            .iter()
                            .map(|x| x.clone().into())
                            .collect::<Vec<FFIPieceMetadata>>();

                        let mut sector = types::FFIStagedSectorMetadata {
                            sector_access: rust_str_to_c_str(meta.sector_access.clone()),
                            sector_id: u64::from(meta.sector_id),
                            pieces_len: pieces.len(),
                            pieces_ptr: pieces.as_ptr(),
                            seal_status_code: FFISealStatus::AcceptingPieces,
                            seal_error_msg: ptr::null(),
                        };

                        sector.seal_status_code = meta.seal_status.clone().into();

                        if let SealStatus::Failed(ref s) = meta.seal_status {
                            sector.seal_error_msg = rust_str_to_c_str(s.clone());
                        }

                        mem::forget(pieces);

                        sector
                    })
                    .collect::<Vec<types::FFIStagedSectorMetadata>>();

                response.sectors_len = sectors.len();
                response.sectors_ptr = sectors.as_ptr();

                mem::forget(sectors);
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        raw_ptr(response)
    })
}

/// Generates a proof-of-spacetime for the given replica commitments.
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_generate_candidates(
    ptr: *mut SectorBuilder,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    challenge_seed: &[u8; 32],
    faults_ptr: *const u64,
    faults_len: libc::size_t,
) -> *mut types::GenerateCandidatesResponse {
    catch_panic_response(|| {
        init_log();

        info!("generate_post: {}", "start");

        let comm_rs = into_commitments(flattened_comm_rs_ptr, flattened_comm_rs_len);
        let faults = from_raw_parts(faults_ptr, faults_len)
            .iter()
            .map(|x| SectorId::from(*x))
            .collect();

        let result = (*ptr).generate_candidates(&comm_rs, challenge_seed, faults);

        let mut response = types::GenerateCandidatesResponse::default();

        match result {
            Ok(candidates) => {
                response.status_code = FCPResponseStatus::FCPNoError;

                let ffi_candidates: Vec<FFICandidate> = candidates
                    .into_iter()
                    .map(|c| {
                        let Candidate {
                            sector_id,
                            partial_ticket,
                            ticket,
                            sector_challenge_index,
                        } = c;

                        FFICandidate {
                            sector_id: u64::from(sector_id),
                            partial_ticket,
                            ticket,
                            sector_challenge_index,
                        }
                    })
                    .collect();
                response.candidates_len = ffi_candidates.len();
                response.candidates_ptr = ffi_candidates.as_ptr();

                // we'll free this stuff when we free the GeneratePoSTResponse
                mem::forget(ffi_candidates);
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        info!("generate_post: {}", "finish");

        raw_ptr(response)
    })
}

/// Generates a proof-of-spacetime for the given replica commitments.
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_generate_post(
    ptr: *mut SectorBuilder,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    challenge_seed: &[u8; 32],
    winners_ptr: *const FFICandidate,
    winners_len: libc::size_t,
) -> *mut types::GeneratePoStResponse {
    catch_panic_response(|| {
        init_log();

        info!("generate_post: {}", "start");

        let comm_rs = into_commitments(flattened_comm_rs_ptr, flattened_comm_rs_len);
        let winners = from_raw_parts(winners_ptr, winners_len)
            .iter()
            .cloned()
            .map(Into::into)
            .collect();

        let result = (*ptr).generate_post(&comm_rs, challenge_seed, winners);

        let mut response = types::GeneratePoStResponse::default();

        match result {
            Ok(proof) => {
                response.status_code = FCPResponseStatus::FCPNoError;

                let flattened_proofs: Vec<u8> = proof.into_iter().flatten().collect();

                response.flattened_proofs_len = flattened_proofs.len();
                response.flattened_proofs_ptr = flattened_proofs.as_ptr();

                // we'll free this stuff when we free the GeneratePoSTResponse
                mem::forget(flattened_proofs);
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        info!("generate_post: {}", "finish");

        raw_ptr(response)
    })
}

/// Initializes and returns a SectorBuilder.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_init_sector_builder(
    sector_class: filecoin_proofs_ffi::types::FFISectorClass,
    last_used_sector_id: u64,
    metadata_dir: *const libc::c_char,
    prover_id: &[u8; 32],
    sealed_sector_dir: *const libc::c_char,
    staged_sector_dir: *const libc::c_char,
    sector_cache_root_dir: *const libc::c_char,
    max_num_staged_sectors: u8,
    num_workers: u8,
) -> *mut types::InitSectorBuilderResponse {
    catch_panic_response(|| {
        init_log();

        let result = SectorBuilder::init_from_metadata(
            sector_class.into(),
            last_used_sector_id.into(),
            c_str_to_rust_str(metadata_dir).to_string(),
            *prover_id,
            c_str_to_rust_str(sealed_sector_dir).to_string(),
            c_str_to_rust_str(staged_sector_dir).to_string(),
            c_str_to_rust_str(sector_cache_root_dir).to_string(),
            max_num_staged_sectors,
            num_workers,
        );

        let mut response = types::InitSectorBuilderResponse::default();

        match result {
            Ok(sb) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.sector_builder = raw_ptr(sb);
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        raw_ptr(response)
    })
}

/// Pre-commits a sector of the provided id to a ticket from the chain. This is
/// the first step of Interactive PoRep.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_seal_pre_commit(
    ptr: *mut SectorBuilder,
    sector_id: u64,
    seal_ticket: FFISealTicket,
) -> *mut types::SectorBuilderSealPreCommitResponse {
    catch_panic_response(|| {
        init_log();

        info!("seal_pre_commit: {}", "start");

        let mut response: types::SectorBuilderSealPreCommitResponse = Default::default();

        match (*ptr).seal_pre_commit(sector_id.into(), seal_ticket.into()) {
            Ok(meta) => {
                if let SealStatus::PreCommitted(t, _, p) = meta.seal_status {
                    let pieces = meta
                        .pieces
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<FFIPieceMetadata>>();

                    response.status_code = FCPResponseStatus::FCPNoError;
                    response.comm_d = p.comm_d;
                    response.comm_r = p.comm_r;
                    response.pieces_len = pieces.len();
                    response.pieces_ptr = pieces.as_ptr();
                    response.seal_ticket = t.into();
                    response.sector_id = sector_id;

                    mem::forget(pieces);
                } else {
                    response.status_code = FCPResponseStatus::FCPReceiverError;
                    response.error_msg = rust_str_to_c_str("programmer error: invalid state");
                }
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        info!("seal_pre_commit: {}", "finish");

        raw_ptr(response)
    })
}

/// Commits a pre-sealed sector to a particular seed. The second step of
/// Interactive PoRep.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_seal_commit(
    ptr: *mut SectorBuilder,
    sector_id: u64,
    seal_seed: FFISealSeed,
) -> *mut types::SectorBuilderSealCommitResponse {
    catch_panic_response(|| {
        init_log();

        info!("seal_commit: {}", "start");

        let mut response: types::SectorBuilderSealCommitResponse = Default::default();

        match (*ptr).seal_commit(sector_id.into(), seal_seed.into()) {
            Ok(meta) => {
                let pieces = meta
                    .pieces
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<FFIPieceMetadata>>();

                let proof = meta.proof.clone();

                response.status_code = FCPResponseStatus::FCPNoError;
                response.comm_d = meta.comm_d;
                response.comm_r = meta.comm_r;
                response.pieces_len = pieces.len();
                response.pieces_ptr = pieces.as_ptr();
                response.proofs_len = proof.len();
                response.proofs_ptr = proof.as_ptr();
                response.seal_seed = meta.seed.into();
                response.seal_ticket = meta.ticket.into();
                response.sector_id = sector_id;

                mem::forget(proof);
                mem::forget(pieces);
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        info!("seal_commit: {}", "finish");

        raw_ptr(response)
    })
}

/// Resumes pre-committing of a sector which was previously paused. Produces an
/// error if the sector with requested id is not in a state which allows it to
/// be resumed.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_resume_seal_pre_commit(
    ptr: *mut SectorBuilder,
    sector_id: u64,
) -> *mut types::ResumeSealPreCommitResponse {
    catch_panic_response(|| {
        init_log();

        info!("resume_seal_pre_commit: {}", "start");

        let mut response: types::ResumeSealPreCommitResponse = Default::default();

        match (*ptr).resume_seal_pre_commit(sector_id.into()) {
            Ok(meta) => {
                if let SealStatus::PreCommitted(t, _, p) = meta.seal_status {
                    let pieces = meta
                        .pieces
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<FFIPieceMetadata>>();

                    response.status_code = FCPResponseStatus::FCPNoError;
                    response.comm_d = p.comm_d;
                    response.comm_r = p.comm_r;
                    response.pieces_len = pieces.len();
                    response.pieces_ptr = pieces.as_ptr();
                    response.seal_ticket = t.into();
                    response.sector_id = sector_id;

                    mem::forget(pieces);
                } else {
                    response.status_code = FCPResponseStatus::FCPReceiverError;
                    response.error_msg = rust_str_to_c_str("programmer error: invalid state");
                }
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        info!("resume_seal_pre_commit: {}", "finish");

        raw_ptr(response)
    })
}

/// Resumes committing of a sector which was previously paused. Produces an
/// error if the sector with requested id is not in a state which allows it to
/// be resumed.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_resume_seal_commit(
    ptr: *mut SectorBuilder,
    sector_id: u64,
) -> *mut types::ResumeSealCommitResponse {
    catch_panic_response(|| {
        init_log();

        info!("resume_seal_commit: {}", "start");

        let mut response: types::ResumeSealCommitResponse = Default::default();

        match (*ptr).resume_seal_commit(sector_id.into()) {
            Ok(meta) => {
                let ffi_meta: FFISealedSectorMetadata = meta.into();

                response.status_code = FCPResponseStatus::FCPNoError;
                response.comm_d = ffi_meta.comm_d;
                response.comm_r = ffi_meta.comm_r;
                response.pieces_len = ffi_meta.pieces_len;
                response.pieces_ptr = ffi_meta.pieces_ptr;
                response.proofs_len = ffi_meta.proofs_len;
                response.proofs_ptr = ffi_meta.proofs_ptr;
                response.seal_seed = ffi_meta.seal_seed;
                response.seal_ticket = ffi_meta.seal_ticket;
                response.sector_id = ffi_meta.sector_id;
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        info!("resume_seal_commit: {}", "finish");

        raw_ptr(response)
    })
}

/// Unseals and returns the bytes associated with the provided piece key.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_read_piece_from_sealed_sector(
    ptr: *mut SectorBuilder,
    piece_key: *const libc::c_char,
) -> *mut types::ReadPieceFromSealedSectorResponse {
    catch_panic_response(|| {
        init_log();

        info!("read_piece_from_sealed_sector: {}", "start");

        let mut response: types::ReadPieceFromSealedSectorResponse = Default::default();

        let piece_key = c_str_to_rust_str(piece_key);

        match (*ptr).read_piece_from_sealed_sector(piece_key.into()) {
            Ok(piece_bytes) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.data_ptr = piece_bytes.as_ptr();
                response.data_len = piece_bytes.len();
                mem::forget(piece_bytes);
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        info!("read_piece_from_sealed_sector: {}", "finish");

        raw_ptr(response)
    })
}

/// Imports a sector sealed elsewhere and takes ownership of its metadata,
/// cache directory, and sealed sector file.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_import_sealed_sector(
    ptr: *mut SectorBuilder,
    sector_id: u64,
    sector_cache_dir_path: *const libc::c_char,
    sealed_sector_path: *const libc::c_char,
    seal_ticket: FFISealTicket,
    seal_seed: FFISealSeed,
    comm_r: &[u8; 32],
    comm_d: &[u8; 32],
    p_aux_comm_c: &[u8; 32],
    p_aux_comm_r_last: &[u8; 32],
    proof_ptr: *mut u8,
    proof_len: libc::size_t,
    pieces_ptr: *mut FFIPieceMetadata,
    pieces_len: libc::size_t,
) -> *mut types::ImportSealedSectorResponse {
    catch_panic_response(|| {
        init_log();

        info!("import_sealed_sector: {}", "start");

        let mut response: types::ImportSealedSectorResponse = Default::default();

        let comm_r_last = PedersenDomain::try_from_bytes(p_aux_comm_r_last);
        let comm_c = PedersenDomain::try_from_bytes(p_aux_comm_c);

        if comm_r_last.is_err() {
            response.status_code = FCPResponseStatus::FCPUnclassifiedError;
            response.error_msg = rust_str_to_c_str("cannot convert comm_r_last to PedersenDomain");
            info!("seal_commit: finish");
            return raw_ptr(response);
        }

        if comm_c.is_err() {
            response.status_code = FCPResponseStatus::FCPUnclassifiedError;
            response.error_msg = rust_str_to_c_str("cannot convert comm_c to PedersenDomain");
            info!("seal_commit: finish");
            return raw_ptr(response);
        }

        // copy bytes from the provided pointer to Rust-managed space
        let proof = std::slice::from_raw_parts(proof_ptr, proof_len).to_vec();

        // map FFIPieceMetadata to PieceMetadata so caller can dealloc
        let pieces = std::slice::from_raw_parts(pieces_ptr, pieces_len)
            .iter()
            .map(|x| PieceMetadata {
                piece_key: c_str_to_rust_str(x.piece_key).into_owned(),
                num_bytes: UnpaddedBytesAmount(x.num_bytes),
                comm_p: x.comm_p,
            })
            .collect();

        match (*ptr).import_sealed_sector(
            SectorId::from(sector_id),
            c_str_to_pbuf(sector_cache_dir_path),
            c_str_to_pbuf(sealed_sector_path),
            seal_ticket.into(),
            seal_seed.into(),
            *comm_r,
            *comm_d,
            PersistentAux {
                comm_c: comm_c.unwrap(),
                comm_r_last: comm_r_last.unwrap(),
            },
            pieces,
            proof,
        ) {
            Ok(_) => {
                response.status_code = FCPResponseStatus::FCPNoError;
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        info!("import_sealed_sector: {}", "finish");

        raw_ptr(response)
    })
}

/// Acquires a new sector id to be used when sealing out-of-band.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_acquire_sector_id(
    ptr: *mut SectorBuilder,
) -> *mut types::AcquireSectorIdResponse {
    catch_panic_response(|| {
        init_log();

        info!("acquire_sector_id: {}", "start");

        let mut response: types::AcquireSectorIdResponse = Default::default();

        match (*ptr).acquire_sector_id() {
            Ok(sector_id) => {
                response.status_code = FCPResponseStatus::FCPNoError;
                response.sector_id = sector_id.into();
            }
            Err(err) => {
                response.set_error(err_code_and_msg(&err));
            }
        }

        info!("acquire_sector_id: {}", "finish");

        raw_ptr(response)
    })
}

////////////////////////////////////////////////////////////////////////////////
// DESTRUCTORS
//////////////

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_add_piece_response(
    ptr: *mut types::AddPieceResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_generate_post_response(
    ptr: *mut types::GeneratePoStResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_generate_candidates_response(
    ptr: *mut types::GenerateCandidatesResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_get_seal_status_response(
    ptr: *mut types::GetSealStatusResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_get_sealed_sectors_response(
    ptr: *mut types::GetSealedSectorsResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_get_staged_sectors_response(
    ptr: *mut types::GetStagedSectorsResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_init_sector_builder_response(
    ptr: *mut types::InitSectorBuilderResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_read_piece_from_sealed_sector_response(
    ptr: *mut types::ReadPieceFromSealedSectorResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_seal_pre_commit_response(
    ptr: *mut types::SectorBuilderSealPreCommitResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_seal_commit_response(
    ptr: *mut types::SectorBuilderSealCommitResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_resume_seal_pre_commit_response(
    ptr: *mut types::ResumeSealPreCommitResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_resume_seal_commit_response(
    ptr: *mut types::ResumeSealCommitResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Destroys a SectorBuilder.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_sector_builder(ptr: *mut SectorBuilder) {
    let _ = Box::from_raw(ptr);
}

/// Destroys a SealPreCommitSectorResponse.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_seal_pre_commit_sector_response(
    ptr: *mut types::SectorBuilderSealPreCommitResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Destroys a ResumeSealCommitSectorResponse.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_resume_seal_commit_sector_response(
    ptr: *mut types::ResumeSealCommitResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Destroys a ImportSealedSectorResponse.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_import_sealed_sector_response(
    ptr: *mut types::ImportSealedSectorResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Destroys a AcquireSectorIdResponse.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_acquire_sector_id_response(
    ptr: *mut types::AcquireSectorIdResponse,
) {
    let _ = Box::from_raw(ptr);
}

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

/// Protects the init off the logger.
static LOG_INIT: OnceCell<bool> = OnceCell::new();

/// Ensures the logger is initialized.
pub(crate) fn init_log() {
    LOG_INIT.get_or_init(|| {
        let _ = pretty_env_logger::try_init_timed();
        true
    });
}
