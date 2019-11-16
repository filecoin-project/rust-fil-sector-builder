use std::path::Path;
use std::ptr;
use std::slice;

use ffi_toolkit::{c_str_to_rust_str, free_c_str, rust_str_to_c_str};

use crate::deallocator::*;
use crate::provingset::*;

include!(concat!(env!("OUT_DIR"), "/libsector_builder_ffi.rs"));

pub(crate) unsafe fn generate_candidates(
    ptr: *mut sector_builder_ffi_SectorBuilder,
    challenge_seed: [u8; 32],
    proving_set: &ProvingSet,
) -> Result<Vec<sector_builder_ffi_FFICandidate>, (sector_builder_ffi_FCPResponseStatus, String)> {
    let flattened_comm_rs = proving_set.flattened_comm_rs();
    let faulty_sector_ids = proving_set.faulty_sector_ids();

    let resp = sector_builder_ffi_generate_candidates(
        ptr,
        flattened_comm_rs.as_ptr(),
        flattened_comm_rs.len(),
        &mut challenge_seed.clone(),
        faulty_sector_ids.as_ptr(),
        faulty_sector_ids.len(),
    );
    defer!(sector_builder_ffi_destroy_generate_candidates_response(
        resp
    ));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok(slice::from_raw_parts((*resp).candidates_ptr, (*resp).candidates_len).to_vec())
}

pub(crate) unsafe fn generate_post(
    ptr: *mut sector_builder_ffi_SectorBuilder,
    challenge_seed: [u8; 32],
    proving_set: &ProvingSet,
    winners: &[sector_builder_ffi_FFICandidate],
) -> Result<Vec<u8>, (sector_builder_ffi_FCPResponseStatus, String)> {
    let flattened_comm_rs = proving_set.flattened_comm_rs();

    let resp = sector_builder_ffi_generate_post(
        ptr,
        flattened_comm_rs.as_ptr(),
        flattened_comm_rs.len(),
        &mut challenge_seed.clone(),
        winners.as_ptr(),
        winners.len(),
    );
    defer!(sector_builder_ffi_destroy_generate_post_response(resp));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok(slice::from_raw_parts((*resp).flattened_proofs_ptr, (*resp).flattened_proofs_len).to_vec())
}

pub(crate) unsafe fn verify_post(
    sector_size: u64,
    challenge_seed: [u8; 32],
    proving_set: &ProvingSet,
    flattened_proofs: &[u8],
    winners: &[sector_builder_ffi_FFICandidate],
    prover_id: &[u8; 32],
) -> Result<bool, (sector_builder_ffi_FCPResponseStatus, String)> {
    let sector_ids = proving_set.all_sector_ids();
    let flattened_comm_rs = proving_set.flattened_comm_rs();

    let resp = sector_builder_ffi_reexported_verify_post(
        sector_size,
        &mut challenge_seed.clone(),
        sector_ids.as_ptr(),
        sector_ids.len(),
        flattened_comm_rs.as_ptr(),
        flattened_comm_rs.len(),
        flattened_proofs.as_ptr(),
        flattened_proofs.len(),
        winners.as_ptr(),
        winners.len(),
        &mut prover_id.clone(),
    );
    defer!(sector_builder_ffi_reexported_destroy_verify_post_response(
        resp
    ));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok((*resp).is_valid.clone())
}

pub(crate) unsafe fn get_sealed_sectors(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    with_health: bool,
) -> Result<
    Vec<sector_builder_ffi_FFISealedSectorMetadata>,
    (sector_builder_ffi_FCPResponseStatus, String),
> {
    let resp = sector_builder_ffi_get_sealed_sectors(ptr, with_health);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_get_sealed_sectors_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok(slice::from_raw_parts((*resp).meta_ptr, (*resp).meta_len).to_vec())
}

pub(crate) unsafe fn get_staged_sectors(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
) -> Result<
    Vec<sector_builder_ffi_FFIStagedSectorMetadata>,
    (sector_builder_ffi_FCPResponseStatus, String),
> {
    let resp = sector_builder_ffi_get_staged_sectors(ptr);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_get_staged_sectors_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok(slice::from_raw_parts((*resp).sectors_ptr, (*resp).sectors_len).to_vec())
}

#[cfg(not(target_os = "windows"))]
pub(crate) unsafe fn add_piece(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    piece_key: &str,
    piece_file: &std::fs::File,
    piece_len: usize,
    store_until_utc_secs: u64,
) -> Result<u64, (sector_builder_ffi_FCPResponseStatus, String)> {
    let c_piece_key = rust_str_to_c_str(piece_key);
    defer!(free_c_str(c_piece_key));

    use std::os::unix::io::AsRawFd;
    let c_piece_fd = piece_file.as_raw_fd() as libc::c_int;

    let resp = sector_builder_ffi_add_piece(
        ptr,
        c_piece_key,
        c_piece_fd,
        piece_len as u64,
        store_until_utc_secs,
    );
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_add_piece_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok((*resp).sector_id.clone())
}

pub(crate) unsafe fn get_seal_status(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
) -> Result<sector_builder_ffi_FFISealStatus, (sector_builder_ffi_FCPResponseStatus, String)> {
    let resp = sector_builder_ffi_get_seal_status(ptr, sector_id);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_get_seal_status_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok((*resp).seal_status_code.clone())
}

pub(crate) unsafe fn read_piece_from_sealed_sector(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    piece_key: &str,
) -> Result<Vec<u8>, (sector_builder_ffi_FCPResponseStatus, String)> {
    let c_piece_key = rust_str_to_c_str(piece_key);
    defer!(free_c_str(c_piece_key));

    let resp = sector_builder_ffi_read_piece_from_sealed_sector(ptr, c_piece_key);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_read_piece_from_sealed_sector_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok(slice::from_raw_parts((*resp).data_ptr, (*resp).data_len).to_vec())
}

pub(crate) unsafe fn generate_data_commitment(
    ctx: &mut Deallocator,
    sector_size: u64,
    piece_info: &[sector_builder_ffi_FFIPublicPieceInfo],
) -> Result<[u8; 32], (sector_builder_ffi_FCPResponseStatus, String)> {
    let resp = sector_builder_ffi_reexported_generate_data_commitment(
        sector_size,
        piece_info.as_ptr(),
        piece_info.len(),
    );
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_reexported_destroy_generate_data_commitment_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok((*resp).comm_d.clone())
}

#[cfg(not(target_os = "windows"))]
pub(crate) unsafe fn generate_piece_commitment(
    ctx: &mut Deallocator,
    piece_file: &mut std::fs::File,
    piece_len: usize,
) -> Result<[u8; 32], (sector_builder_ffi_FCPResponseStatus, String)> {
    use std::os::unix::io::AsRawFd;
    let c_piece_fd = piece_file.as_raw_fd();

    let resp =
        sector_builder_ffi_reexported_generate_piece_commitment(c_piece_fd, piece_len as u64);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_reexported_destroy_generate_piece_commitment_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok((*resp).comm_p.clone())
}

pub(crate) unsafe fn resume_seal_pre_commit(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
) -> Result<(), (sector_builder_ffi_FCPResponseStatus, String)> {
    let resp = sector_builder_ffi_resume_seal_pre_commit(ptr, sector_id);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_resume_seal_pre_commit_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok(())
}

pub(crate) unsafe fn resume_seal_commit(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
) -> Result<
    sector_builder_ffi_ResumeSealCommitResponse,
    (sector_builder_ffi_FCPResponseStatus, String),
> {
    let resp = sector_builder_ffi_resume_seal_commit(ptr, sector_id);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_resume_seal_commit_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok(*resp)
}

pub(crate) unsafe fn seal_pre_commit(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
    ticket: sector_builder_ffi_FFISealTicket,
) -> Result<
    sector_builder_ffi_SectorBuilderSealPreCommitResponse,
    (sector_builder_ffi_FCPResponseStatus, String),
> {
    let resp = sector_builder_ffi_seal_pre_commit(ptr, sector_id, ticket);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_seal_pre_commit_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok(*resp)
}

pub(crate) unsafe fn seal_commit(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
    seed: sector_builder_ffi_FFISealSeed,
) -> Result<
    sector_builder_ffi_SectorBuilderSealCommitResponse,
    (sector_builder_ffi_FCPResponseStatus, String),
> {
    let resp = sector_builder_ffi_seal_commit(ptr, sector_id, seed);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_seal_commit_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok(*resp)
}

pub(crate) unsafe fn verify_seal(
    ctx: &mut Deallocator,
    sector_size: u64,
    sector_id: u64,
    ticket: [u8; 32],
    seed: [u8; 32],
    proof: &[u8],
    comm_r: [u8; 32],
    comm_d: [u8; 32],
    prover_id: [u8; 32],
) -> Result<bool, (sector_builder_ffi_FCPResponseStatus, String)> {
    let resp = sector_builder_ffi_reexported_verify_seal(
        sector_size,
        &mut comm_r.clone(),
        &mut comm_d.clone(),
        &mut prover_id.clone(),
        sector_id,
        &mut ticket.clone(),
        &mut seed.clone(),
        proof.as_ptr(),
        proof.len(),
    );
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_reexported_destroy_verify_seal_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok((*resp).is_valid.clone())
}

pub(crate) unsafe fn get_max_user_bytes_per_staged_sector(sector_size: u64) -> u64 {
    sector_builder_ffi_reexported_get_max_user_bytes_per_staged_sector(sector_size)
}

pub(crate) unsafe fn destroy_sector_builder(mut p: *mut sector_builder_ffi_SectorBuilder) {
    sector_builder_ffi_destroy_sector_builder(p);
    p = ptr::null_mut();
    assert!(p.is_null());
}

pub(crate) unsafe fn init_sector_builder<T: AsRef<Path>>(
    ctx: &mut Deallocator,
    metadata_dir: T,
    staging_dir: T,
    sealed_dir: T,
    sector_cache_root_dir: T,
    prover_id: [u8; 32],
    last_committed_sector_id: u64,
    sector_class: sector_builder_ffi_FFISectorClass,
    max_num_staged_sectors: u8,
) -> Result<*mut sector_builder_ffi_SectorBuilder, (sector_builder_ffi_FCPResponseStatus, String)> {
    let c_metadata_dir = rust_str_to_c_str(metadata_dir.as_ref().to_str().unwrap());
    let c_sealed_dir = rust_str_to_c_str(sealed_dir.as_ref().to_str().unwrap());
    let c_staging_dir = rust_str_to_c_str(staging_dir.as_ref().to_str().unwrap());
    let c_sector_cache_root_dir =
        rust_str_to_c_str(sector_cache_root_dir.as_ref().to_str().unwrap());

    defer!({
        free_c_str(c_metadata_dir);
        free_c_str(c_sealed_dir);
        free_c_str(c_staging_dir);
        free_c_str(c_sector_cache_root_dir);
    });

    let resp = sector_builder_ffi_init_sector_builder(
        sector_class,
        last_committed_sector_id,
        c_metadata_dir,
        &mut prover_id.clone(),
        c_sealed_dir,
        c_staging_dir,
        c_sector_cache_root_dir,
        max_num_staged_sectors,
        2,
    );
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_init_sector_builder_response(resp);
    })));

    if (*resp).status_code != 0 {
        return Err((
            (*resp).status_code,
            c_str_to_rust_str((*resp).error_msg).to_string(),
        ));
    }

    Ok((*resp).sector_builder)
}
