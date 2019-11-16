use ffi_toolkit::catch_panic_response;

/// Returns the number of user bytes (before bit-padding has been added) which
/// will fit into a sector of the given size.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_get_max_user_bytes_per_staged_sector(
    sector_size: u64,
) -> u64 {
    crate::api::init_log();

    filecoin_proofs_ffi::api::get_max_user_bytes_per_staged_sector(sector_size)
}

/// Returns the merkle root for a piece after piece padding and alignment.
/// The caller is responsible for closing the file descriptor.
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn sector_builder_ffi_reexported_generate_piece_commitment(
    piece_fd_raw: libc::c_int,
    unpadded_piece_size: u64,
) -> *mut filecoin_proofs_ffi::types::GeneratePieceCommitmentResponse {
    catch_panic_response(|| {
        crate::api::init_log();

        filecoin_proofs_ffi::api::generate_piece_commitment(piece_fd_raw, unpadded_piece_size)
    })
}

/// Verifies the output of seal.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_verify_seal(
    sector_size: u64,
    comm_r: &[u8; 32],
    comm_d: &[u8; 32],
    prover_id: &[u8; 32],
    sector_id: u64,
    ticket: &[u8; 32],
    seed: &[u8; 32],
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> *mut filecoin_proofs_ffi::types::VerifySealResponse {
    catch_panic_response(|| {
        crate::api::init_log();

        filecoin_proofs_ffi::api::verify_seal(
            sector_size,
            comm_r,
            comm_d,
            prover_id,
            ticket,
            seed,
            sector_id,
            proof_ptr,
            proof_len,
        )
    })
}

/// Generate a data commitment for a sector containing the provided pieces.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_generate_data_commitment(
    sector_size: u64,
    pieces_ptr: *const filecoin_proofs_ffi::types::FFIPublicPieceInfo,
    pieces_len: libc::size_t,
) -> *mut filecoin_proofs_ffi::types::GenerateDataCommitmentResponse {
    catch_panic_response(|| {
        crate::api::init_log();
        filecoin_proofs_ffi::api::generate_data_commitment(sector_size, pieces_ptr, pieces_len)
    })
}

/// Verifies that a proof-of-spacetime is valid.
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_verify_post(
    sector_size: u64,
    randomness: &[u8; 32],
    sector_ids_ptr: *const u64,
    sector_ids_len: libc::size_t,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
    winners_ptr: *const filecoin_proofs_ffi::types::FFIWinner,
    winners_len: libc::size_t,
    prover_id: &[u8; 32],
) -> *mut filecoin_proofs_ffi::types::VerifyPoStResponse {
    catch_panic_response(|| {
        crate::api::init_log();

        filecoin_proofs_ffi::api::verify_post(
            sector_size,
            randomness,
            sector_ids_ptr,
            sector_ids_len,
            flattened_comm_rs_ptr,
            flattened_comm_rs_len,
            flattened_proofs_ptr,
            flattened_proofs_len,
            winners_ptr,
            winners_len,
            &prover_id,
        )
    })
}

/// Finalizes a partial_ticket.
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_finalize_ticket(
    partial_ticket: &[u8; 32],
) -> *mut filecoin_proofs_ffi::types::FinalizeTicketResponse {
    catch_panic_response(|| {
        crate::api::init_log();

        filecoin_proofs_ffi::api::finalize_ticket(partial_ticket)
    })
}

/// TODO: document
///
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn sector_builder_ffi_reexported_write_with_alignment(
    src_fd: libc::c_int,
    src_size: u64,
    dst_fd: libc::c_int,
    existing_piece_sizes_ptr: *const u64,
    existing_piece_sizes_len: libc::size_t,
) -> *mut filecoin_proofs_ffi::types::WriteWithAlignmentResponse {
    catch_panic_response(|| {
        crate::api::init_log();

        filecoin_proofs_ffi::api::write_with_alignment(
            src_fd,
            src_size,
            dst_fd,
            existing_piece_sizes_ptr,
            existing_piece_sizes_len,
        )
    })
}

/// TODO: document
///
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn sector_builder_ffi_reexported_write_without_alignment(
    src_fd: libc::c_int,
    src_size: u64,
    dst_fd: libc::c_int,
) -> *mut filecoin_proofs_ffi::types::WriteWithoutAlignmentResponse {
    catch_panic_response(|| {
        crate::api::init_log();

        filecoin_proofs_ffi::api::write_without_alignment(src_fd, src_size, dst_fd)
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_seal_pre_commit(
    sector_class: filecoin_proofs_ffi::types::FFISectorClass,
    cache_dir_path: *const libc::c_char,
    staged_sector_path: *const libc::c_char,
    sealed_sector_path: *const libc::c_char,
    sector_id: u64,
    prover_id: &[u8; 32],
    ticket: &[u8; 32],
    pieces_ptr: *const filecoin_proofs_ffi::types::FFIPublicPieceInfo,
    pieces_len: libc::size_t,
) -> *mut filecoin_proofs_ffi::types::SealPreCommitResponse {
    catch_panic_response(|| {
        crate::api::init_log();

        filecoin_proofs_ffi::api::seal_pre_commit(
            sector_class,
            cache_dir_path,
            staged_sector_path,
            sealed_sector_path,
            sector_id,
            prover_id,
            ticket,
            pieces_ptr,
            pieces_len,
        )
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_seal_commit(
    sector_class: filecoin_proofs_ffi::types::FFISectorClass,
    cache_dir_path: *const libc::c_char,
    sector_id: u64,
    prover_id: &[u8; 32],
    ticket: &[u8; 32],
    seed: &[u8; 32],
    pieces_ptr: *const filecoin_proofs_ffi::types::FFIPublicPieceInfo,
    pieces_len: libc::size_t,
    spco: filecoin_proofs_ffi::types::FFISealPreCommitOutput,
) -> *mut filecoin_proofs_ffi::types::SealCommitResponse {
    catch_panic_response(|| {
        crate::api::init_log();

        filecoin_proofs_ffi::api::seal_commit(
            sector_class,
            cache_dir_path,
            sector_id,
            prover_id,
            ticket,
            seed,
            pieces_ptr,
            pieces_len,
            spco,
        )
    })
}

/// TODO: document
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_unseal(
    sector_class: filecoin_proofs_ffi::types::FFISectorClass,
    sealed_sector_path: *const libc::c_char,
    unseal_output_path: *const libc::c_char,
    sector_id: u64,
    prover_id: &[u8; 32],
    ticket: &[u8; 32],
    comm_d: &[u8; 32],
) -> *mut filecoin_proofs_ffi::types::UnsealResponse {
    catch_panic_response(|| {
        crate::api::init_log();

        filecoin_proofs_ffi::api::unseal(
            sector_class,
            sealed_sector_path,
            unseal_output_path,
            sector_id,
            prover_id,
            ticket,
            comm_d,
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_destroy_verify_seal_response(
    ptr: *mut filecoin_proofs_ffi::types::VerifySealResponse,
) {
    filecoin_proofs_ffi::api::destroy_verify_seal_response(ptr)
}

/// Deallocates a VerifyPoStResponse.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_destroy_verify_post_response(
    ptr: *mut filecoin_proofs_ffi::types::VerifyPoStResponse,
) {
    filecoin_proofs_ffi::api::destroy_verify_post_response(ptr)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_destroy_finalize_ticket_response(
    ptr: *mut filecoin_proofs_ffi::types::FinalizeTicketResponse,
) {
    filecoin_proofs_ffi::api::destroy_finalize_ticket_response(ptr)
}

/// Deallocates a GeneratePieceCommitmentResponse.
///
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn sector_builder_ffi_reexported_destroy_generate_piece_commitment_response(
    ptr: *mut filecoin_proofs_ffi::types::GeneratePieceCommitmentResponse,
) {
    filecoin_proofs_ffi::api::destroy_generate_piece_commitment_response(ptr)
}

/// Deallocates a GenerateDataCommitmentResponse.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_destroy_generate_data_commitment_response(
    ptr: *mut filecoin_proofs_ffi::types::GenerateDataCommitmentResponse,
) {
    filecoin_proofs_ffi::api::destroy_generate_data_commitment_response(ptr)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_destroy_unseal_response(
    ptr: *mut filecoin_proofs_ffi::types::UnsealResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_destroy_seal_commit_response(
    ptr: *mut filecoin_proofs_ffi::types::SealCommitResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_destroy_seal_pre_commit_response(
    ptr: *mut filecoin_proofs_ffi::types::SealPreCommitResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_destroy_write_without_alignment_response(
    ptr: *mut filecoin_proofs_ffi::types::WriteWithoutAlignmentResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_reexported_destroy_write_with_alignment_response(
    ptr: *mut filecoin_proofs_ffi::types::WriteWithAlignmentResponse,
) {
    let _ = Box::from_raw(ptr);
}
