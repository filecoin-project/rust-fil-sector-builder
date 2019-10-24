use std::sync::atomic::AtomicPtr;
use std::sync::mpsc;
use std::time::Duration;
use std::{slice, thread};

use ffi_toolkit::c_str_to_rust_str;

use crate::deallocator::*;
use crate::plumbing::*;
use crate::provingset::*;

pub(crate) unsafe fn get_sealed_sector(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
) -> sector_builder_ffi_FFISealedSectorMetadata {
    let sealed_sector = get_sealed_sectors(ctx, ptr, true)
        .unwrap()
        .into_iter()
        .find(|ss| ss.sector_id == sector_id)
        .expect(&format!("no sealed sector with id {}", sector_id));

    sealed_sector
}

pub(crate) unsafe fn get_staged_sector(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
) -> sector_builder_ffi_FFIStagedSectorMetadata {
    let staged_sector = get_staged_sectors(ctx, ptr)
        .unwrap()
        .into_iter()
        .find(|ss| ss.sector_id == sector_id)
        .expect(&format!("no sealed sector with id {}", sector_id));

    staged_sector
}

pub(crate) unsafe fn get_sealed_piece(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
    piece_key: &str,
) -> sector_builder_ffi_FFIPieceMetadata {
    let sealed_sector = get_sealed_sectors(ctx, ptr, true)
        .unwrap()
        .into_iter()
        .find(|ss| ss.sector_id == sector_id)
        .expect(&format!("no sealed sector with id={}", sector_id));

    slice::from_raw_parts(sealed_sector.pieces_ptr, sealed_sector.pieces_len)
        .to_vec()
        .into_iter()
        .find(|&piece| {
            let pk = c_str_to_rust_str(piece.piece_key).to_string();
            &pk == piece_key
        })
        .expect(&format!(
            "no piece with key={} in sector with id={}",
            piece_key, sector_id
        ))
}

pub(crate) unsafe fn get_sector_info(
    mut ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
) -> Vec<PoStSectorInfo> {
    get_sealed_sectors(&mut ctx, ptr, true)
        .unwrap()
        .into_iter()
        .map(|ss| PoStSectorInfo {
            sector_id: ss.sector_id,
            comm_r: ss.comm_r,
            is_healthy: ss.health == sector_builder_ffi_FFISealedSectorHealth_Ok,
        })
        .collect()
}

pub(crate) unsafe fn seal_pre_commit_nonblocking(
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
    ticket: sector_builder_ffi_FFISealTicket,
) {
    let atomic_ptr = AtomicPtr::new(ptr);

    thread::spawn(move || {
        let sector_builder = atomic_ptr.into_inner();

        let _ = seal_pre_commit(&mut Default::default(), sector_builder, sector_id, ticket);
    });
}

pub(crate) unsafe fn resume_seal_pre_commit_nonblocking(
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
) {
    let atomic_ptr = AtomicPtr::new(ptr);

    thread::spawn(move || {
        let sector_builder = atomic_ptr.into_inner();

        let _ = resume_seal_pre_commit(&mut Default::default(), sector_builder, sector_id);
    });
}

pub(crate) unsafe fn seal_commit_nonblocking(
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
    seed: sector_builder_ffi_FFISealSeed,
) {
    let atomic_ptr = AtomicPtr::new(ptr);

    thread::spawn(move || {
        let sector_builder = atomic_ptr.into_inner();

        let _ = seal_commit(&mut Default::default(), sector_builder, sector_id, seed);
    });
}

pub(crate) unsafe fn resume_seal_commit_nonblocking(
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
) {
    let atomic_ptr = AtomicPtr::new(ptr);

    thread::spawn(move || {
        let sector_builder = atomic_ptr.into_inner();

        let _ = resume_seal_commit(&mut Default::default(), sector_builder, sector_id);
    });
}

enum PollComplete {
    Success(u64),
    Failure(String),
}

pub(crate) unsafe fn poll_for_sector_sealing_status(
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
    target_status: sector_builder_ffi_FFISealStatus,
    max_wait_secs: u64,
) -> () {
    let (result_tx, result_rx) = mpsc::channel();
    let (kill_tx, kill_rx) = mpsc::channel();

    let atomic_ptr = AtomicPtr::new(ptr);

    let _join_handle = thread::spawn(move || {
        let sector_builder = atomic_ptr.into_inner();

        loop {
            match kill_rx.try_recv() {
                Ok(_) => return,
                _ => (),
            };

            let status =
                get_seal_status(&mut Default::default(), sector_builder, sector_id).unwrap();

            if status == target_status {
                let _ = result_tx.send(PollComplete::Success(sector_id)).unwrap();
            } else if status == sector_builder_ffi_FFISealStatus_Failed {
                let meta = get_staged_sector(&mut Default::default(), sector_builder, sector_id);

                let s = format!(
                    "sealing failed for sector with id {:?} (reason = {:?})",
                    sector_id,
                    c_str_to_rust_str(meta.seal_error_msg)
                );

                let _ = result_tx.send(PollComplete::Failure(s)).unwrap();
            }

            thread::sleep(Duration::from_millis(1000));
        }
    });

    defer!({
        let _ = kill_tx.send(true).unwrap();
    });

    let x = result_rx
        .recv_timeout(Duration::from_secs(max_wait_secs))
        .unwrap();

    match x {
        PollComplete::Success(id) => assert_eq!(id, sector_id),
        PollComplete::Failure(msg) => panic!(msg),
    }
}
