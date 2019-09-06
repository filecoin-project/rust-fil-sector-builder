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
        .into_iter()
        .find(|ss| ss.sector_id == sector_id)
        .expect("no sealed sector with id 124");

    sealed_sector
}

pub(crate) unsafe fn get_sealed_piece(
    ctx: &mut Deallocator,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
    piece_key: &str,
) -> sector_builder_ffi_FFIPieceMetadata {
    let sealed_sector = get_sealed_sectors(ctx, ptr, true)
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
        .into_iter()
        .map(|ss| PoStSectorInfo {
            sector_id: ss.sector_id,
            comm_r: ss.comm_r,
            is_healthy: ss.health == sector_builder_ffi_FFISealedSectorHealth_Ok,
        })
        .collect()
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

            if get_seal_status(&mut Default::default(), sector_builder, sector_id) == target_status
            {
                let _ = result_tx.send(sector_id).unwrap();
            }

            thread::sleep(Duration::from_millis(1000));
        }
    });

    defer!({
        let _ = kill_tx.send(true).unwrap();
    });

    let now_sealed_sector_id = result_rx
        .recv_timeout(Duration::from_secs(max_wait_secs))
        .unwrap();

    assert_eq!(now_sealed_sector_id, sector_id);
}
