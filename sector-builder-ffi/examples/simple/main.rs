#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(dead_code)]

#[macro_use]
extern crate log;
extern crate nix;
#[macro_use(defer)]
extern crate scopeguard;

use std::io::{Seek, SeekFrom};
use std::time::Duration;
use std::{env, fs};
use std::{slice, thread};

use ffi_toolkit::c_str_to_pbuf;
use nix::unistd::ForkResult;

use deallocator::*;
use helpers::*;
use plumbing::*;
use porcelain::*;
use provingset::*;

mod deallocator;
mod helpers;
mod plumbing;
mod porcelain;
mod provingset;

#[derive(Debug, Clone, Copy)]
struct LifecycleTestConfiguration {
    first_piece_bytes: usize,
    second_piece_bytes: usize,
    sector_class: sector_builder_ffi_FFISectorClass,
    third_piece_bytes: usize,
    fourth_piece_bytes: usize,
    max_num_staged_sectors: u8,
    max_secs_to_seal_sector: u64,
}

#[derive(Debug, Clone, Copy)]
struct KillRestartTestConfiguration {
    sector_class: sector_builder_ffi_FFISectorClass,
    max_num_staged_sectors: u8,
    max_secs_to_seal_sector: u64,
}

fn main() {
    pretty_env_logger::try_init_timed().expect("could not initialize logger");

    let sector_size = env::args()
        .collect::<Vec<String>>()
        .get(1)
        .expect("first argument must be sector size, in bytes")
        .parse::<u64>()
        .expect("could not parse argument to a sector size");

    unsafe { sector_builder_lifecycle(sector_size).unwrap() };
    unsafe { kill_restart_recovery(sector_size).unwrap() };
}

/// A test which simulates a sector builder being shutdown impolitely (SIGKILL).
/// Ensures that sealing jobs which had started but not yet completed are
/// resumed and that sector builder metadata is successfully recreated from the
/// last snapshot.
///
unsafe fn kill_restart_recovery(sector_size: u64) -> Result<(), failure::Error> {
    let cfg = KillRestartTestConfiguration {
        sector_class: sector_builder_ffi_FFISectorClass {
            sector_size,
            porep_proof_partitions: 2,
        },
        max_num_staged_sectors: 2,
        max_secs_to_seal_sector: 60 * 60, // TODO: something more rigorous
    };

    info!("running FFI test using cfg={:?}", cfg);

    let metadata_dir_a = tempfile::tempdir()?;
    let staging_dir_a = tempfile::tempdir()?;
    let sealed_dir_a = tempfile::tempdir()?;
    let sector_cache_root_dir_a = tempfile::tempdir()?;

    // clone the directory-paths so that we can move them into the child process
    let metadata_dir_a_c = metadata_dir_a.path().clone();
    let staging_dir_a_c = staging_dir_a.path().clone();
    let sealed_dir_a_c = sealed_dir_a.path().clone();
    let sector_cache_root_dir_a_c = sector_cache_root_dir_a.path().clone();

    let prover_id = [1u8; 32];
    let seal_ticket = [1u8; 32];

    let mut ctx: Deallocator = Default::default();

    // use an OS pipe so that we can communicate between processes
    let (mut done_tx, mut done_rx) = pipe_channel::channel();

    // The exclusive file lock which sled acquires on its database is scoped to
    // a file descriptor pointing to the opened database-file, and the lock is
    // released when that file descriptor is no longer valid. Instead of
    // exposing the file descriptor to this test, we instead let the file
    // descriptor be owned by a process which we control. When we kill the
    // process, the OS closes its file descriptors which in turn releases the
    // lock. This behavior would not be exhibited were we to spawn a thread
    // instead of forking a process.
    //
    // Motivated by rust-fil-sector-builder/17.
    match nix::unistd::fork() {
        Ok(ForkResult::Parent { child, .. }) => {
            let _ = done_rx.recv().unwrap();

            // send SIGKILL to the child process
            nix::sys::signal::kill(child, nix::sys::signal::SIGKILL).unwrap();

            // wait for the child process to die
            nix::sys::wait::waitpid(child, None).unwrap();
        }
        Ok(ForkResult::Child) => {
            let max_user_bytes = get_max_user_bytes_per_staged_sector(cfg.sector_class.sector_size);

            let mut ctx: Deallocator = Default::default();

            let ptr = init_sector_builder(
                &mut ctx,
                &metadata_dir_a_c,
                &staging_dir_a_c,
                &sealed_dir_a_c,
                &sector_cache_root_dir_a_c,
                prover_id,
                500,
                cfg.sector_class,
                cfg.max_num_staged_sectors,
            );

            // add a piece which completely fills a staged sector
            {
                let MakePiece { file, bytes, key } = make_piece(max_user_bytes as usize);
                assert_eq!(
                    501,
                    add_piece(&mut ctx, ptr, &key, file.as_file(), bytes.len(), 5000000)
                );
            }

            // call seal_sector w/out blocking
            seal_sector_nonblocking(
                ptr,
                501,
                sector_builder_ffi_FFISealTicket {
                    block_height: 2,
                    ticket_bytes: seal_ticket,
                },
            );

            // block until sector sealing begins
            poll_for_sector_sealing_status(
                ptr,
                501,
                sector_builder_ffi_FFISealStatus_Sealing,
                cfg.max_secs_to_seal_sector * 2,
            );

            std::mem::drop(ctx);

            // send the completion signal
            done_tx.send(true).expect("failed to send");

            // loop until the parent kills this process
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        Err(err) => panic!(err),
    }

    // initialize a sector builder
    let ptr = init_sector_builder(
        &mut Default::default(),
        &metadata_dir_a,
        &staging_dir_a,
        &sealed_dir_a,
        &sector_cache_root_dir_a,
        prover_id,
        500,
        cfg.sector_class,
        cfg.max_num_staged_sectors,
    );
    defer!(sector_builder_ffi_destroy_sector_builder(ptr));

    // resume sealing for all paused sectors
    {
        let mut n = 0;
        for s in get_staged_sectors(&mut ctx, ptr).iter() {
            if s.seal_status_code == sector_builder_ffi_FFISealStatus_Paused {
                resume_seal_sector_nonblocking(ptr, s.sector_id);
                n = n + 1;
            }
        }
        assert_eq!(n, 1, "should have resumed but one seal op");
    }

    // block until the sector has sealed
    poll_for_sector_sealing_status(
        ptr,
        501,
        sector_builder_ffi_FFISealStatus_Sealed,
        cfg.max_secs_to_seal_sector * 2,
    );

    // get sealed sector and verify the proof using the second ticket
    {
        let sealed_sector = get_sealed_sector(&mut ctx, ptr, 501);

        assert!(
            verify_seal(
                &mut ctx,
                cfg.sector_class.sector_size,
                sealed_sector.sector_id,
                seal_ticket,
                slice::from_raw_parts(sealed_sector.proofs_ptr, sealed_sector.proofs_len),
                sealed_sector.comm_r,
                sealed_sector.comm_d,
                prover_id,
            ),
            "seal verification failed for sector with id 501"
        );
    }

    Ok(())
}

/// A somewhat-exhaustive battery of sector builder tests, including:
///
/// - bin packing (adding pieces)
/// - sealing
/// - PoSt generation
/// - proof verification
/// - unsealing
/// - piece commitment generation
/// - PIP verification
/// - migrating metadata and sector directories
/// - polling for sector sealing-status
/// - getting sealed and staged sector metadata
///
unsafe fn sector_builder_lifecycle(sector_size: u64) -> Result<(), failure::Error> {
    let cfg = LifecycleTestConfiguration {
        sector_class: sector_builder_ffi_FFISectorClass {
            sector_size,
            porep_proof_partitions: 2,
        },
        first_piece_bytes: ((400.0 / 1024.0) * (sector_size as f64)) as usize,
        second_piece_bytes: ((200.0 / 1024.0) * (sector_size as f64)) as usize,
        third_piece_bytes: ((500.0 / 1024.0) * (sector_size as f64)) as usize,
        fourth_piece_bytes: ((200.0 / 1024.0) * (sector_size as f64)) as usize,
        max_num_staged_sectors: 2,
        max_secs_to_seal_sector: 60 * 60, // TODO: something more rigorous
    };

    info!("running FFI test using cfg={:?}", cfg);

    let metadata_dir_a = tempfile::tempdir()?;
    let metadata_dir_b = tempfile::tempdir()?;
    let staging_dir_a = tempfile::tempdir()?;
    let staging_dir_b = tempfile::tempdir()?;
    let sealed_dir_a = tempfile::tempdir()?;
    let sealed_dir_b = tempfile::tempdir()?;
    let sector_cache_root_dir_a = tempfile::tempdir()?;
    let sector_cache_root_dir_b = tempfile::tempdir()?;

    let prover_id = [1u8; 32];
    let seal_ticket = [1u8; 32];

    let mut ctx: Deallocator = Default::default();

    let a_ptr = init_sector_builder(
        &mut ctx,
        &metadata_dir_a,
        &staging_dir_a,
        &sealed_dir_a,
        &sector_cache_root_dir_a,
        prover_id,
        123,
        cfg.sector_class,
        cfg.max_num_staged_sectors,
    );

    // verify that we have neither sealed nor staged sectors yet
    {
        let sealed_sectors = get_sealed_sectors(&mut ctx, a_ptr, false);
        let staged_sectors = get_staged_sectors(&mut ctx, a_ptr);
        assert_eq!(0, sealed_sectors.len());
        assert_eq!(0, staged_sectors.len());
    }

    // add first piece, which lazily provisions a new staged sector
    {
        let MakePiece { file, bytes, key } = make_piece(cfg.first_piece_bytes);
        assert_eq!(
            124,
            add_piece(&mut ctx, a_ptr, &key, file.as_file(), bytes.len(), 5000000)
        );
    }

    // add second piece, which fits into existing staged sector
    {
        let MakePiece { file, bytes, key } = make_piece(cfg.second_piece_bytes);
        assert_eq!(
            124,
            add_piece(&mut ctx, a_ptr, &key, file.as_file(), bytes.len(), 5000000)
        );
    }

    // add third piece, which won't fit into existing staging sector
    {
        let MakePiece { file, bytes, key } = make_piece(cfg.third_piece_bytes);
        assert_eq!(
            125,
            add_piece(&mut ctx, a_ptr, &key, file.as_file(), bytes.len(), 5000000)
        );
    }

    // get staged sector metadata and verify that we've now got two staged
    // sectors
    {
        let staged_sectors = get_staged_sectors(&mut ctx, a_ptr);
        assert_eq!(2, staged_sectors.len());
    }

    // add fourth piece, which fills the remaining space in 124
    let MakePiece {
        file: mut fourth_piece_file,
        bytes: fourth_piece_bytes,
        key: fourth_piece_key,
    } = make_piece(cfg.fourth_piece_bytes);
    assert_eq!(
        124,
        add_piece(
            &mut ctx,
            a_ptr,
            &fourth_piece_key,
            fourth_piece_file.as_file(),
            fourth_piece_bytes.len(),
            5000000
        )
    );

    seal_sector_nonblocking(
        a_ptr,
        124,
        sector_builder_ffi_FFISealTicket {
            block_height: 10,
            ticket_bytes: seal_ticket,
        },
    );

    seal_sector_nonblocking(
        a_ptr,
        125,
        sector_builder_ffi_FFISealTicket {
            block_height: 10,
            ticket_bytes: seal_ticket,
        },
    );

    // block until both sectors have been sealed - note that we won't know which
    // of the two sectors will seal first
    poll_for_sector_sealing_status(
        a_ptr,
        124,
        sector_builder_ffi_FFISealStatus_Sealed,
        cfg.max_secs_to_seal_sector * 2,
    );

    poll_for_sector_sealing_status(
        a_ptr,
        125,
        sector_builder_ffi_FFISealStatus_Sealed,
        cfg.max_secs_to_seal_sector * 2,
    );

    // drop the first sector builder, relinquishing any locks on persistence
    destroy_sector_builder(a_ptr);

    // migrate staged sectors, sealed sectors, and sector builder metadata to
    // new directory (overwrites destination directory)
    let b_ptr = {
        let renames = vec![
            (metadata_dir_a.as_ref(), metadata_dir_b.as_ref()),
            (staging_dir_a.as_ref(), staging_dir_b.as_ref()),
            (sealed_dir_a.as_ref(), sealed_dir_b.as_ref()),
            (
                sector_cache_root_dir_a.as_ref(),
                sector_cache_root_dir_b.as_ref(),
            ),
        ];

        for (from, to) in renames {
            fs::rename(from, to).expect(&format!("could not rename from {:?} to {:?}", from, to));
        }

        // create a new sector builder using the new staged sector dir and original
        // prover id, which will initialize with metadata persisted by previous
        // sector builder
        init_sector_builder(
            &mut ctx,
            &metadata_dir_b,
            &staging_dir_b,
            &sealed_dir_b,
            &sector_cache_root_dir_b,
            prover_id,
            125,
            cfg.sector_class,
            cfg.max_num_staged_sectors,
        )
    };
    defer!(sector_builder_ffi_destroy_sector_builder(b_ptr));

    // after sealing, read the bytes (triggering unseal) and compare with what
    // we've added to the sector
    {
        let unsealed_bytes = read_piece_from_sealed_sector(&mut ctx, b_ptr, &fourth_piece_key);
        assert_eq!(
            format!("{:x?}", fourth_piece_bytes),
            format!("{:x?}", unsealed_bytes)
        );
    }

    // get sealed sector and verify the proof using the ticket we sealed with
    {
        let sealed_sector = get_sealed_sector(&mut ctx, b_ptr, 124);

        assert!(
            verify_seal(
                &mut ctx,
                cfg.sector_class.sector_size,
                sealed_sector.sector_id,
                seal_ticket,
                slice::from_raw_parts(sealed_sector.proofs_ptr, sealed_sector.proofs_len),
                sealed_sector.comm_r,
                sealed_sector.comm_d,
                prover_id,
            ),
            "seal verification failed for sector with id 124"
        );
    }

    // get second sealed sector and verify the proof using the second ticket
    {
        let sealed_sector = get_sealed_sector(&mut ctx, b_ptr, 125);

        assert!(
            verify_seal(
                &mut ctx,
                cfg.sector_class.sector_size,
                sealed_sector.sector_id,
                seal_ticket,
                slice::from_raw_parts(sealed_sector.proofs_ptr, sealed_sector.proofs_len),
                sealed_sector.comm_r,
                sealed_sector.comm_d,
                prover_id,
            ),
            "seal verification failed for sector with id 125"
        );
    }

    // storage client and miner should generate identical CommP for the same
    // piece
    {
        fourth_piece_file
            .as_file_mut()
            .seek(SeekFrom::Start(0))
            .expect("failed to seek to the start");

        assert_eq!(
            format!("{:x?}", get_sealed_piece(&mut ctx, b_ptr, 124, &fourth_piece_key).comm_p),
            format!(
                "{:x?}",
                generate_piece_commitment(&mut ctx, fourth_piece_file.as_file_mut(), fourth_piece_bytes.len())
            ),
            "client (generate_piece_commitment) and server (during seal) generated different piece commitments"
        );
    }

    // get sealed sectors w/health checks
    {
        assert_eq!(2, get_sealed_sectors(&mut ctx, b_ptr, true).len());

        assert_eq!(
            get_sealed_sector(&mut ctx, b_ptr, 125).health,
            sector_builder_ffi_FFISealedSectorHealth_Ok
        );

        let sealed_sector_path = sealed_dir_b.path().join(c_str_to_pbuf(
            get_sealed_sector(&mut ctx, b_ptr, 125).sector_access,
        ));

        let content = std::fs::read(&sealed_sector_path).expect("failed to read sector data");

        // change 1 byte
        let mut new_content = content.clone();
        new_content[0] = new_content[0].wrapping_add(1);

        // write back
        std::fs::write(&sealed_sector_path, &new_content).expect("failed to write fake sector");

        // invalid checksum
        assert_eq!(
            get_sealed_sector(&mut ctx, b_ptr, 125).health,
            sector_builder_ffi_FFISealedSectorHealth_ErrorInvalidChecksum
        );
    }

    // verify piece inclusion proofs
    {
        let sealed_sector = get_sealed_sector(&mut ctx, b_ptr, 124);

        for piece in slice::from_raw_parts(sealed_sector.pieces_ptr, sealed_sector.pieces_len) {
            assert!(
                verify_piece_inclusion_proof(
                    cfg.sector_class.sector_size,
                    sealed_sector.comm_d.clone(),
                    piece.comm_p,
                    slice::from_raw_parts(
                        piece.piece_inclusion_proof_ptr,
                        piece.piece_inclusion_proof_len
                    ),
                    piece.num_bytes as usize
                ),
                "PIP invalid"
            );
        }
    }

    // generate and then verify a proof-of-spacetime for the sealed sector
    {
        let cseed = [1u8; 32];
        let p_set = ProvingSet::new(get_sector_info(&mut ctx, b_ptr));
        let proof = generate_post(b_ptr, cseed, &p_set);

        assert!(
            verify_post(cfg.sector_class.sector_size, cseed, &p_set, &proof),
            "PoSt was invalid"
        );
    }

    Ok(())
}
