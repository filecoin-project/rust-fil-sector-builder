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
    max_num_staged_sectors: u8,
    max_secs_to_seal_sector: u64,
    second_piece_bytes: usize,
    sector_class: sector_builder_ffi_FFISectorClass,
    third_piece_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
struct KillRestartTestConfiguration {
    sector_class: sector_builder_ffi_FFISectorClass,
    max_num_staged_sectors: u8,
    max_secs_to_seal_sector: u64,
}

#[derive(Debug, Clone, Copy)]
struct StateTransitionsTestConfiguration {
    half_sector_size_unpadded: usize,
    max_num_staged_sectors: u8,
    max_secs_to_seal_sector: u64,
    sector_class: sector_builder_ffi_FFISectorClass,
    seal_seed: sector_builder_ffi_FFISealSeed,
    seal_ticket: sector_builder_ffi_FFISealTicket,
    prover_id: [u8; 32],
}

fn main() {
    pretty_env_logger::try_init_timed().expect("could not initialize logger");

    let sector_size = env::args()
        .collect::<Vec<String>>()
        .get(1)
        .expect("first argument must be sector size, in bytes")
        .parse::<u64>()
        .expect("could not parse argument to a sector size");

    let test_idx = env::args()
        .collect::<Vec<String>>()
        .get(2)
        .expect("first argument must test index")
        .parse::<usize>()
        .expect("could not parse argument to a usize");

    match test_idx {
        0 => unsafe {
            sector_state_transitions(sector_size).unwrap();
            sector_builder_lifecycle(sector_size).unwrap();
            kill_restart_recovery(sector_size).unwrap();
        },
        1 => unsafe { sector_state_transitions(sector_size).unwrap() },
        2 => unsafe { sector_builder_lifecycle(sector_size).unwrap() },
        3 => unsafe { kill_restart_recovery(sector_size).unwrap() },
        _ => panic!("test index {:?} not supported", test_idx),
    }
}

/// A test which demonstrates the various state transitions for a staged sector
/// on its journey towards being sealed.
unsafe fn sector_state_transitions(sector_size: u64) -> Result<(), failure::Error> {
    let cfg = StateTransitionsTestConfiguration {
        sector_class: sector_builder_ffi_FFISectorClass {
            sector_size,
            porep_proof_partitions: 2,
        },
        seal_seed: sector_builder_ffi_FFISealSeed {
            block_height: 10,
            ticket_bytes: [0u8; 32],
        },
        seal_ticket: sector_builder_ffi_FFISealTicket {
            block_height: 15,
            ticket_bytes: [1u8; 32],
        },
        half_sector_size_unpadded: ((508.0 / 1024.0) * (sector_size as f64)) as usize,
        max_num_staged_sectors: 2,
        max_secs_to_seal_sector: 60 * 60, // TODO: something more rigorous
        prover_id: [4u8; 32],
    };

    let mut ctx: Deallocator = Default::default();

    info!("running FFI test using cfg={:?}", cfg);

    let dir_meta = tempfile::tempdir()?;
    let dir_stag = tempfile::tempdir()?;
    let dir_seal = tempfile::tempdir()?;
    let dir_cach = tempfile::tempdir()?;

    let ptr = init_sector_builder(
        &mut ctx,
        &dir_meta,
        &dir_stag,
        &dir_seal,
        &dir_cach,
        cfg.prover_id,
        600,
        cfg.sector_class,
        cfg.max_num_staged_sectors,
    )
    .unwrap();

    // add a piece that half-fills a sector
    let MakePiece { file, bytes, key } = make_piece(cfg.half_sector_size_unpadded);
    assert_eq!(
        601,
        add_piece(&mut ctx, ptr, &key, file.as_file(), bytes.len(), 5000000).unwrap()
    );

    // block until state==AcceptingPieces
    poll_for_sector_sealing_status(
        ptr,
        601,
        sector_builder_ffi_FFISealStatus_AcceptingPieces,
        5,
    );

    // verify can't pre-commit
    assert!(
        seal_pre_commit(&mut ctx, ptr, 601, cfg.seal_ticket).is_err(),
        "invalid transition: pre-commit(accepting)"
    );

    // verify can't commit
    assert!(
        seal_commit(&mut ctx, ptr, 601, cfg.seal_seed).is_err(),
        "invalid transition: commit(accepting)"
    );

    // verify can't resume pre-commit
    assert!(
        resume_seal_pre_commit(&mut ctx, ptr, 601).is_err(),
        "invalid transition: resume pre-commit(accepting)"
    );

    // verify can't resume commit
    assert!(
        resume_seal_commit(&mut ctx, ptr, 601).is_err(),
        "invalid transition: resume commit(accepting)"
    );

    // add a piece that fills the remaining space
    let MakePiece { file, bytes, key } = make_piece(cfg.half_sector_size_unpadded);
    assert_eq!(
        601,
        add_piece(&mut ctx, ptr, &key, file.as_file(), bytes.len(), 5000000).unwrap()
    );

    // block until state==FullyPacked
    poll_for_sector_sealing_status(ptr, 601, sector_builder_ffi_FFISealStatus_FullyPacked, 5);

    // verify can't commit
    assert!(
        seal_commit(&mut ctx, ptr, 601, cfg.seal_seed).is_err(),
        "invalid transition: commit(fully)"
    );

    // verify can't resume pre-commit
    assert!(
        resume_seal_pre_commit(&mut ctx, ptr, 601).is_err(),
        "invalid transition: resume pre-commit(fully)"
    );

    // verify can't resume commit
    assert!(
        resume_seal_commit(&mut ctx, ptr, 601).is_err(),
        "invalid transition: resume commit(fully)"
    );

    // pre-commit sector
    seal_pre_commit_nonblocking(ptr, 601, cfg.seal_ticket);

    // block until state==PreCommitting
    poll_for_sector_sealing_status(ptr, 601, sector_builder_ffi_FFISealStatus_PreCommitting, 5);

    // verify can't pre-commit
    assert!(
        seal_pre_commit(&mut ctx, ptr, 601, cfg.seal_ticket).is_err(),
        "invalid transition: pre-commit(pre-committing)"
    );

    // verify can't commit
    assert!(
        seal_commit(&mut ctx, ptr, 601, cfg.seal_seed).is_err(),
        "invalid transition: commit(pre-committing)"
    );

    // verify can't resume pre-commit
    assert!(
        resume_seal_pre_commit(&mut ctx, ptr, 601).is_err(),
        "invalid transition: resume pre-commit(pre-committing)"
    );

    // verify can't resume commit
    assert!(
        resume_seal_commit(&mut ctx, ptr, 601).is_err(),
        "invalid transition: resume commit(pre-committing)"
    );

    // block until state==PreCommitting
    poll_for_sector_sealing_status(
        ptr,
        601,
        sector_builder_ffi_FFISealStatus_PreCommitted,
        cfg.max_secs_to_seal_sector,
    );

    // commit
    seal_commit_nonblocking(ptr, 601, cfg.seal_seed);

    // block until state==Committing
    poll_for_sector_sealing_status(ptr, 601, sector_builder_ffi_FFISealStatus_Committing, 5);

    // verify can't pre-commit
    assert!(
        seal_pre_commit(&mut ctx, ptr, 601, cfg.seal_ticket).is_err(),
        "invalid transition: pre-commit(pre-committing)"
    );

    // verify can't commit
    assert!(
        seal_commit(&mut ctx, ptr, 601, cfg.seal_seed).is_err(),
        "invalid transition: commit(pre-committing)"
    );

    // verify can't resume pre-commit
    assert!(
        resume_seal_pre_commit(&mut ctx, ptr, 601).is_err(),
        "invalid transition: resume pre-commit(pre-committing)"
    );

    // verify can't resume commit
    assert!(
        resume_seal_commit(&mut ctx, ptr, 601).is_err(),
        "invalid transition: resume commit(pre-committing)"
    );

    // block until state==Committed
    poll_for_sector_sealing_status(
        ptr,
        601,
        sector_builder_ffi_FFISealStatus_Committed,
        cfg.max_secs_to_seal_sector,
    );

    // verify can't pre-commit
    assert!(
        seal_pre_commit(&mut ctx, ptr, 601, cfg.seal_ticket).is_err(),
        "invalid transition: pre-commit(pre-committing)"
    );

    // verify can't commit
    assert!(
        seal_commit(&mut ctx, ptr, 601, cfg.seal_seed).is_err(),
        "invalid transition: commit(pre-committing)"
    );

    // verify can't resume pre-commit
    assert!(
        resume_seal_pre_commit(&mut ctx, ptr, 601).is_err(),
        "invalid transition: resume pre-commit(pre-committing)"
    );

    // verify can't resume commit
    assert!(
        resume_seal_commit(&mut ctx, ptr, 601).is_err(),
        "invalid transition: resume commit(pre-committing)"
    );

    Ok(())
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
    let seal_seed = [3u8; 32];

    let mut ctx: Deallocator = Default::default();

    // use an OS pipe so that we can communicate between processes
    let (mut done_tx, mut done_rx) = pipe_channel::channel();

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
            )
            .unwrap();

            // add a piece which completely fills a staged sector
            {
                let MakePiece { file, bytes, key } = make_piece(max_user_bytes as usize);
                assert_eq!(
                    501,
                    add_piece(&mut ctx, ptr, &key, file.as_file(), bytes.len(), 5000000).unwrap()
                );
            }

            // call seal_sector w/out blocking
            seal_pre_commit_nonblocking(
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
                sector_builder_ffi_FFISealStatus_PreCommitting,
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
    )
    .unwrap();
    defer!(sector_builder_ffi_destroy_sector_builder(ptr));

    // resume sealing for all paused sectors
    {
        let mut n = 0;
        for s in get_staged_sectors(&mut ctx, ptr).unwrap().iter() {
            if s.seal_status_code == sector_builder_ffi_FFISealStatus_PreCommittingPaused {
                resume_seal_pre_commit_nonblocking(ptr, s.sector_id);
                n = n + 1;
            }
        }
        assert_eq!(n, 1, "should have resumed but one pre-commit op");
    }

    // wait until pre-commit completes
    poll_for_sector_sealing_status(
        ptr,
        501,
        sector_builder_ffi_FFISealStatus_PreCommitted,
        cfg.max_secs_to_seal_sector * 2,
    );

    // commit sector
    seal_commit_nonblocking(
        ptr,
        501,
        sector_builder_ffi_FFISealSeed {
            block_height: 10,
            ticket_bytes: seal_seed,
        },
    );

    // wait until commit completes
    poll_for_sector_sealing_status(
        ptr,
        501,
        sector_builder_ffi_FFISealStatus_Committed,
        cfg.max_secs_to_seal_sector * 2,
    );

    // generate comm_d and ensure that it matches what was generated while
    // sealing
    {
        let sealed_sector = get_sealed_sector(&mut ctx, ptr, 501);

        let public_piece_info: Vec<sector_builder_ffi_FFIPublicPieceInfo> =
            slice::from_raw_parts(sealed_sector.pieces_ptr, sealed_sector.pieces_len)
                .iter()
                .map(|p| sector_builder_ffi_FFIPublicPieceInfo {
                    comm_p: p.comm_p,
                    num_bytes: p.num_bytes,
                })
                .collect();

        let x =
            generate_data_commitment(&mut ctx, cfg.sector_class.sector_size, &public_piece_info);

        if let Ok(comm_d) = x {
            assert_eq!(
                comm_d, sealed_sector.comm_d,
                "generated data commitment and seal output comm_d don't match"
            );
        } else {
            panic!("generate_data_commitment failed: {:?}", x);
        }
    }

    // get sealed sector and verify the proof using the second ticket
    {
        let sealed_sector = get_sealed_sector(&mut ctx, ptr, 501);

        assert!(
            verify_seal(
                &mut ctx,
                cfg.sector_class.sector_size,
                sealed_sector.sector_id,
                seal_ticket,
                seal_seed,
                slice::from_raw_parts(sealed_sector.proofs_ptr, sealed_sector.proofs_len),
                sealed_sector.comm_r,
                sealed_sector.comm_d,
                prover_id,
            )
            .unwrap(),
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
        first_piece_bytes: ((254.0 / 1024.0) * (sector_size as f64)) as usize,
        second_piece_bytes: ((1016.0 / 1024.0) * (sector_size as f64)) as usize,
        third_piece_bytes: ((508.0 / 1024.0) * (sector_size as f64)) as usize,

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
    let seal_seed = [3u8; 32];

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
    )
    .unwrap();

    // verify that we have neither sealed nor staged sectors yet
    {
        let sealed_sectors = get_sealed_sectors(&mut ctx, a_ptr, false).unwrap();
        let staged_sectors = get_staged_sectors(&mut ctx, a_ptr).unwrap();
        assert_eq!(0, sealed_sectors.len());
        assert_eq!(0, staged_sectors.len());
    }

    // add first piece, which lazily provisions a new staged sector
    {
        let MakePiece { file, bytes, key } = make_piece(cfg.first_piece_bytes);
        assert_eq!(
            124,
            add_piece(&mut ctx, a_ptr, &key, file.as_file(), bytes.len(), 5000000).unwrap()
        );
    }

    // wait for the staged sector's sealing state to be updated
    poll_for_sector_sealing_status(
        a_ptr,
        124,
        sector_builder_ffi_FFISealStatus_AcceptingPieces,
        cfg.max_secs_to_seal_sector * 2,
    );

    // add piece, which won't fit in to 124 but will provision a new sector and
    // completely fill it
    let MakePiece {
        file: mut third_piece_file,
        bytes: third_piece_bytes,
        key: third_piece_key,
    } = make_piece(cfg.second_piece_bytes);
    assert_eq!(
        125,
        add_piece(
            &mut ctx,
            a_ptr,
            &third_piece_key,
            third_piece_file.as_file(),
            third_piece_bytes.len(),
            5000000
        )
        .unwrap()
    );

    // this sector will have its remaining space reduced to zero
    poll_for_sector_sealing_status(
        a_ptr,
        125,
        sector_builder_ffi_FFISealStatus_FullyPacked,
        cfg.max_secs_to_seal_sector * 2,
    );

    // add final piece, which (due to alignment) fills the remaining space in
    // 124
    {
        let MakePiece { file, bytes, key } = make_piece(cfg.third_piece_bytes);
        assert_eq!(
            124,
            add_piece(&mut ctx, a_ptr, &key, file.as_file(), bytes.len(), 5000000).unwrap()
        );
    }

    // wait for updated status
    poll_for_sector_sealing_status(
        a_ptr,
        124,
        sector_builder_ffi_FFISealStatus_FullyPacked,
        cfg.max_secs_to_seal_sector * 2,
    );

    // get staged sector metadata and verify that we've now got two staged
    // sectors
    {
        let staged_sectors = get_staged_sectors(&mut ctx, a_ptr).unwrap();
        assert_eq!(2, staged_sectors.len());
    }

    seal_pre_commit_nonblocking(
        a_ptr,
        124,
        sector_builder_ffi_FFISealTicket {
            block_height: 10,
            ticket_bytes: seal_ticket,
        },
    );

    seal_pre_commit_nonblocking(
        a_ptr,
        125,
        sector_builder_ffi_FFISealTicket {
            block_height: 10,
            ticket_bytes: seal_ticket,
        },
    );

    // block until both sectors have been pre-committed - note that we won't know which
    // of the two sectors will seal first
    poll_for_sector_sealing_status(
        a_ptr,
        124,
        sector_builder_ffi_FFISealStatus_PreCommitted,
        cfg.max_secs_to_seal_sector * 2,
    );

    poll_for_sector_sealing_status(
        a_ptr,
        125,
        sector_builder_ffi_FFISealStatus_PreCommitted,
        cfg.max_secs_to_seal_sector * 2,
    );

    seal_commit_nonblocking(
        a_ptr,
        124,
        sector_builder_ffi_FFISealSeed {
            block_height: 100,
            ticket_bytes: seal_seed,
        },
    );

    seal_commit_nonblocking(
        a_ptr,
        125,
        sector_builder_ffi_FFISealSeed {
            block_height: 100,
            ticket_bytes: seal_seed,
        },
    );

    // block until both sectors have been committed
    poll_for_sector_sealing_status(
        a_ptr,
        124,
        sector_builder_ffi_FFISealStatus_Committed,
        cfg.max_secs_to_seal_sector * 2,
    );

    poll_for_sector_sealing_status(
        a_ptr,
        125,
        sector_builder_ffi_FFISealStatus_Committed,
        cfg.max_secs_to_seal_sector * 2,
    );

    // verify that we now have some sealed sectors
    {
        let sealed_sectors = get_sealed_sectors(&mut ctx, a_ptr, false).unwrap();
        let staged_sectors = get_staged_sectors(&mut ctx, a_ptr).unwrap();
        assert_eq!(2, sealed_sectors.len(), "expected two sealed sectors");
        assert_eq!(
            0,
            staged_sectors.len(),
            "expected zero staged sectors (they're all sealed)"
        );
    }

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
        .unwrap()
    };
    defer!(sector_builder_ffi_destroy_sector_builder(b_ptr));

    // after sealing, read the bytes (triggering unseal) and compare with what
    // we've added to the sector
    {
        let unsealed_bytes =
            read_piece_from_sealed_sector(&mut ctx, b_ptr, &third_piece_key).unwrap();
        assert_eq!(
            format!("{:x?}", third_piece_bytes),
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
                seal_seed,
                slice::from_raw_parts(sealed_sector.proofs_ptr, sealed_sector.proofs_len),
                sealed_sector.comm_r,
                sealed_sector.comm_d,
                prover_id,
            )
            .unwrap(),
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
                seal_seed,
                slice::from_raw_parts(sealed_sector.proofs_ptr, sealed_sector.proofs_len),
                sealed_sector.comm_r,
                sealed_sector.comm_d,
                prover_id,
            )
            .unwrap(),
            "seal verification failed for sector with id 125"
        );
    }

    // storage client and miner should generate identical CommP for the same
    // piece
    {
        third_piece_file
            .as_file_mut()
            .seek(SeekFrom::Start(0))
            .expect("failed to seek to the start");

        assert_eq!(
            format!("{:x?}", get_sealed_piece(&mut ctx, b_ptr, 125, &third_piece_key).comm_p),
            format!(
                "{:x?}",
                generate_piece_commitment(&mut ctx, third_piece_file.as_file_mut(), third_piece_bytes.len()).unwrap()
            ),
            "client (generate_piece_commitment) and server (during seal) generated different piece commitments"
        );
    }

    // get sealed sectors w/health checks
    {
        assert_eq!(2, get_sealed_sectors(&mut ctx, b_ptr, true).unwrap().len());

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

    // generate and then verify a proof-of-spacetime for the sealed sector
    {
        let cseed = [1u8; 32];
        let p_set = ProvingSet::new(get_sector_info(&mut ctx, b_ptr));

        let candidates = generate_candidates(b_ptr, cseed, &p_set).unwrap();

        let winners: Vec<sector_builder_ffi_FFIWinner> = candidates
            .into_iter()
            .map(|c| sector_builder_ffi_FFIWinner {
                sector_id: c.sector_id,
                partial_ticket: c.partial_ticket,
                ticket: c.ticket,
                sector_challenge_index: c.sector_challenge_index,
            })
            .collect();

        let proofs = generate_post(b_ptr, cseed, &p_set, &winners).unwrap();

        assert!(
            verify_post(
                cfg.sector_class.sector_size,
                cseed,
                &p_set,
                &proofs,
                &winners,
                &prover_id
            )
            .unwrap(),
            "PoSt was invalid"
        );
    }

    Ok(())
}
