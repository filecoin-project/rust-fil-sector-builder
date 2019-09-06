#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(dead_code)]

#[macro_use(defer)]
extern crate scopeguard;

use std::io::Write;
use std::slice;
use std::{env, fs};

use ffi_toolkit::c_str_to_pbuf;
use filecoin_proofs::constants::{LIVE_SECTOR_SIZE, TEST_SECTOR_SIZE};
use tempfile::NamedTempFile;

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

struct TestConfiguration {
    first_piece_bytes: usize,
    max_bytes: u64,
    second_piece_bytes: usize,
    sector_class: sector_builder_ffi_FFISectorClass,
    third_piece_bytes: usize,
    fourth_piece_bytes: usize,
    max_num_staged_sectors: u8,
    estimated_secs_to_seal_sector: u64,
}

fn main() {
    let cfg = if env::var("TEST_LIVE_SEAL").is_ok() {
        TestConfiguration {
            sector_class: sector_builder_ffi_FFISectorClass {
                sector_size: LIVE_SECTOR_SIZE,
                porep_proof_partitions: 2,
            },
            max_bytes: 1016 * 1024 * 256,
            first_piece_bytes: 400 * 1024 * 256,
            second_piece_bytes: 200 * 1024 * 256,
            third_piece_bytes: 500 * 1024 * 256,
            fourth_piece_bytes: 200 * 1024 * 256,
            max_num_staged_sectors: 2,
            estimated_secs_to_seal_sector: 60 * 120,
        }
    } else {
        TestConfiguration {
            sector_class: sector_builder_ffi_FFISectorClass {
                sector_size: TEST_SECTOR_SIZE,
                porep_proof_partitions: 2,
            },
            max_bytes: 1016,
            first_piece_bytes: 400,
            second_piece_bytes: 200,
            third_piece_bytes: 500,
            fourth_piece_bytes: 200,
            max_num_staged_sectors: 2,
            estimated_secs_to_seal_sector: 60 * 5,
        }
    };

    unsafe { sector_builder_lifecycle(cfg).unwrap() };
}

unsafe fn sector_builder_lifecycle(cfg: TestConfiguration) -> Result<(), failure::Error> {
    let metadata_dir_a = tempfile::tempdir()?;
    let metadata_dir_b = tempfile::tempdir()?;
    let staging_dir_a = tempfile::tempdir()?;
    let staging_dir_b = tempfile::tempdir()?;
    let sealed_dir_a = tempfile::tempdir()?;
    let sealed_dir_b = tempfile::tempdir()?;

    let prover_id = [1u8; 31];

    let mut ctx: Deallocator = Default::default();

    let a_ptr = init_sector_builder(
        &mut ctx,
        &metadata_dir_a,
        &staging_dir_a,
        &sealed_dir_a,
        prover_id,
        123,
        cfg.sector_class,
        cfg.max_num_staged_sectors,
    );

    let max_bytes = get_max_user_bytes_per_staged_sector(cfg.sector_class.sector_size);

    // TODO: Replace the hard-coded byte amounts with values computed
    // from whatever was retrieved from the SectorBuilder.
    if max_bytes != cfg.max_bytes {
        panic!(
            "test assumes the wrong number of bytes (expected: {}, actual: {})",
            cfg.max_bytes, max_bytes
        );
    }

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
            add_piece(&mut ctx, a_ptr, &key, file.path(), bytes.len(), 5000000)
        );
    }

    // add second piece, which fits into existing staged sector
    {
        let MakePiece { file, bytes, key } = make_piece(cfg.second_piece_bytes);
        assert_eq!(
            124,
            add_piece(&mut ctx, a_ptr, &key, file.path(), bytes.len(), 5000000)
        );
    }

    // add third piece, which won't fit into existing staging sector
    {
        let MakePiece { file, bytes, key } = make_piece(cfg.third_piece_bytes);
        assert_eq!(
            125,
            add_piece(&mut ctx, a_ptr, &key, file.path(), bytes.len(), 5000000)
        );
    }

    // get staged sector metadata and verify that we've now got two staged
    // sectors
    {
        let staged_sectors = get_staged_sectors(&mut ctx, a_ptr);
        assert_eq!(2, staged_sectors.len());
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
            prover_id,
            123,
            cfg.sector_class,
            cfg.max_num_staged_sectors,
        )
    };
    defer!(sector_builder_ffi_destroy_sector_builder(b_ptr));

    // add fourth piece, which triggers sealing of the first sector
    let MakePiece {
        file: fourth_piece_file,
        bytes: fourth_piece_bytes,
        key: fourth_piece_key,
    } = make_piece(cfg.fourth_piece_bytes);
    assert_eq!(
        124,
        add_piece(
            &mut ctx,
            b_ptr,
            &fourth_piece_key,
            fourth_piece_file.path(),
            fourth_piece_bytes.len(),
            5000000
        )
    );

    // block until the sector has been sealed
    poll_for_sector_sealing_status(
        b_ptr,
        124,
        sector_builder_ffi_FFISealStatus_Sealed,
        cfg.estimated_secs_to_seal_sector,
    );

    // after sealing, read the bytes (triggering unseal) and compare with what
    // we've added to the sector
    {
        let unsealed_bytes = read_piece_from_sealed_sector(&mut ctx, b_ptr, &fourth_piece_key);
        assert_eq!(
            format!("{:x?}", fourth_piece_bytes),
            format!("{:x?}", unsealed_bytes)
        );
    }

    // get sealed sector and verify the proof
    {
        let sealed_sector = get_sealed_sector(&mut ctx, b_ptr, 124);

        assert!(
            verify_seal(
                &mut ctx,
                cfg.sector_class.sector_size,
                sealed_sector.sector_id,
                slice::from_raw_parts(sealed_sector.proofs_ptr, sealed_sector.proofs_len),
                sealed_sector.comm_r,
                sealed_sector.comm_d,
                sealed_sector.comm_r_star,
                prover_id,
            ),
            "seal verification failed"
        );
    }

    // storage client and miner should generate identical CommP for the same
    // piece
    {
        let mut file = NamedTempFile::new().expect("could not create named temp file");
        let _ = file.write_all(&fourth_piece_bytes);

        assert_eq!(
            format!("{:x?}", get_sealed_piece(&mut ctx, b_ptr, 124, &fourth_piece_key).comm_p),
            format!(
                "{:x?}",
                generate_piece_commitment(&mut ctx, fourth_piece_file.path(), fourth_piece_bytes.len())
            ),
            "client (generate_piece_commitment) and server (during seal) generated different piece commitments"
        );
    }

    // get sealed sectors w/health checks
    {
        assert_eq!(1, get_sealed_sectors(&mut ctx, b_ptr, true).len());

        assert_eq!(
            get_sealed_sector(&mut ctx, b_ptr, 124).health,
            sector_builder_ffi_FFISealedSectorHealth_Ok
        );

        let sealed_sector_path = sealed_dir_b.path().join(c_str_to_pbuf(
            get_sealed_sector(&mut ctx, b_ptr, 124).sector_access,
        ));

        let content = std::fs::read(&sealed_sector_path).expect("failed to read sector data");

        // change 1 byte
        let mut new_content = content.clone();
        new_content[0] = new_content[0].wrapping_add(1);

        // write back
        std::fs::write(&sealed_sector_path, &new_content).expect("failed to write fake sector");

        // invalid checksum
        assert_eq!(
            get_sealed_sector(&mut ctx, b_ptr, 124).health,
            sector_builder_ffi_FFISealedSectorHealth_ErrorInvalidChecksum
        );

        // restore
        std::fs::write(&sealed_sector_path, &content).expect("failed to restore sector");

        // checksum is now valid
        assert_eq!(
            get_sealed_sector(&mut ctx, b_ptr, 124).health,
            sector_builder_ffi_FFISealedSectorHealth_Ok
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
