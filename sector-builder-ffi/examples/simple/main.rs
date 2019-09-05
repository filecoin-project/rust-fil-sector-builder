#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[macro_use(defer)]
extern crate scopeguard;

use std::error::Error;
use std::io::Write;
use std::ptr;
use std::slice;
use std::sync::atomic::AtomicPtr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::{env, fs};

use ffi_toolkit::{c_str_to_pbuf, c_str_to_rust_str, free_c_str, rust_str_to_c_str};
use filecoin_proofs::constants::{LIVE_SECTOR_SIZE, TEST_SECTOR_SIZE};
use filecoin_proofs::error::ExpectWithBacktrace;
use rand::{thread_rng, Rng};
use std::path::Path;
use tempfile::{NamedTempFile, TempDir};

include!(concat!(env!("OUT_DIR"), "/libsector_builder_ffi.rs"));

#[derive(Default)]
struct MemContext {
    destructors: Vec<Box<dyn Fn()>>,
}

impl Drop for MemContext {
    fn drop(&mut self) {
        for f in self.destructors.iter() {
            f();
        }
    }
}

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

/// miscellaneous utility functions
///

struct MakePiece {
    file: NamedTempFile,
    bytes: Vec<u8>,
    key: String,
}

fn make_piece(num_bytes_in_piece: usize) -> MakePiece {
    let mut rng = thread_rng();
    let bytes: Vec<u8> = (0..num_bytes_in_piece).map(|_| rng.gen()).collect();
    let key = (0..16)
        .map(|_| (0x20u8 + (rand::random::<f32>() * 96.0) as u8) as char)
        .collect();

    // write piece bytes to a temporary file
    let mut file = NamedTempFile::new().expects("could not create named temp file");
    let _ = file.write_all(&bytes);

    MakePiece { file, bytes, key }
}

/// wrappers for FFI calls
///

unsafe fn get_sealed_sectors(
    ctx: &mut MemContext,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    with_health: bool,
) -> Vec<sector_builder_ffi_FFISealedSectorMetadata> {
    let resp = sector_builder_ffi_get_sealed_sectors(ptr, with_health);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_get_sealed_sectors_response(resp);
    })));

    if (*resp).status_code != 0 {
        panic!("{}", c_str_to_rust_str((*resp).error_msg))
    }

    slice::from_raw_parts((*resp).sectors_ptr, (*resp).sectors_len).to_vec()
}

unsafe fn get_staged_sectors(
    ctx: &mut MemContext,
    ptr: *mut sector_builder_ffi_SectorBuilder,
) -> Vec<sector_builder_ffi_FFIStagedSectorMetadata> {
    let resp = sector_builder_ffi_get_staged_sectors(ptr);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_get_staged_sectors_response(resp);
    })));

    if (*resp).status_code != 0 {
        panic!("{}", c_str_to_rust_str((*resp).error_msg))
    }

    slice::from_raw_parts((*resp).sectors_ptr, (*resp).sectors_len).to_vec()
}

unsafe fn add_piece<T: AsRef<Path>>(
    ctx: &mut MemContext,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    piece_key: &str,
    piece_path: T,
    piece_len: usize,
    store_until_utc_secs: u64,
) -> u64 {
    let c_piece_key = rust_str_to_c_str(piece_key);
    defer!(free_c_str(c_piece_key));

    let c_piece_path = rust_str_to_c_str(piece_path.as_ref().to_str().unwrap());
    defer!(free_c_str(c_piece_path));

    let resp = sector_builder_ffi_add_piece(
        ptr,
        c_piece_key,
        piece_len as u64,
        c_piece_path,
        store_until_utc_secs,
    );
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_add_piece_response(resp);
    })));

    if (*resp).status_code != 0 {
        panic!("{}", c_str_to_rust_str((*resp).error_msg))
    }

    (*resp).sector_id.clone()
}

unsafe fn get_seal_status(
    ctx: &mut MemContext,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
) -> sector_builder_ffi_FFISealStatus {
    let resp = sector_builder_ffi_get_seal_status(ptr, sector_id);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_get_seal_status_response(resp);
    })));

    if (*resp).status_code != 0 {
        panic!("{}", c_str_to_rust_str((*resp).error_msg))
    }

    (*resp).seal_status_code.clone()
}

unsafe fn generate_piece_commitment<T: AsRef<Path>>(
    ctx: &mut MemContext,
    piece_path: T,
    piece_len: usize,
) -> [u8; 32] {
    let piece_path_as_c_str = rust_str_to_c_str(piece_path.as_ref().to_str().unwrap());
    defer!(free_c_str(piece_path_as_c_str));

    let resp = sector_builder_ffi_generate_piece_commitment(piece_path_as_c_str, piece_len as u64);
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_generate_piece_commitment_response(resp);
    })));

    (*resp).comm_p.clone()
}

unsafe fn verify_seal(
    ctx: &mut MemContext,
    sector_size: u64,
    sector_id: u64,
    proof: &[u8],
    comm_r: [u8; 32],
    comm_d: [u8; 32],
    comm_r_star: [u8; 32],
    prover_id: [u8; 31],
) -> bool {
    let resp = sector_builder_ffi_verify_seal(
        sector_size,
        &mut comm_r.clone(),
        &mut comm_d.clone(),
        &mut comm_r_star.clone(),
        &mut prover_id.clone(),
        sector_id,
        proof.as_ptr(),
        proof.len(),
    );
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_verify_seal_response(resp);
    })));

    if (*resp).status_code != 0 {
        panic!("{}", c_str_to_rust_str((*resp).error_msg))
    }

    (*resp).is_valid.clone()
}

/// compound operations
///

unsafe fn get_faulty_sector_ids(
    ctx: &mut MemContext,
    ptr: *mut sector_builder_ffi_SectorBuilder,
) -> Vec<u64> {
    get_sealed_sectors(ctx, ptr, true)
        .iter()
        .filter(|ss| ss.health != sector_builder_ffi_FFISealedSectorHealth_Ok)
        .map(|ss| ss.sector_id)
        .collect()
}

unsafe fn get_sealed_sector(
    ctx: &mut MemContext,
    ptr: *mut sector_builder_ffi_SectorBuilder,
    sector_id: u64,
) -> sector_builder_ffi_FFISealedSectorMetadata {
    let sealed_sector = get_sealed_sectors(ctx, ptr, true)
        .into_iter()
        .find(|ss| ss.sector_id == sector_id)
        .expect("no sealed sector with id 124");

    sealed_sector
}

unsafe fn get_sealed_piece(
    ctx: &mut MemContext,
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

unsafe fn get_max_user_bytes_per_staged_sector(sector_size: u64) -> u64 {
    sector_builder_ffi_get_max_user_bytes_per_staged_sector(sector_size)
}

unsafe fn destroy_sector_builder(mut p: *mut sector_builder_ffi_SectorBuilder) {
    sector_builder_ffi_destroy_sector_builder(p);
    p = ptr::null_mut();
    assert!(p.is_null());
}

unsafe fn poll_for_sector_sealing_status(
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

    assert_eq!(now_sealed_sector_id, 124);
}

unsafe fn init_sector_builder(
    ctx: &mut MemContext,
    metadata_dir: &TempDir,
    staging_dir: &TempDir,
    sealed_dir: &TempDir,
    prover_id: [u8; 31],
    last_committed_sector_id: u64,
    sector_class: sector_builder_ffi_FFISectorClass,
    max_num_staged_sectors: u8,
) -> *mut sector_builder_ffi_SectorBuilder {
    let c_metadata_dir = rust_str_to_c_str(metadata_dir.path().to_str().unwrap());
    let c_sealed_dir = rust_str_to_c_str(sealed_dir.path().to_str().unwrap());
    let c_staging_dir = rust_str_to_c_str(staging_dir.path().to_str().unwrap());

    defer!({
        free_c_str(c_metadata_dir);
        free_c_str(c_sealed_dir);
        free_c_str(c_staging_dir);
    });

    let resp = sector_builder_ffi_init_sector_builder(
        sector_class,
        last_committed_sector_id,
        c_metadata_dir,
        &mut prover_id.clone(),
        c_sealed_dir,
        c_staging_dir,
        max_num_staged_sectors,
    );
    defer!(ctx.destructors.push(Box::new(move || {
        sector_builder_ffi_destroy_init_sector_builder_response(resp);
    })));

    if (*resp).status_code != 0 {
        panic!("{}", c_str_to_rust_str((*resp).error_msg))
    }

    (*resp).sector_builder
}

/// lifecycle test

unsafe fn sector_builder_lifecycle(cfg: TestConfiguration) -> Result<(), Box<dyn Error>> {
    let metadata_dir_a = tempfile::tempdir().unwrap();
    let metadata_dir_b = tempfile::tempdir().unwrap();
    let staging_dir_a = tempfile::tempdir().unwrap();
    let staging_dir_b = tempfile::tempdir().unwrap();
    let sealed_dir_a = tempfile::tempdir().unwrap();
    let sealed_dir_b = tempfile::tempdir().unwrap();

    let prover_id = [1u8; 31];

    let mut ctx: MemContext = Default::default();

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

    // add fourth piece that will trigger sealing in the first sector
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

    // after sealing, read the bytes (causes unseal) and compare with what we
    // added to the sector
    {
        let c_piece_key = rust_str_to_c_str(fourth_piece_key.clone());
        defer!(free_c_str(c_piece_key));

        let resp = sector_builder_ffi_read_piece_from_sealed_sector(b_ptr, c_piece_key);
        defer!(sector_builder_ffi_destroy_read_piece_from_sealed_sector_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        let data_ptr = (*resp).data_ptr as *mut u8;
        let data_len = (*resp).data_len;
        let mut bytes_out = Vec::with_capacity(data_len);
        bytes_out.set_len(data_len);
        ptr::copy(data_ptr, bytes_out.as_mut_ptr(), data_len);

        assert_eq!(
            format!("{:x?}", fourth_piece_bytes),
            format!("{:x?}", bytes_out)
        );
    }

    // get sealed sector and verify the PoRep proof
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
        let mut file = NamedTempFile::new().expects("could not create named temp file");
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

    // verify pips
    {
        let sealed_sector = get_sealed_sector(&mut ctx, b_ptr, 124);

        let mut comm_d = sealed_sector.comm_d.clone();

        let pieces = slice::from_raw_parts(sealed_sector.pieces_ptr, sealed_sector.pieces_len);

        for piece in pieces {
            let mut comm_p = piece.comm_p.clone();

            let resp = sector_builder_ffi_verify_piece_inclusion_proof(
                &mut comm_d,
                &mut comm_p,
                piece.piece_inclusion_proof_ptr,
                piece.piece_inclusion_proof_len,
                piece.num_bytes,
                cfg.sector_class.sector_size,
            );
            defer!(sector_builder_ffi_destroy_verify_piece_inclusion_proof_response(resp));

            if (*resp).status_code != 0 {
                panic!("{}", c_str_to_rust_str((*resp).error_msg));
            }

            assert!((*resp).is_valid);
        }
    }

    // generate and then verify a proof-of-spacetime for the sealed sector
    {
        let comm_rs =
            get_sealed_sectors(&mut ctx, b_ptr, true)
                .iter()
                .fold(vec![], |mut acc, item| {
                    acc.append(&mut item.comm_r.to_vec());
                    acc
                });

        let faulty_sector_ids = get_faulty_sector_ids(&mut ctx, b_ptr);

        let mut challenge_seed = [1u8; 32];

        let resp = sector_builder_ffi_generate_post(
            b_ptr,
            comm_rs.as_ptr(),
            comm_rs.len(),
            &mut challenge_seed,
            faulty_sector_ids.as_ptr(),
            faulty_sector_ids.len(),
        );
        defer!(sector_builder_ffi_destroy_generate_post_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        let sector_ids: Vec<u64> = get_sealed_sectors(&mut ctx, b_ptr, true)
            .iter()
            .map(|ss| ss.sector_id)
            .collect();

        let resp = sector_builder_ffi_verify_post(
            cfg.sector_class.sector_size,
            &mut challenge_seed,
            sector_ids.as_ptr(),
            sector_ids.len(),
            faulty_sector_ids.as_ptr(),
            faulty_sector_ids.len(),
            comm_rs.as_ptr(),
            comm_rs.len(),
            (*resp).proof_ptr,
            (*resp).proof_len,
        );
        defer!(sector_builder_ffi_destroy_verify_post_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert!((*resp).is_valid)
    }

    Ok(())
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
