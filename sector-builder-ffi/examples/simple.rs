#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[macro_use(defer)]
extern crate scopeguard;

include!(concat!(env!("OUT_DIR"), "/libsector_builder_ffi.rs"));

use std::error::Error;
use std::io::Write;
use std::ptr;
use std::slice::from_raw_parts;
use std::sync::atomic::AtomicPtr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::{env, fs};

use byteorder::{LittleEndian, WriteBytesExt};
use ffi_toolkit::{c_str_to_rust_str, free_c_str, rust_str_to_c_str};
use filecoin_proofs::constants::{LIVE_SECTOR_SIZE, TEST_SECTOR_SIZE};
use filecoin_proofs::error::ExpectWithBacktrace;
use rand::{thread_rng, Rng};
use tempfile::{NamedTempFile, TempDir};

///////////////////////////////////////////////////////////////////////////////
// SectorBuilder lifecycle test
///////////////////////////////

fn u64_to_fr_safe(sector_id: u64) -> [u8; 31] {
    let mut byte_vector = vec![];
    byte_vector.write_u64::<LittleEndian>(sector_id).unwrap();
    byte_vector.resize(31, 0);

    let mut byte_array = [0; 31];
    let bytes = &byte_vector[..byte_array.len()]; // panics if not enough data
    byte_array.copy_from_slice(bytes);

    byte_array
}

fn make_piece(num_bytes_in_piece: usize) -> (String, Vec<u8>) {
    let mut rng = thread_rng();
    let bytes = (0..num_bytes_in_piece).map(|_| rng.gen()).collect();
    let key = (0..16)
        .map(|_| (0x20u8 + (rand::random::<f32>() * 96.0) as u8) as char)
        .collect();
    (key, bytes)
}

unsafe fn create_and_add_piece(
    sector_builder: *mut sector_builder_ffi_SectorBuilder,
    num_bytes_in_piece: usize,
) -> (Vec<u8>, String, *mut sector_builder_ffi_AddPieceResponse) {
    let (piece_key, piece_bytes) = make_piece(num_bytes_in_piece);

    let c_piece_key = rust_str_to_c_str(piece_key.clone());
    defer!(free_c_str(c_piece_key));

    // write piece bytes to a temporary file
    let mut file = NamedTempFile::new().expects("could not create named temp file");
    let p = file.path().to_string_lossy().to_string();
    let _ = file.write_all(&piece_bytes);
    let c_piece_path = rust_str_to_c_str(p);
    defer!(free_c_str(c_piece_path));

    (
        piece_bytes.clone(),
        piece_key.clone(),
        sector_builder_ffi_add_piece(
            sector_builder,
            c_piece_key,
            piece_bytes.len() as u64,
            c_piece_path,
            5000000000,
        ),
    )
}

unsafe fn create_sector_builder(
    metadata_dir: &TempDir,
    staging_dir: &TempDir,
    sealed_dir: &TempDir,
    prover_id: [u8; 31],
    last_committed_sector_id: u64,
    sector_class: sector_builder_ffi_FFISectorClass,
) -> (*mut sector_builder_ffi_SectorBuilder, usize) {
    let mut prover_id: [u8; 31] = prover_id;

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
        &mut prover_id,
        c_sealed_dir,
        c_staging_dir,
        2,
    );
    defer!(sector_builder_ffi_destroy_init_sector_builder_response(
        resp
    ));

    if (*resp).status_code != 0 {
        panic!("{}", c_str_to_rust_str((*resp).error_msg))
    }

    (
        (*resp).sector_builder,
        sector_builder_ffi_get_max_user_bytes_per_staged_sector(sector_class.sector_size) as usize,
    )
}

struct ConfigurableSizes {
    first_piece_bytes: usize,
    max_bytes: usize,
    second_piece_bytes: usize,
    sector_class: sector_builder_ffi_FFISectorClass,
    third_piece_bytes: usize,
    fourth_piece_bytes: usize,
}

unsafe fn sector_builder_lifecycle(use_live_store: bool) -> Result<(), Box<Error>> {
    let metadata_dir_a = tempfile::tempdir().unwrap();
    let metadata_dir_b = tempfile::tempdir().unwrap();
    let staging_dir_a = tempfile::tempdir().unwrap();
    let staging_dir_b = tempfile::tempdir().unwrap();
    let sealed_dir_a = tempfile::tempdir().unwrap();
    let sealed_dir_b = tempfile::tempdir().unwrap();

    let sizes = if use_live_store {
        ConfigurableSizes {
            sector_class: sector_builder_ffi_FFISectorClass {
                sector_size: LIVE_SECTOR_SIZE,
                porep_proof_partitions: 2,
                post_proof_partitions: 1,
            },
            max_bytes: 1016 * 1024 * 256,
            first_piece_bytes: 400 * 1024 * 256,
            second_piece_bytes: 200 * 1024 * 256,
            third_piece_bytes: 500 * 1024 * 256,
            fourth_piece_bytes: 200 * 1024 * 256,
        }
    } else {
        ConfigurableSizes {
            sector_class: sector_builder_ffi_FFISectorClass {
                sector_size: TEST_SECTOR_SIZE,
                porep_proof_partitions: 2,
                post_proof_partitions: 1,
            },
            max_bytes: 1016,
            first_piece_bytes: 400,
            second_piece_bytes: 200,
            third_piece_bytes: 500,
            fourth_piece_bytes: 200,
        }
    };

    let (sector_builder_a, max_bytes) = create_sector_builder(
        &metadata_dir_a,
        &staging_dir_a,
        &sealed_dir_a,
        u64_to_fr_safe(0),
        123,
        sizes.sector_class,
    );

    // TODO: Replace the hard-coded byte amounts with values computed
    // from whatever was retrieved from the SectorBuilder.
    if max_bytes != sizes.max_bytes {
        panic!(
            "test assumes the wrong number of bytes (expected: {}, actual: {})",
            sizes.max_bytes, max_bytes
        );
    }

    // verify that we have neither sealed nor staged sectors yet
    {
        let resp = sector_builder_ffi_get_sealed_sectors(sector_builder_a);
        defer!(sector_builder_ffi_destroy_get_sealed_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(0, (*resp).sectors_len);

        let resp = sector_builder_ffi_get_staged_sectors(sector_builder_a);
        defer!(sector_builder_ffi_destroy_get_staged_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(0, (*resp).sectors_len);
    }

    // add first piece, which lazily provisions a new staged sector
    {
        let (_, _, resp) = create_and_add_piece(sector_builder_a, sizes.first_piece_bytes);
        defer!(sector_builder_ffi_destroy_add_piece_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(124, (*resp).sector_id);
    }

    // add second piece, which fits into existing staged sector
    {
        let (_, _, resp) = create_and_add_piece(sector_builder_a, sizes.second_piece_bytes);
        defer!(sector_builder_ffi_destroy_add_piece_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(124, (*resp).sector_id);
    }

    // add third piece, which won't fit into existing staging sector
    {
        let (_, _, resp) = create_and_add_piece(sector_builder_a, sizes.third_piece_bytes);
        defer!(sector_builder_ffi_destroy_add_piece_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        // note that the sector id changed here
        assert_eq!(125, (*resp).sector_id);
    }

    // get staged sector metadata and verify that we've now got two staged
    // sectors
    {
        let resp = sector_builder_ffi_get_staged_sectors(sector_builder_a);
        defer!(sector_builder_ffi_destroy_get_staged_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(2, (*resp).sectors_len);
    }

    // drop the first sector builder, relinquishing any locks on persistence
    sector_builder_ffi_destroy_sector_builder(sector_builder_a);

    // migrate staged sectors, sealed sectors, and sector builder metadata to
    // new directory (overwrites destination directory)
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
    let (sector_builder_b, _) = create_sector_builder(
        &metadata_dir_b,
        &staging_dir_b,
        &sealed_dir_b,
        u64_to_fr_safe(0),
        123,
        sizes.sector_class,
    );
    defer!(sector_builder_ffi_destroy_sector_builder(sector_builder_b));

    // add fourth piece that will trigger sealing in the first sector
    let (bytes_in, piece_key) = {
        let (piece_bytes, piece_key, resp) =
            create_and_add_piece(sector_builder_b, sizes.fourth_piece_bytes);
        defer!(sector_builder_ffi_destroy_add_piece_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        // sector id changed again (piece wouldn't fit)
        assert_eq!(124, (*resp).sector_id);

        (piece_bytes, piece_key)
    };

    // poll for sealed sector metadata through the FFI
    {
        let (result_tx, result_rx) = mpsc::channel();
        let (kill_tx, kill_rx) = mpsc::channel();

        let atomic_ptr = AtomicPtr::new(sector_builder_b);

        let _join_handle = thread::spawn(move || {
            let sector_builder = atomic_ptr.into_inner();

            loop {
                match kill_rx.try_recv() {
                    Ok(_) => return,
                    _ => (),
                };

                let resp = sector_builder_ffi_get_seal_status(sector_builder, 124);
                defer!(sector_builder_ffi_destroy_get_seal_status_response(resp));

                if (*resp).status_code != 0 {
                    return;
                }

                if (*resp).seal_status_code == sector_builder_ffi_FFISealStatus_Sealed {
                    let _ = result_tx.send((*resp).sector_id).unwrap();
                }

                thread::sleep(Duration::from_millis(1000));
            }
        });

        defer!({
            let _ = kill_tx.send(true).unwrap();
        });

        // wait up to 5 minutes for sealing to complete
        let now_sealed_sector_id = if use_live_store {
            result_rx.recv().unwrap()
        } else {
            result_rx.recv_timeout(Duration::from_secs(300)).unwrap()
        };

        assert_eq!(now_sealed_sector_id, 124);
    }

    // get sealed sector and verify the PoRep proof
    {
        let resp = sector_builder_ffi_get_seal_status(sector_builder_b, 124);

        {
            let resp2 = sector_builder_ffi_verify_seal(
                sizes.sector_class.sector_size,
                &mut (*resp).comm_r,
                &mut (*resp).comm_d,
                &mut (*resp).comm_r_star,
                &mut u64_to_fr_safe(0),
                &mut u64_to_fr_safe(124),
                (*resp).proof_ptr,
                (*resp).proof_len,
            );
            defer!(sector_builder_ffi_destroy_verify_seal_response(resp2));

            if (*resp2).status_code != 0 {
                panic!("{}", c_str_to_rust_str((*resp2).error_msg))
            }

            assert!((*resp2).is_valid)
        }

        sector_builder_ffi_destroy_get_seal_status_response(resp);
    }

    // get sealed sectors - we should have just one
    {
        let resp = sector_builder_ffi_get_sealed_sectors(sector_builder_b);
        defer!(sector_builder_ffi_destroy_get_sealed_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(1, (*resp).sectors_len);
    }

    // verify pips
    {
        let resp = sector_builder_ffi_get_sealed_sectors(sector_builder_b);
        defer!(sector_builder_ffi_destroy_get_sealed_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!((*resp).sectors_len, 1);

        let sealed_sector_metadata: sector_builder_ffi_FFISealedSectorMetadata =
            from_raw_parts((*resp).sectors_ptr, (*resp).sectors_len)[0];

        let mut comm_d = sealed_sector_metadata.comm_d.clone();

        let pieces = from_raw_parts(
            sealed_sector_metadata.pieces_ptr,
            sealed_sector_metadata.pieces_len,
        );

        for piece in pieces {
            let mut comm_p = piece.comm_p.clone();

            let resp = sector_builder_ffi_verify_piece_inclusion_proof(
                &mut comm_d,
                &mut comm_p,
                piece.piece_inclusion_proof_ptr,
                piece.piece_inclusion_proof_len,
                piece.num_bytes,
                sizes.sector_class.sector_size,
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
        let resp = sector_builder_ffi_get_sealed_sectors(sector_builder_b);
        defer!(sector_builder_ffi_destroy_get_sealed_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        let sealed_sector_metadata: sector_builder_ffi_FFISealedSectorMetadata =
            from_raw_parts((*resp).sectors_ptr, (*resp).sectors_len)[0];
        let sealed_sector_replica_commitment: [u8; 32] = sealed_sector_metadata.comm_r;
        // FIXME: for some reason bindgen generates *mut instead of *const.
        let mut challenge_seed: [u8; 32] = [0; 32];

        let resp = sector_builder_ffi_generate_post(
            sector_builder_b,
            &sealed_sector_replica_commitment[0],
            32,
            &mut challenge_seed,
        );
        defer!(sector_builder_ffi_destroy_generate_post_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        let resp = sector_builder_ffi_verify_post(
            sizes.sector_class.sector_size,
            sizes.sector_class.post_proof_partitions,
            &sealed_sector_replica_commitment[0],
            32,
            &mut challenge_seed,
            (*resp).flattened_proofs_ptr,
            (*resp).flattened_proofs_len,
            (*resp).faults_ptr,
            (*resp).faults_len,
        );
        defer!(sector_builder_ffi_destroy_verify_post_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert!((*resp).is_valid)
    }

    // after sealing, read the bytes (causes unseal) and compare with what we
    // added to the sector
    {
        let c_piece_key = rust_str_to_c_str(piece_key.clone());
        defer!(free_c_str(c_piece_key));

        let resp = sector_builder_ffi_read_piece_from_sealed_sector(sector_builder_b, c_piece_key);
        defer!(sector_builder_ffi_destroy_read_piece_from_sealed_sector_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        let data_ptr = (*resp).data_ptr as *mut u8;
        let data_len = (*resp).data_len;
        let mut bytes_out = Vec::with_capacity(data_len);
        bytes_out.set_len(data_len);
        ptr::copy(data_ptr, bytes_out.as_mut_ptr(), data_len);

        assert_eq!(format!("{:x?}", bytes_in), format!("{:x?}", bytes_out));
    }

    // verify that the comm_p of the fourth piece generated by sealing matches
    // the comm_p generated directly with its bytes written to a piece file
    {
        let resp = sector_builder_ffi_get_sealed_sectors(sector_builder_b);
        defer!(sector_builder_ffi_destroy_get_sealed_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        let sealed_sector_metadata: sector_builder_ffi_FFISealedSectorMetadata =
            from_raw_parts((*resp).sectors_ptr, (*resp).sectors_len)[0];

        let pieces = from_raw_parts(
            sealed_sector_metadata.pieces_ptr,
            sealed_sector_metadata.pieces_len,
        );

        let piece = pieces
            .into_iter()
            .find(|&piece| {
                let pk = c_str_to_rust_str(piece.piece_key).to_string();
                &pk == &piece_key
            })
            .expects("could not find piece with matching key");

        let comm_p = piece.comm_p.clone();

        let mut file = NamedTempFile::new().expects("could not create named temp file");
        let p = file.path().to_string_lossy().to_string();
        let _ = file.write_all(&bytes_in);
        let c_piece_path = rust_str_to_c_str(p);
        defer!(free_c_str(c_piece_path));

        let resp = sector_builder_ffi_generate_piece_commitment(c_piece_path, piece.num_bytes);
        defer!(sector_builder_ffi_destroy_generate_piece_commitment_response(resp));

        assert_eq!(format!("{:x?}", comm_p), format!("{:x?}", (*resp).comm_p))
    }

    Ok(())
}

fn main() {
    // If TEST_LIVE_SEAL is set, use the Live configuration, and don't unseal
    // — so process running time will closely approximate sealing time.
    let use_live_store = match env::var("TEST_LIVE_SEAL") {
        Ok(_) => true,
        Err(_) => false,
    };

    unsafe { sector_builder_lifecycle(use_live_store).unwrap() };
}
