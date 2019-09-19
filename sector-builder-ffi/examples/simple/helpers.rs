use std::io::Write;
use std::io::{Seek, SeekFrom};

use rand::{thread_rng, Rng};
use tempfile::NamedTempFile;

pub(crate) struct MakePiece {
    pub file: NamedTempFile,
    pub bytes: Vec<u8>,
    pub key: String,
}

pub(crate) fn make_piece(num_bytes_in_piece: usize) -> MakePiece {
    let mut rng = thread_rng();
    let bytes: Vec<u8> = (0..num_bytes_in_piece).map(|_| rng.gen()).collect();
    let key = (0..16)
        .map(|_| (0x20u8 + (rand::random::<f32>() * 96.0) as u8) as char)
        .collect();

    // write piece bytes to a temporary file
    let mut file = NamedTempFile::new().expect("could not create named temp file");
    file.write_all(&bytes).expect("failed to write piece");
    file.as_file().sync_all().unwrap();

    assert_eq!(
        file.as_file().metadata().unwrap().len(),
        num_bytes_in_piece as u64
    );

    // make sure we are set to 0 on the file
    file.as_file_mut().seek(SeekFrom::Start(0)).unwrap();

    MakePiece { file, bytes, key }
}
