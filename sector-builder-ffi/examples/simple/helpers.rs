use std::io::Write;

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
    let _ = file.write_all(&bytes);

    MakePiece { file, bytes, key }
}
