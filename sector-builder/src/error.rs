#[derive(Debug, thiserror::Error)]
pub enum SectorBuilderErr {
    #[error(
        "number of bytes in piece ({}) exceeds maximum ({})",
        num_bytes_in_piece,
        max_bytes_per_sector
    )]
    OverflowError {
        num_bytes_in_piece: u64,
        max_bytes_per_sector: u64,
    },

    #[error(
        "number of bytes written ({}) does not match bytes in piece ({})",
        num_bytes_written,
        num_bytes_in_piece
    )]
    IncompleteWriteError {
        num_bytes_written: u64,
        num_bytes_in_piece: u64,
    },

    #[error("no piece with key {} found", _0)]
    PieceNotFound(String),

    #[error("unrecoverable error: {}", _0)]
    Unrecoverable(String),
}

pub fn err_piecenotfound(piece_key: String) -> SectorBuilderErr {
    SectorBuilderErr::PieceNotFound(piece_key)
}

pub fn err_unrecov(msg: String) -> SectorBuilderErr {
    SectorBuilderErr::Unrecoverable(msg)
}

pub fn err_overflow(num_bytes_in_piece: u64, max_bytes_per_sector: u64) -> SectorBuilderErr {
    SectorBuilderErr::OverflowError {
        num_bytes_in_piece,
        max_bytes_per_sector,
    }
}

pub fn err_inc_write(num_bytes_written: u64, num_bytes_in_piece: u64) -> SectorBuilderErr {
    SectorBuilderErr::IncompleteWriteError {
        num_bytes_written,
        num_bytes_in_piece,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SectorManagerErr {
    #[error("unclassified error: {}", _0)]
    UnclassifiedError(String),

    #[error("caller error: {}", _0)]
    CallerError(String),

    #[error("receiver error: {}", _0)]
    ReceiverError(String),
}
