use failure;

pub type Result<T> = ::std::result::Result<T, SectorBuilderErr>;

use serde_cbor;
use std::fmt::Display;

#[derive(Debug, Fail)]
pub enum SectorBuilderErr {
    #[fail(
        display = "number of bytes in piece ({}) exceeds maximum ({})",
        num_bytes_in_piece, max_bytes_per_sector
    )]
    OverflowError {
        num_bytes_in_piece: u64,
        max_bytes_per_sector: u64,
    },

    #[fail(
        display = "number of bytes written ({}) does not match bytes in piece ({})",
        num_bytes_written, num_bytes_in_piece
    )]
    IncompleteWriteError {
        num_bytes_written: u64,
        num_bytes_in_piece: u64,
    },

    #[fail(display = "no piece with key {} found", _0)]
    PieceNotFound(String),

    #[fail(display = "unrecoverable error: {}", _0)]
    Unrecoverable(String, failure::Backtrace),

    #[fail(display = "{}", _0)]
    Generic(String),

    #[fail(display = "sector manager error: {}", _0)]
    SectorManager(#[fail(cause)] SectorManagerErr),

    #[fail(display = "filecoin_proofs error: {}", _0)]
    FilecoinProofs(#[fail(cause)] failure::Error),
}

pub fn err_piecenotfound(piece_key: String) -> SectorBuilderErr {
    SectorBuilderErr::PieceNotFound(piece_key)
}

pub fn err_unrecov<S: Display>(msg: S) -> SectorBuilderErr {
    let backtrace = failure::Backtrace::new();
    SectorBuilderErr::Unrecoverable(format!("{}", msg), backtrace)
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

pub fn err_generic(message: String) -> SectorBuilderErr {
    SectorBuilderErr::Generic(message)
}

pub fn err_filecoin_proofs(error: failure::Error) -> SectorBuilderErr {
    SectorBuilderErr::FilecoinProofs(error)
}

#[derive(Debug, Fail)]
pub enum SectorManagerErr {
    #[fail(display = "unclassified error: {}", _0)]
    UnclassifiedError(String),

    #[fail(display = "caller error: {}", _0)]
    CallerError(String),

    #[fail(display = "receiver error: {}", _0)]
    ReceiverError(String),
}

impl From<SectorManagerErr> for SectorBuilderErr {
    fn from(error: SectorManagerErr) -> Self {
        SectorBuilderErr::SectorManager(error)
    }
}

impl From<serde_cbor::error::Error> for SectorBuilderErr {
    fn from(error: serde_cbor::error::Error) -> Self {
        SectorBuilderErr::Generic(format!("serde_cbor error: {}", error))
    }
}

impl From<std::io::Error> for SectorBuilderErr {
    fn from(error: std::io::Error) -> Self {
        SectorBuilderErr::Generic(format!("std io error: {}", error))
    }
}

impl From<sled::Error> for SectorBuilderErr {
    fn from(error: sled::Error) -> Self {
        SectorBuilderErr::Generic(format!("sled error: {}", error))
    }
}
