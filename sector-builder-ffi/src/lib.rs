#![deny(clippy::all, clippy::perf, clippy::correctness)]

// These need to be here because of cbindgen: https://github.com/eqrion/cbindgen/issues/292
extern crate filecoin_proofs;
extern crate filecoin_proofs_ffi;
extern crate sector_builder;

#[macro_use]
extern crate log;

mod responses;

pub mod api;
