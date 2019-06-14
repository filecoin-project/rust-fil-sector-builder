use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/");

    let out_path = env::var("OUT_DIR").unwrap();
    let mfs_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let hdr_path = "include/sector_builder_ffi.h";

    cbindgen::generate(mfs_path.clone())
        .expect("Could not generate header")
        .write_to_file(hdr_path);

    let b = bindgen::builder()
        .header(PathBuf::from(mfs_path).join(hdr_path).to_string_lossy())
        // Here, we tell Rust to link libsector_builder_ffi so that
        // auto-generated symbols are linked to symbols in the compiled cdylib.
        // For reasons unbeknown to me, the link attribute needs to precede an
        // extern block.
        .raw_line("#[link(name = \"sector_builder_ffi\")]\nextern \"C\" {}")
        .generate();

    match b {
        Ok(res) => {
            res.write_to_file(PathBuf::from(out_path).join("libsector_builder_ffi.rs"))
                .expect("could not write file");
        }
        Err(err) => {
            eprintln!("unable to generate bindings: {:?}", err);
            std::process::exit(1);
        }
    }
}
