use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/gpuprobe.bpf.c";

fn main() {
    let skel_out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("gpuprobe.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&skel_out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
