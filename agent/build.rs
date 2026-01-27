//! # Build Script for Aegis Agent
//!
//! This script is responsible for the build-time generation of the eBPF skeleton.
//! It uses `libbpf-cargo` to:
//! 1. Compile the C-based BPF program (`src/bpf/aegis.bpf.c`).
//! 2. Generate the Rust skeleton bindings (`src/bpf/aegis.skel.rs`).
//!
//! This allows the main Rust binary to include the BPF bytecode directly and
//! interact with it using safe Rust types.

use std::{env, ffi::OsStr, path::PathBuf};

use libbpf_cargo::SkeletonBuilder;

/// Path to the source C file containing the eBPF program logic.
const SRC: &str = "src/bpf/aegis.bpf.c";

fn main() {
    // Determine the output path for the generated skeleton file.
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("aegis.skel.rs");

    // Use libbpf-cargo to compile the source and generate the Rust skeleton.
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([OsStr::new("-I"), OsStr::new("src/bpf")])
        .build_and_generate(&out)
        .unwrap();

    // Compile protobuf definitions for gRPC
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["../proto/session.proto"], &["../proto"])
        .expect("Failed to compile protobuf definitions. Ensure protoc is installed and session.proto is valid.");

    println!("cargo:rerun-if-changed=../proto/session.proto");
}
