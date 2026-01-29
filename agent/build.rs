//! # Build Script
//!
//! Compiles eBPF program and generates Rust bindings at build time:
//! 1. Compiles C eBPF code to BPF bytecode
//! 2. Generates Rust skeleton for safe interaction
//! 3. Compiles protobuf definitions for gRPC

use std::{env, ffi::OsStr, path::PathBuf};

use libbpf_cargo::SkeletonBuilder;

const BPF_SOURCE: &str = "src/bpf/aegis.bpf.c";

fn main() {
    // Generate BPF skeleton
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set in build environment"),
    )
    .join("src")
    .join("bpf")
    .join("aegis.skel.rs");

    SkeletonBuilder::new()
        .source(BPF_SOURCE)
        .clang_args([OsStr::new("-I"), OsStr::new("src/bpf")])
        .build_and_generate(&out)
        .expect("Failed to build BPF skeleton");

    // Generate gRPC service code from protobuf
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["../proto/session.proto"], &["../proto"])
        .expect("Failed to compile protobuf. Ensure protoc is installed.");

    println!("cargo:rerun-if-changed=../proto/session.proto");
    println!("cargo:rerun-if-changed={}", BPF_SOURCE);
}
