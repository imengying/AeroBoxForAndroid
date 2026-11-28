// AeroBox pure-Rust build: no compiler probes, C, or assembly build steps.
fn main() {
    for name in ["blake3_sse2_ffi", "blake3_sse2_rust", "blake3_sse41_ffi", "blake3_sse41_rust", "blake3_avx2_ffi", "blake3_avx2_rust", "blake3_avx512_ffi", "blake3_neon", "blake3_wasm32_simd"] {
        println!("cargo::rustc-check-cfg=cfg({name})");
    }
    assert!(std::env::var_os("CARGO_FEATURE_NEON").is_none(), "native NEON is disabled in AeroBox");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if arch == "x86" || arch == "x86_64" {
        for name in ["blake3_sse2_rust", "blake3_sse41_rust", "blake3_avx2_rust"] {
            println!("cargo::rustc-cfg={name}");
        }
    }
    if arch == "wasm32" && std::env::var_os("CARGO_FEATURE_WASM32_SIMD").is_some() {
        println!("cargo::rustc-cfg=blake3_wasm32_simd");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
