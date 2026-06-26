// Embed the per-arch guest (kernel + agent initramfs) into the macOS binary so a
// fresh install runs containers with no download and no toolchain. Artifacts are
// staged per Rust arch by `vmagent/build.sh <arch>`; if absent, the build still
// works and the VM falls back to downloading on first run.
use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(carrier_embedded)");

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let dir = format!("vmagent/artifacts/{arch}");
    let kernel = Path::new(&dir).join("Image");
    let initrd = Path::new(&dir).join("initramfs.cpio.gz");
    println!("cargo:rerun-if-changed={}", kernel.display());
    println!("cargo:rerun-if-changed={}", initrd.display());

    if os == "macos" && kernel.exists() && initrd.exists() {
        let out = env::var("OUT_DIR").unwrap();
        fs::copy(&kernel, Path::new(&out).join("Image")).unwrap();
        fs::copy(&initrd, Path::new(&out).join("initramfs.cpio.gz")).unwrap();
        println!("cargo:rustc-cfg=carrier_embedded");
    }
}
