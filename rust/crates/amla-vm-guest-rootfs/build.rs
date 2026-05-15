// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Build script for the guest VM rootfs.
//!
//! This builds:
//! 1. Guest binaries (`guest_agent`, `coreutils`, and optionally test binaries)
//! 2. Creates an EROFS rootfs image containing `coreutils` and `guest_agent`
//!
//! The EROFS image is served via `virtio-fs` to guests with a `CoW` overlay.
//! Workspace-specific additions (container bundles, pty-relay, etc.) are mounted as separate pmem devices.
//!
//! The Linux kernel is built automatically from `kernel/Makefile` if not already present.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn target_arch() -> String {
    env::var("CARGO_CFG_TARGET_ARCH").unwrap()
}

// =============================================================================
// Path Helpers
// =============================================================================

fn workspace_root() -> PathBuf {
    // This crate lives in crates/amla-vm-guest-rootfs/.
    // The workspace root is at src/rust/ (two levels up).
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent() // crates/
        .expect("crates directory")
        .parent() // src/rust/
        .expect("workspace root")
        .to_path_buf()
}

/// Emits a cargo: directive, panicking if `value` contains newlines.
/// This prevents injection of additional cargo directives via crafted
/// path strings or environment variables.
fn cargo_directive(directive: &str, value: &str) {
    assert!(
        !value.contains('\n') && !value.contains('\r'),
        "cargo directive value contains newline characters: \
         directive={directive:?}, value={value:?}"
    );
    println!("cargo:{directive}={value}");
}

fn get_kernel(arch: &str) -> PathBuf {
    // 1. Use the amla guest kernel from the kernel/ subdirectory of this crate.
    //    The Makefile downloads, configures, and builds a minimal Linux kernel
    //    with CONFIG_VIRTIO_FS, CONFIG_VIRTIO_MEM, CONFIG_VIRTIO_BALLOON,
    //    and CONFIG_MHP_MEMMAP_ON_MEMORY — required for all integration tests.
    //
    //    x86_64: vmlinux (ELF, direct boot)
    //    aarch64: arch/arm64/boot/Image (flat binary with ARM64 header)
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let kernel_dir = manifest_dir.join("kernel");
    let build_dir = kernel_dir.join(".build");

    let kernel_image = match arch {
        "aarch64" => build_dir
            .join("linux-guest-build-arm64")
            .join("arch/arm64/boot/Image"),
        _ => build_dir.join("linux-guest-build-x86").join("vmlinux"),
    };

    cargo_directive("rerun-if-changed", &kernel_image.display().to_string());
    cargo_directive(
        "rerun-if-changed",
        &kernel_dir.join("Makefile").display().to_string(),
    );

    if kernel_image.exists() {
        return kernel_image.canonicalize().unwrap_or(kernel_image);
    }

    // 2. Build the kernel automatically via `make`.
    //    The Makefile handles download, configure, and compile.
    let guest_arch_arg = match arch {
        "aarch64" => "arm64",
        _ => "x86_64",
    };

    let mut cmd = Command::new("make");
    cmd.current_dir(&kernel_dir)
        .arg(format!("GUEST_ARCH={guest_arch_arg}"))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let output = cmd
        .output()
        .expect("failed to run `make` — is it installed?");

    assert!(
        output.status.success(),
        "Kernel build failed (exit code {:?}).\n\
         Ensure make, wget, gcc, flex, bison, and bc are installed.",
        output.status.code()
    );

    assert!(
        kernel_image.exists(),
        "Kernel build completed but output not found at: {}\n\
         Expected the Makefile to produce the kernel image at this path.",
        kernel_image.display()
    );

    kernel_image.canonicalize().unwrap_or(kernel_image)
}

// =============================================================================
// Build Guest Binary
// =============================================================================

fn guest_musl_target(arch: &str) -> &'static str {
    match arch {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        other => panic!(
            "Unsupported guest architecture: {other}. \
             Supported: x86_64, aarch64"
        ),
    }
}

fn check_musl_target(target: &str) -> Result<(), String> {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = Command::new(&rustc)
        .args(["--print", "target-list"])
        .output()
        .map_err(|e| format!("{rustc} not found ({e})"))?;

    if !output.status.success() {
        return Err("rustc --print target-list failed".into());
    }

    let targets = String::from_utf8_lossy(&output.stdout);
    if !targets.lines().any(|t| t.trim() == target) {
        return Err(format!(
            "Target {target} not recognized by rustc. \
             Ensure the toolchain supports this target."
        ));
    }
    Ok(())
}

/// Run `cargo build` in the workspace for a musl guest target, returning the profile output directory.
fn cargo_build_guest(
    workspace: &Path,
    target_dir: &Path,
    profile: &str,
    target: &str,
    crate_name: &str,
    bin_args: &[&str],
) -> PathBuf {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(&cargo);
    cmd.current_dir(workspace)
        .arg("build")
        .arg("--locked")
        .arg("-p")
        .arg(crate_name)
        .args(bin_args)
        .arg("--target")
        .arg(target)
        .arg("--target-dir")
        .arg(target_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Prevent the parent cargo's rustflags (e.g. Windows /LIBPATH args,
    // tokio_unstable cfg) from leaking into the guest Linux build.
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
    cmd.env_remove("RUSTFLAGS");

    // When cross-compiling guest binaries for a different architecture than the
    // host, propagate the cross-linker to the nested cargo invocation.
    let guest_arch = target.split('-').next().unwrap_or("");
    if guest_arch != std::env::consts::ARCH {
        let linker_env = format!(
            "CARGO_TARGET_{}_LINKER",
            target.to_uppercase().replace('-', "_")
        );
        let default_linker = match guest_arch {
            "aarch64" => "aarch64-linux-gnu-gcc",
            "x86_64" => "x86_64-linux-gnu-gcc",
            _ => "gcc",
        };
        let linker = env::var(&linker_env).unwrap_or_else(|_| default_linker.to_string());
        cmd.env(&linker_env, &linker);
    }

    if profile != "debug" {
        cmd.arg("--profile").arg(profile);
    }

    let output = cmd.output().expect("run cargo build");
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "Failed to build {crate_name} {bin_args:?}:\n\
             stdout: {stdout}\n\
             stderr: {stderr}"
        );
    }

    let profile_dir = if profile == "debug" { "debug" } else { profile };
    target_dir.join(target).join(profile_dir)
}

/// Build a single guest binary from the workspace for a musl guest target.
///
/// Returns the path to the built binary.
fn build_guest_binary(
    workspace: &Path,
    target_dir: &Path,
    profile: &str,
    target: &str,
    crate_name: &str,
    binary_name: &str,
    extra_args: &[&str],
) -> PathBuf {
    let mut bin_args = vec!["--bin", binary_name];
    bin_args.extend_from_slice(extra_args);
    cargo_build_guest(
        workspace, target_dir, profile, target, crate_name, &bin_args,
    )
    .join(binary_name)
}

// =============================================================================
// Vulkan ICD
// =============================================================================

// =============================================================================
// Main
// =============================================================================

/// Emit all cargo rerun-if-changed and rerun-if-env-changed directives.
fn register_rerun_triggers(workspace: &Path, _template: &Path) {
    for path in [
        "crates/amla-guest/src",
        "crates/amla-guest/Cargo.toml",
        "crates/amla-vm-constants/src",
        "crates/amla-vm-constants/Cargo.toml",
        "crates/amla-vm-ringbuf/src",
        "crates/amla-vm-ringbuf/Cargo.toml",
        "Cargo.lock",
    ] {
        cargo_directive(
            "rerun-if-changed",
            &workspace.join(path).display().to_string(),
        );
    }
}

fn main() {
    // Guest binaries are always Linux (musl), built for the target's architecture.
    // Stub only when we truly can't build (Miri, Windows target).
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let needs_stub = env::var("MIRI_SYSROOT").is_ok() || target_os == "windows";
    if needs_stub {
        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
        let stub = out_dir.join("cross_stub_bin");
        fs::write(&stub, b"").ok();
        let stub_str = stub.display().to_string();
        println!("cargo:rustc-env=AMLA_GUEST_BIN={stub_str}");
        println!("cargo:rustc-env=AMLA_KERNEL_BIN={stub_str}");
        return;
    }

    let arch = target_arch();
    let workspace = workspace_root();
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let template = manifest_dir.join("rootfs-template");

    register_rerun_triggers(&workspace, &template);

    let kernel_path = get_kernel(&arch);

    // Build the single unified amla-guest binary
    let guest_target_dir = out_dir.join("guest-target");
    let guest_target = guest_musl_target(&arch);
    check_musl_target(guest_target).unwrap_or_else(|e| panic!("{e}"));

    // Feature flags for the guest build
    #[allow(unused_mut)]
    let mut extra_args: Vec<&str> = Vec::new();
    #[cfg(feature = "test-binaries")]
    {
        extra_args.push("--features");
        extra_args.push("test-binaries");
    }

    let guest_bin = build_guest_binary(
        &workspace,
        &guest_target_dir,
        &profile,
        guest_target,
        "amla-guest",
        "amla-guest",
        &extra_args,
    );

    // Export binary path for include_bytes! in lib.rs
    cargo_directive("rustc-env=AMLA_GUEST_BIN", &guest_bin.display().to_string());
    cargo_directive(
        "rustc-env=AMLA_KERNEL_BIN",
        &kernel_path.display().to_string(),
    );
}
