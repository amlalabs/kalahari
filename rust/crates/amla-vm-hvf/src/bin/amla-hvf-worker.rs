// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

/// Embed entitlements plist in a Mach-O section so the linker wrapper
/// can extract and codesign automatically at link time.
#[cfg(target_os = "macos")]
#[used]
#[unsafe(link_section = "__DATA,__entitlements")]
static _ENTITLEMENTS: [u8; 245] = *include_bytes!("../../entitlements.plist");

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[tokio::main]
async fn main() -> ! {
    amla_hvf::worker::worker_main().await
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("amla-hvf-worker: only supported on macOS aarch64");
    std::process::exit(1);
}
