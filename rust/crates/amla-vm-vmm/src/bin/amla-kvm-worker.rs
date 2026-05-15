// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#[cfg(all(target_os = "linux", feature = "subprocess"))]
#[tokio::main]
async fn main() -> ! {
    amla_vmm::worker_main().await
}

#[cfg(not(all(target_os = "linux", feature = "subprocess")))]
fn main() {
    eprintln!("amla-kvm-worker: not supported in this build configuration");
    std::process::exit(1);
}
