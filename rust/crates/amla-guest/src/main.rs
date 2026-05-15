//! Unified multi-call binary for amla guest VMs.
//!
//! Dispatches by subcommand: `amla-guest <subcmd> [args...]`.
//! When running as PID 1 (kernel `init=`), automatically enters agent mode.
//!
//! # Subcommands
//!
//! - `agent` — PID 1 guest agent (ring buffer IPC, process management)
//! - `init` — container namespace setup (OCI, Wayland compositor)
//! - `exec` — container command execution (namespace entry, uid/gid switch)
//! - coreutils applets (`echo`, `cat`, `ls`, etc.)
//! - test subcommands (behind `test-binaries` feature)

#![allow(clippy::print_stdout, clippy::print_stderr)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("amla-guest: only supported on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod agent;
#[cfg(target_os = "linux")]
mod coreutils;
#[cfg(target_os = "linux")]
mod exec;
#[cfg(target_os = "linux")]
mod hardening;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod net;
#[cfg(target_os = "linux")]
mod oci;
#[cfg(all(target_os = "linux", feature = "test-binaries"))]
#[allow(dead_code)]
mod testing;
#[cfg(target_os = "linux")]
mod wayland;

#[cfg(target_os = "linux")]
/// Redirect stdout/stderr to `/dev/kmsg` before `main()`, but only as PID 1.
///
/// When running as PID 1 in a KVM guest, the kernel opens `/dev/console` for
/// fd 0/1/2 but the console TTY returns EIO for userspace writes. Redirecting
/// to `/dev/kmsg` makes all stdio output appear on the serial console.
#[used]
#[unsafe(link_section = ".init_array")]
static REDIRECT_STDIO: unsafe extern "C" fn() = {
    unsafe extern "C" fn redirect() {
        // SAFETY: getpid has no preconditions.
        if unsafe { libc::getpid() } != 1 {
            return;
        }
        let path = b"/dev/kmsg\0";
        // SAFETY: `path` is a NUL-terminated byte string.
        let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_WRONLY) };
        if fd >= 0 {
            // SAFETY: `fd` is a valid OS fd just opened above; dup2/close take
            // valid fds and have no other preconditions.
            unsafe {
                libc::dup2(fd, 1);
                libc::dup2(fd, 2);
                if fd > 2 {
                    libc::close(fd);
                }
            }
        }
    }
    redirect
};

/// Coreutils applet names recognized as top-level subcommands.
#[cfg(target_os = "linux")]
const COREUTILS_APPLETS: &[&str] = &[
    "echo",
    "cat",
    "id",
    "ls",
    "mkdir",
    "dirname",
    "true",
    "false",
    "printenv",
    "exit-with",
    "sleep",
    "grep",
    "nproc",
    "wget",
    "ping",
    "tee",
    #[cfg(feature = "test-binaries")]
    "eof-marker",
    "dd",
    "mount",
    "umount",
    "wc",
    "date",
    "stat",
];

#[cfg(target_os = "linux")]
fn main() {
    // PID 1 → agent mode (kernel init= doesn't pass args).
    if std::process::id() == 1 {
        agent::run();
        return;
    }

    let args: Vec<String> = std::env::args().collect();
    let subcmd = args.get(1).map(String::as_str);

    let exit_code = match subcmd {
        Some("agent") => {
            agent::run();
            0
        }
        Some("init") => init::run(&args[2..]),
        Some("exec") => exec::run(&args[2..]),
        Some(name) if name == "coreutils" || COREUTILS_APPLETS.contains(&name) => {
            coreutils::run(name, &args[2..])
        }
        #[cfg(feature = "test-binaries")]
        Some("vm-exit") => testing::vm_exit::run(&args[2..]),
        #[cfg(feature = "test-binaries")]
        Some("test-autotest") => {
            testing::autotest::run();
            0
        }
        #[cfg(feature = "test-binaries")]
        Some("test-network") => {
            testing::network::run();
            0
        }
        #[cfg(feature = "test-binaries")]
        Some("udp-echo") => testing::udp_echo::run(&args[2..]),
        #[cfg(feature = "test-binaries")]
        Some("tcp-echo") => testing::tcp_echo::run(&args[2..]),
        #[cfg(feature = "test-binaries")]
        Some("tcp-upload") => testing::tcp_upload::run(&args[2..]),
        #[cfg(feature = "test-binaries")]
        Some("https-get") => testing::https_get::run(&args[2..]),
        Some(other) => {
            eprintln!("amla-guest: unknown subcommand: {other}");
            eprintln!("usage: amla-guest <agent|init|exec|APPLET> [args...]");
            1
        }
        None => {
            eprintln!("usage: amla-guest <agent|init|exec|APPLET> [args...]");
            1
        }
    };

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    std::process::exit(exit_code);
}
