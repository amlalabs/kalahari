//! Container hardening: minimal /dev population and capability drop.
//!
//! The guest kernel is booted with `iomem=relaxed`, and the `amla-guest`
//! agent (PID 1) needs `/dev/mem` at startup to map the host↔guest ring
//! buffer. If the container inherited the full guest devtmpfs and the root
//! capability set, any root process inside the container could also open
//! `/dev/mem` and reach the shared ring (and `/dev/pmem*`, `/dev/vsock`,
//! `/dev/vport*`, …) — bypassing the boundary the VM is supposed to
//! enforce.
//!
//! Two defenses, applied at container setup:
//!
//! 1. [`populate_container_dev`] — called right after the container's
//!    `/dev` is (re)mounted as tmpfs. It creates only the standard nodes
//!    a container expects (null, zero, random, …) plus any DRI/input/fuse
//!    nodes mirrored from the host VM for GPU and FUSE support. The
//!    dangerous nodes (mem, kmem, pmem*, vport*, vsock, hvc*, kmsg, …)
//!    are simply absent from the container's /dev.
//!
//! 2. [`drop_to_container_caps`] — called in the forked child that is
//!    about to `execve` the container command, right before `setgid`/
//!    `setuid`. Drops the bounding set and effective/permitted cap set
//!    to a Docker-like list, but without `CAP_MKNOD`; otherwise root
//!    could recreate hidden device nodes such as `/dev/kmsg`. Also sets
//!    `PR_SET_NO_NEW_PRIVS` so the drop survives `execve` of a suid or
//!    filecap binary.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::path::Path;

// ---------------------------------------------------------------------------
// /dev population
// ---------------------------------------------------------------------------

/// Core character devices every container expects, as `(path, mode, major, minor)`.
const CORE_NODES: &[(&str, u32, u32, u32)] = &[
    ("/dev/null", 0o666, 1, 3),
    ("/dev/zero", 0o666, 1, 5),
    ("/dev/full", 0o666, 1, 7),
    ("/dev/random", 0o666, 1, 8),
    ("/dev/urandom", 0o666, 1, 9),
    ("/dev/tty", 0o666, 5, 0),
    ("/dev/console", 0o600, 5, 1),
];

/// Populate a freshly-mounted tmpfs `/dev` with the device nodes a container
/// expects, plus host-VM GPU/input/fuse nodes if they exist at
/// `/run/vm-root/dev/…`.
///
/// Caller must:
/// - have already mounted a tmpfs (or any writable fs) at `/dev`,
/// - still hold `CAP_MKNOD` (we are called from PID 1 in the container
///   namespace, before [`drop_to_container_caps`]).
pub fn populate_container_dev() -> Result<(), String> {
    for &(path, mode, major, minor) in CORE_NODES {
        mknod_char(path, mode, major, minor)?;
    }

    for (link, target) in [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
        ("/dev/ptmx", "pts/ptmx"),
    ] {
        // Stale symlinks from a prior tmpfs population would block symlink();
        // NotFound is the expected happy path on a fresh tmpfs.
        if let Err(e) = fs::remove_file(link)
            && e.kind() != io::ErrorKind::NotFound
        {
            eprintln!("amla-init: remove stale {link}: {e}");
        }
        if let Err(e) = symlink(target, link) {
            eprintln!("amla-init: symlink {link} -> {target}: {e}");
        }
    }

    // Mirror GPU and input device nodes from the VM's devtmpfs (still visible
    // at /run/vm-root/dev/* at this point) so Wayland/GPU workloads keep
    // working. Best-effort — absent on headless HVF.
    mirror_subtree("/run/vm-root/dev/dri", "/dev/dri");
    mirror_subtree("/run/vm-root/dev/input", "/dev/input");
    mirror_node("/run/vm-root/dev/fuse", "/dev/fuse");

    Ok(())
}

fn mknod_char(path: &str, mode: u32, major: u32, minor: u32) -> Result<(), String> {
    let c = CString::new(path).map_err(|e| format!("cstring {path}: {e}"))?;
    let dev = libc::makedev(major, minor);
    // SAFETY: `c` is a live CString; `mode|S_IFCHR` is a valid file-type+mode;
    // `dev` is a dev_t from makedev.
    let ret = unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | mode, dev) };
    if ret != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
        return Err(format!("mknod {path}: {}", io::Error::last_os_error()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))
        .map_err(|e| format!("chmod {path}: {e}"))?;
    Ok(())
}

fn mirror_subtree(src: &str, dst: &str) {
    let Ok(entries) = fs::read_dir(src) else {
        return;
    };
    if let Err(e) = fs::create_dir_all(dst) {
        eprintln!("amla-init: create_dir_all {dst}: {e}");
        return;
    }
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(src_path) = Path::new(src).join(&name).to_str().map(str::to_owned) else {
            continue;
        };
        let Some(dst_path) = Path::new(dst).join(&name).to_str().map(str::to_owned) else {
            continue;
        };
        mirror_node(&src_path, &dst_path);
    }
}

fn mirror_node(src: &str, dst: &str) {
    let Ok(meta) = fs::symlink_metadata(src) else {
        return;
    };
    // Only mirror actual device nodes — never regular files, symlinks, dirs.
    if !(meta.file_type().is_char_device() || meta.file_type().is_block_device()) {
        return;
    }
    let Ok(dst_c) = CString::new(dst) else { return };
    let mode = meta.mode();
    // SAFETY: `dst_c` is a live CString; `mode` and `meta.rdev()` come from
    // stat on a live device node.
    let ret = unsafe { libc::mknod(dst_c.as_ptr(), mode, meta.rdev()) };
    if ret != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
        eprintln!("amla-init: mknod {dst}: {}", io::Error::last_os_error());
        return;
    }
    if let Err(e) = fs::set_permissions(dst, fs::Permissions::from_mode(mode & 0o7777)) {
        eprintln!("amla-init: set_permissions {dst}: {e}");
    }
}

// ---------------------------------------------------------------------------
// Capability drop
// ---------------------------------------------------------------------------

// Capability numbers from <linux/capability.h>.
const CAP_CHOWN: u32 = 0;
const CAP_DAC_OVERRIDE: u32 = 1;
const CAP_FOWNER: u32 = 3;
const CAP_FSETID: u32 = 4;
const CAP_KILL: u32 = 5;
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_SETPCAP: u32 = 8;
const CAP_NET_BIND_SERVICE: u32 = 10;
const CAP_NET_RAW: u32 = 13;
const CAP_SYS_CHROOT: u32 = 18;
const CAP_AUDIT_WRITE: u32 = 29;
const CAP_SETFCAP: u32 = 31;

/// Upper bound for `PR_CAPBSET_DROP` iteration. Kernel 6.12 defines caps up
/// to `CAP_CHECKPOINT_RESTORE = 40`. Extra slots are harmless — the prctl
/// just returns EINVAL and we ignore it.
const CAP_LAST_CAP: u32 = 40;

/// Retained capabilities (lower 32). Matches Docker's default bounding set:
/// `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `SETGID`, `SETUID`,
/// `SETPCAP`, `NET_BIND_SERVICE`, `NET_RAW`, `SYS_CHROOT`, `AUDIT_WRITE`,
/// `SETFCAP`.
///
/// Notably absent: `CAP_SYS_RAWIO` (would allow `/dev/mem`), `CAP_SYS_ADMIN`,
/// `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_SYS_BOOT`, `CAP_NET_ADMIN`,
/// `CAP_MKNOD` (would allow recreating hidden devices), `CAP_MAC_*`,
/// `CAP_SYSLOG`, `CAP_BPF`, `CAP_PERFMON`.
const RETAINED_MASK_LO: u32 = (1 << CAP_CHOWN)
    | (1 << CAP_DAC_OVERRIDE)
    | (1 << CAP_FOWNER)
    | (1 << CAP_FSETID)
    | (1 << CAP_KILL)
    | (1 << CAP_SETGID)
    | (1 << CAP_SETUID)
    | (1 << CAP_SETPCAP)
    | (1 << CAP_NET_BIND_SERVICE)
    | (1 << CAP_NET_RAW)
    | (1 << CAP_SYS_CHROOT)
    | (1 << CAP_AUDIT_WRITE)
    | (1 << CAP_SETFCAP);

/// Retained capabilities (upper 32). Empty — we keep nothing from 32+.
const RETAINED_MASK_HI: u32 = 0;

// capset() header/data structs and version constant. libc crate does not
// wrap capset() directly, so we call the syscall.
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Drop privileges to the container-root set.
///
/// Call in the forked child that will `execve` the container command, AFTER
/// any post-fork bookkeeping that needs elevated privilege and BEFORE
/// `setgid`/`setuid` (setuid to a non-zero uid clears effective/permitted
/// caps but cannot revoke `CAP_SETPCAP`, which `PR_CAPBSET_DROP` needs).
pub fn drop_to_container_caps() -> Result<(), String> {
    // SAFETY: prctl takes integer args; no pointer preconditions.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "prctl(PR_SET_NO_NEW_PRIVS): {}",
            io::Error::last_os_error()
        ));
    }

    // Drop every cap not in the retained set from the bounding set.
    for cap in 0..=CAP_LAST_CAP {
        let retained = if cap < 32 {
            (RETAINED_MASK_LO >> cap) & 1 != 0
        } else {
            (RETAINED_MASK_HI >> (cap - 32)) & 1 != 0
        };
        if retained {
            continue;
        }
        // SAFETY: PR_CAPBSET_DROP takes an integer cap index.
        let _ = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) };
    }

    // Narrow effective/permitted/inheritable to the retained set.
    let header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapUserData {
            effective: RETAINED_MASK_LO,
            permitted: RETAINED_MASK_LO,
            inheritable: 0,
        },
        CapUserData {
            effective: RETAINED_MASK_HI,
            permitted: RETAINED_MASK_HI,
            inheritable: 0,
        },
    ];
    // SAFETY: SYS_capset reads 1 cap_user_header_t from `&header` and 2
    // cap_user_data_t structs from `data.as_ptr()`. Layouts match the kernel
    // definition for LINUX_CAPABILITY_VERSION_3.
    let ret =
        unsafe { libc::syscall(libc::SYS_capset, std::ptr::from_ref(&header), data.as_ptr()) };
    if ret != 0 {
        return Err(format!("capset: {}", io::Error::last_os_error()));
    }

    Ok(())
}
