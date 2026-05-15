//! Guest agent - runs as PID 1, configured by host over ring buffer.
//!
//! # Startup Sequence
//!
//! 1. Mount /proc, /sys, /dev, cgroup2 (essential for any init)
//! 2. Set up networking
//! 3. Emit boot markers
//! 4. Open persistent control channel (receive proactive Setup from host)
//! 5. Enter async event loop (ring buffer)
//!
//! Zero cmdline parsing — all configuration comes from the host via ring buffer.
//!
//! # I/O Note
//!
//! A `.init_array` constructor redirects stdout/stderr to `/dev/kmsg` before
//! `main()` runs. This is necessary because the kernel's `/dev/console` TTY
//! returns EIO for userspace writes when running as PID 1 in a KVM guest.
//!
//! # Control Channel
//!
//! A single ring buffer transport carries all lifecycle messages (Ping
//! heartbeats) and exec sessions.
//! Host-to-guest notifications arrive as readable data on `/dev/vport0p1`
//! (virtio-console port 1); guest-to-host via 1-byte kick writes to the
//! same vport.
//!
//! # Async Runtime
//!
//! The agent uses a single-threaded tokio runtime (`current_thread`). On this
//! runtime, signals are only processed at `.await` points. Between
//! `posix_spawn()` and registration there are no `.await` points,
//! so SIGCHLD can never fire before registration — eliminating races.

#[allow(dead_code)]
pub mod transport;

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use amla_constants::protocol::{AgentSetup, ExecId, GuestMessage, HostMessage};
use transport::{RingTransport, mount_fs};

// =============================================================================
// Filesystem Setup (PID 1 responsibilities)
// =============================================================================

fn mount_essential_filesystems() {
    // Note: /dev is NOT listed — the kernel auto-mounts devtmpfs before PID 1
    // runs (CONFIG_DEVTMPFS_MOUNT=y). Adding it here would EBUSY.
    let mounts = [
        ("proc", "/proc", "proc"),
        ("sysfs", "/sys", "sysfs"),
        ("tmpfs", "/run", "tmpfs"),
        ("tmpfs", "/tmp", "tmpfs"),
        ("tmpfs", "/workspaces", "tmpfs"),
    ];

    for (source, target, fstype) in mounts {
        if let Err(e) = fs::create_dir_all(target) {
            eprintln!("boot: create_dir_all {target}: {e}");
        }
        if let Err(e) = mount_fs(source, target, fstype, 0, None) {
            eprintln!("mount {target}: {e}");
        }
        ckpt(&format!("mount_{fstype}"));
    }

    // devpts for PTY support (pty-relay needs /dev/pts/N slave devices)
    if let Err(e) = fs::create_dir_all("/dev/pts") {
        eprintln!("boot: create_dir_all /dev/pts: {e}");
    }
    if let Err(e) = mount_fs("devpts", "/dev/pts", "devpts", 0, None) {
        eprintln!("mount /dev/pts: {e}");
    }
    ckpt("mount_devpts");

    // cgroup2 — standard pseudo-filesystem for resource management
    mount_cgroup2();
    ckpt("mount_cgroup2");

    // cgroup v1 devices controller — Docker checks for this alongside cgroup2.
    if let Err(e) = fs::create_dir_all("/sys/fs/cgroup/devices") {
        eprintln!("boot: create_dir_all /sys/fs/cgroup/devices: {e}");
    }
    if let Err(e) = mount_fs(
        "cgroup",
        "/sys/fs/cgroup/devices",
        "cgroup",
        0,
        Some("devices"),
    ) {
        eprintln!("mount /sys/fs/cgroup/devices (cgroup v1): {e}");
    }
    ckpt("mount_cgroup_devices");

    // When root is read-only EROFS, overlay writable tmpfs on directories
    // that need to be writable (mount-point creation, etc.).
    if root_is_erofs() {
        mount_root_overlays();
        ckpt("mount_overlays");
    }
}

fn root_is_erofs() -> bool {
    fs::read_to_string("/proc/cmdline").is_ok_and(|c| c.contains("rootfstype=erofs"))
}

fn mount_root_overlays() {
    for (dir, tag) in [("/etc", "e"), ("/mnt", "m")] {
        let upper = format!("/run/ov/{tag}/u");
        let work = format!("/run/ov/{tag}/w");
        if let Err(e) = fs::create_dir_all(&upper) {
            eprintln!("overlay {dir}: create_dir_all {upper}: {e}");
        }
        if let Err(e) = fs::create_dir_all(&work) {
            eprintln!("overlay {dir}: create_dir_all {work}: {e}");
        }
        let opts = format!("lowerdir={dir},upperdir={upper},workdir={work}");
        if let Err(e) = mount_fs("overlay", dir, "overlay", 0, Some(&opts)) {
            eprintln!("overlay {dir}: {e}");
        }
    }
}

// =============================================================================
// AgentSetup Mount Processing
// =============================================================================

/// Process mount operations from the host's `AgentSetup` message.
fn process_mounts(mounts: &[amla_constants::protocol::MountOp]) {
    for op in mounts {
        if let Err(e) = execute_mount_op(op) {
            kmsg_fmt(format_args!("mount op failed: {e}"));
        }
    }
}

/// Counter for generating unique dm device names.
static DM_COUNTER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Counter for generating unique temp mount directories.
static MOUNT_COUNTER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Allocate a unique path under `/run/mnt/` for an intermediate mount.
/// Callers are responsible for creating the directory.
fn next_mount_dir() -> String {
    let n = MOUNT_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    format!("/run/mnt/{n}")
}

/// Recursively execute a mount operation. Returns the resulting device or
/// mount path for use by parent operations.
fn execute_mount_op(op: &amla_constants::protocol::MountOp) -> Result<String, io::Error> {
    use amla_constants::protocol::MountOp;
    match op {
        MountOp::Pmem { device_index } => Ok(format!("/dev/pmem{device_index}")),
        MountOp::DmLinear {
            device_index,
            offset,
            size,
        } => {
            let pmem_dev = format!("/dev/pmem{device_index}");
            let name = format!(
                "amla-{}",
                DM_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
            );
            dm_create_linear(&name, &pmem_dev, *offset, *size)?;
            let path = format!("/dev/mapper/{name}");
            Ok(path)
        }
        MountOp::Mount {
            source,
            mount_path,
            fs_type,
            options,
        } => {
            let path = match mount_path {
                Some(p) if p == "/" => return Ok("/".to_string()),
                Some(p) => p.clone(),
                None => next_mount_dir(),
            };
            let dev = execute_mount_op(source)?;
            fs::create_dir_all(&path)?;
            mount_fs(&dev, &path, fs_type, 0, Some(options))?;
            Ok(path)
        }
        MountOp::Overlay {
            lower,
            upper,
            mount_path,
        } => {
            fs::create_dir_all(mount_path)?;
            let mut lower_paths = Vec::with_capacity(lower.len().max(1));
            if lower.is_empty() {
                lower_paths.push(mount_path.clone());
            } else {
                for (i, l) in lower.iter().enumerate() {
                    lower_paths.push(
                        execute_mount_op(l)
                            .map_err(|e| io::Error::other(format!("overlay lower[{i}]: {e}")))?,
                    );
                }
            }
            let (upper_dir, work_dir) = if let Some(upper_op) = upper {
                let upper_base = execute_mount_op(upper_op)
                    .map_err(|e| io::Error::other(format!("overlay upper: {e}")))?;
                let u = format!("{upper_base}/upper");
                let w = format!("{upper_base}/work");
                fs::create_dir_all(&u)?;
                fs::create_dir_all(&w)?;
                (u, w)
            } else {
                let tmpfs_base = next_mount_dir();
                fs::create_dir_all(&tmpfs_base)?;
                mount_fs("tmpfs", &tmpfs_base, "tmpfs", 0, None)?;
                let u = format!("{tmpfs_base}/u");
                let w = format!("{tmpfs_base}/w");
                fs::create_dir_all(&u)?;
                fs::create_dir_all(&w)?;
                (u, w)
            };
            // Reverse: OCI layers are base-first, overlayfs lowerdir is top-first.
            lower_paths.reverse();
            let opts = format!(
                "lowerdir={},upperdir={upper_dir},workdir={work_dir},index=off,metacopy=off,redirect_dir=off,nfs_export=off",
                lower_paths.join(":")
            );
            mount_fs("overlay", mount_path, "overlay", 0, Some(&opts))?;
            Ok(mount_path.clone())
        }
        MountOp::VirtioFs { tag, mount_path } => {
            let path = match mount_path {
                Some(p) if p == "/" => return Ok("/".to_string()),
                Some(p) => p.clone(),
                None => next_mount_dir(),
            };
            fs::create_dir_all(&path)?;
            mount_fs(tag, &path, "virtiofs", 0, None)?;
            Ok(path)
        }
    }
}

/// Create a dm-linear device via device-mapper ioctls.
fn dm_create_linear(
    name: &str,
    backing_dev: &str,
    offset: u64,
    size: u64,
) -> Result<(), io::Error> {
    use std::os::unix::fs::MetadataExt;

    let meta = fs::metadata(backing_dev)?;
    let rdev = meta.rdev();
    let major = libc::major(rdev);
    let minor = libc::minor(rdev);

    let ctl = DmControl::open()?;

    // Create device — kernel returns dev number.
    let mut buf = DmIoctl::new(name);
    ctl.ioctl(DM_DEV_CREATE, &mut buf)?;
    let dev = buf.dev;

    // Load linear table.
    let mut buf = DmIoctl::new(name);
    let target_params = format!("{major}:{minor} {}", offset / 512);
    buf.set_target(0, size / 512, "linear", &target_params);
    ctl.ioctl(DM_TABLE_LOAD, &mut buf)?;

    // Activate.
    let mut buf = DmIoctl::new(name);
    ctl.ioctl(DM_DEV_SUSPEND, &mut buf)?;

    // Create device node.
    if let Err(e) = fs::create_dir_all("/dev/mapper") {
        eprintln!("dm: create_dir_all /dev/mapper: {e}");
    }
    let node = CString::new(format!("/dev/mapper/{name}"))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: `node` is a live CString; mode/dev are valid integer args.
    let ret = unsafe {
        libc::mknod(
            node.as_ptr(),
            libc::S_IFBLK | 0o660,
            libc::makedev(
                ((dev >> 8) & 0xFFF) as u32,
                (dev & 0xFF) as u32 | (((dev >> 12) & !0xFF) as u32),
            ),
        )
    };
    if ret != 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(e);
        }
    }

    Ok(())
}

// ── Device-mapper ioctl interface ────────────────────────────────────────

#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
const DM_DEV_CREATE: libc::Ioctl = 0xC138_FD03_u32 as i32 as libc::Ioctl;
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
const DM_TABLE_LOAD: libc::Ioctl = 0xC138_FD09_u32 as i32 as libc::Ioctl;
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
const DM_DEV_SUSPEND: libc::Ioctl = 0xC138_FD06_u32 as i32 as libc::Ioctl;

/// RAII wrapper for `/dev/mapper/control` fd.
struct DmControl(i32);

impl DmControl {
    fn open() -> Result<Self, io::Error> {
        let path = CString::new("/dev/mapper/control")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
        // SAFETY: `path` is a live CString, so `path.as_ptr()` is NUL-terminated.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    fn ioctl(&self, request: libc::Ioctl, io: &mut DmIoctl) -> Result<(), io::Error> {
        // SAFETY: `self.0` is a valid fd for /dev/mapper/control; `io` is a
        // DmIoctl with the matching struct layout for the DM_* request.
        let ret = unsafe { libc::ioctl(self.0, request, std::ptr::from_mut(io)) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for DmControl {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid OS fd owned by DmControl.
        unsafe { libc::close(self.0) };
    }
}

/// Kernel `struct dm_ioctl` (312 bytes) + inline target buffer (512 bytes).
#[repr(C)]
struct DmIoctl {
    version: [u32; 3],
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    _padding: u32,
    dev: u64,
    name: [u8; 128],
    uuid: [u8; 129],
    _pad: [u8; 7],
    target_buf: [u8; 512],
}

const DM_HEADER_SIZE: u32 = 312;

impl DmIoctl {
    fn new(name: &str) -> Self {
        let mut s = Self {
            version: [4, 0, 0],
            data_size: DM_HEADER_SIZE + 512,
            data_start: DM_HEADER_SIZE,
            target_count: 0,
            open_count: 0,
            flags: 0,
            event_nr: 0,
            _padding: 0,
            dev: 0,
            name: [0; 128],
            uuid: [0; 129],
            _pad: [0; 7],
            target_buf: [0; 512],
        };
        let len = name.len().min(127);
        s.name[..len].copy_from_slice(&name.as_bytes()[..len]);
        s
    }

    /// Write a single `dm_target_spec` + params into the inline buffer.
    ///
    /// Panics if `params` exceeds 471 bytes (the inline buffer is 512 bytes,
    /// and the `dm_target_spec` header is 40 bytes + NUL + 8-byte alignment).
    fn set_target(&mut self, sector_start: u64, num_sectors: u64, target_type: &str, params: &str) {
        self.target_count = 1;
        // dm_target_spec: sector_start(u64) + length(u64) + status(i32) + next(u32) + target_type([u8;16]) = 40 bytes
        let mut buf = [0u8; 512];
        buf[0..8].copy_from_slice(&sector_start.to_ne_bytes());
        buf[8..16].copy_from_slice(&num_sectors.to_ne_bytes());
        // next (offset 20): total size of spec + params, 8-byte aligned
        let params_bytes = params.as_bytes();
        let total = (40 + params_bytes.len() + 1 + 7) & !7;
        assert!(
            total <= self.target_buf.len(),
            "dm target params too large for inline buffer: {total} > {}",
            self.target_buf.len(),
        );
        #[allow(clippy::cast_possible_truncation)]
        buf[20..24].copy_from_slice(&(total as u32).to_ne_bytes());
        // target_type (offset 24, 16 bytes)
        let tt_len = target_type.len().min(15);
        buf[24..24 + tt_len].copy_from_slice(&target_type.as_bytes()[..tt_len]);
        // params (offset 40)
        buf[40..40 + params_bytes.len()].copy_from_slice(params_bytes);
        #[allow(clippy::cast_possible_truncation)] // total <= 512, fits u32
        {
            self.data_size = DM_HEADER_SIZE + total as u32;
        }
        self.target_buf[..total].copy_from_slice(&buf[..total]);
    }
}

fn kmsg_fmt(msg: std::fmt::Arguments<'_>) {
    let formatted = format!("<2>agent: {msg}\n");
    if let Err(e) = fs::write("/dev/kmsg", formatted.as_bytes()) {
        // Fall back to stderr (which is itself redirected to /dev/kmsg at init,
        // but that's a regular fd write so it may succeed when fs::write fails).
        eprintln!("agent: kmsg_fmt write failed ({e}); msg: {msg}");
    }
}

/// Write a WARNING-level message to /dev/kmsg (syslog priority 4).
fn kmsg_warn(msg: std::fmt::Arguments<'_>) {
    let formatted = format!("<4>agent: WARNING: {msg}\n");
    if let Err(e) = fs::write("/dev/kmsg", formatted.as_bytes()) {
        eprintln!("agent: kmsg_warn write failed ({e}); WARNING: {msg}");
    }
}

// =============================================================================
// Network Setup
// =============================================================================

/// Bring up networking: loopback (always) and eth0 (if present).
///
/// Uses netlink sockets directly — no external commands (ip, udhcpc).
/// Static config only (usernet defaults: 10.0.2.15/24, gw 10.0.2.2).
fn setup_network() {
    match crate::net::setup_network() {
        Ok(true) => {}
        Ok(false) => eprintln!("network: no eth0, skipped"),
        Err(e) => eprintln!("network: setup failed: {e}"),
    }
}

/// Mount cgroup2 at `/sys/fs/cgroup`.
fn mount_cgroup2() {
    if let Err(e) = fs::create_dir_all("/sys/fs/cgroup") {
        eprintln!("mount cgroup2: create_dir_all /sys/fs/cgroup: {e}");
    }
    if let Err(e) = mount_fs("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, None) {
        // EBUSY means already mounted — not an error
        if e.raw_os_error() != Some(libc::EBUSY) {
            eprintln!("mount cgroup2: {e}");
        }
    }
}

// =============================================================================
// Programmatic Exec (pipe-based, per-invocation)
// =============================================================================

/// Create a pipe pair. Returns `(read_fd, write_fd)`.
fn make_pipe() -> io::Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a 2-element array; pipe2 writes both fds into it.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fds.into())
}

/// Pre-built `CString` arrays and pointer vectors for `posix_spawnp`.
///
/// Must stay alive until after the spawn call — the pointer arrays
/// borrow from the `CString` vecs.
struct SpawnArgs {
    spawn_path: CString,
    _args_c: Vec<CString>,
    _env_c: Vec<CString>,
    argv_ptrs: Vec<*mut libc::c_char>,
    envp_ptrs: Vec<*mut libc::c_char>,
}

impl SpawnArgs {
    fn envp(&self) -> *const *mut libc::c_char {
        if self.envp_ptrs.is_empty() || (self.envp_ptrs.len() == 1 && self.envp_ptrs[0].is_null()) {
            std::ptr::null()
        } else {
            self.envp_ptrs.as_ptr()
        }
    }
}

/// Convert argv/env strings to `CString` arrays and build pointer vectors for `posix_spawnp`.
fn prepare_spawn(argv: &[String], env: &[String]) -> io::Result<SpawnArgs> {
    if argv.is_empty() {
        return Err(io::Error::other("empty argv"));
    }
    let spawn_path = to_cstring(&argv[0])?;
    let args_c: Vec<CString> = argv
        .iter()
        .map(|s| to_cstring(s))
        .collect::<io::Result<Vec<_>>>()?;
    let env_c: Vec<CString> = env
        .iter()
        .map(|s| {
            CString::new(s.as_str()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
        })
        .collect::<io::Result<Vec<_>>>()?;

    let mut argv_ptrs: Vec<*mut libc::c_char> =
        args_c.iter().map(|s| s.as_ptr().cast_mut()).collect();
    argv_ptrs.push(std::ptr::null_mut());

    let mut envp_ptrs: Vec<*mut libc::c_char> =
        env_c.iter().map(|c| c.as_ptr().cast_mut()).collect();
    if !env.is_empty() {
        envp_ptrs.push(std::ptr::null_mut());
    }

    Ok(SpawnArgs {
        spawn_path,
        _args_c: args_c,
        _env_c: env_c,
        argv_ptrs,
        envp_ptrs,
    })
}

/// Wait for a child process and return its exit code.
fn wait_child_exit(pid: libc::pid_t) -> i32 {
    let mut status: libc::c_int = 0;
    // SAFETY: `&raw mut status` is a valid out-pointer for the duration of the call.
    let ret = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if ret < 0 {
        -1
    } else if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
    }
}

/// Send an error message + ExecExit(-1) on the exec channel.
fn send_exec_fail(tx: &mpsc::Sender<GuestMessage>, id: ExecId, msg: String) {
    if let Err(e) = tx.blocking_send(GuestMessage::ExecStderr {
        id,
        data: msg.into_bytes(),
    }) {
        eprintln!("exec {id}: failed to send ExecStderr (fail-path): {e}");
    }
    if let Err(e) = tx.blocking_send(GuestMessage::ExecExit { id, code: -1 }) {
        eprintln!("exec {id}: failed to send ExecExit(-1) (fail-path): {e}");
    }
}

/// Drain a pipe fd with hysteresis aggregation, sending `ExecStdout` or `ExecStderr`.
///
/// Reads into `read_buf` repeatedly, aggregating into a single message up to
/// `max_payload` bytes. Flushes when the buffer fills or a partial read
/// indicates the pipe is drained.
///
/// Returns `true` if the pipe is still open, `false` on EOF (read returned 0).
fn drain_pipe_aggregated(
    fd: i32,
    read_buf: &mut [u8],
    max_payload: usize,
    id: ExecId,
    is_stdout: bool,
    tx: &mpsc::Sender<GuestMessage>,
) -> bool {
    let mut msg_buf = Vec::with_capacity(max_payload);

    let send = |data: Vec<u8>, where_: &str| {
        let (msg, variant) = if is_stdout {
            (GuestMessage::ExecStdout { id, data }, "ExecStdout")
        } else {
            (GuestMessage::ExecStderr { id, data }, "ExecStderr")
        };
        if let Err(e) = tx.blocking_send(msg) {
            eprintln!("exec {id}: failed to send {variant} ({where_}): {e}");
        }
    };
    let flush = |buf: Vec<u8>| {
        if !buf.is_empty() {
            send(buf, "drain flush");
        }
    };

    loop {
        // SAFETY: `fd` is a valid OS fd; `read_buf` has `read_buf.len()` bytes writable.
        let r = unsafe { libc::read(fd, read_buf.as_mut_ptr().cast(), read_buf.len()) };
        if r == 0 {
            flush(msg_buf);
            return false; // EOF — pipe closed
        }
        if r < 0 {
            // SAFETY: __errno_location returns a valid thread-local errno pointer.
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EINTR {
                continue; // interrupted — retry
            }
            flush(msg_buf);
            // EAGAIN/EWOULDBLOCK = pipe drained but open; anything else = permanent error
            return errno == libc::EAGAIN || errno == libc::EWOULDBLOCK;
        }

        #[allow(clippy::cast_sign_loss)]
        let n = r as usize;
        msg_buf.extend_from_slice(&read_buf[..n]);

        // Hysteresis: full read + room left → likely more data, keep reading.
        if n == read_buf.len() && msg_buf.len() + read_buf.len() <= max_payload {
            continue;
        }

        // Partial read (pipe drained) or buffer near-full → flush.
        send(std::mem::take(&mut msg_buf), "drain partial");

        // Partial read means pipe is drained — return to poll().
        if n < read_buf.len() {
            return true;
        }
    }
}

/// Run a command with piped stdin/stdout/stderr and send results back
/// over the control channel.
///
/// Spawns `argv[0]` directly via `posix_spawnp` with the given args.
/// Streams stdin from `stdin_rx`, reads stdout/stderr via poll, and
/// Apply `posix_spawn_file_actions_addchdir_np` if `cwd` is non-empty.
///
/// Returns the `CString` that must be kept alive until after `posix_spawn`.
/// Returns `Ok(None)` when `cwd` is empty (inherit parent).
fn apply_cwd(
    file_actions: &mut libc::posix_spawn_file_actions_t,
    cwd: &str,
) -> Result<Option<CString>, String> {
    if cwd.is_empty() {
        return Ok(None);
    }
    let c = CString::new(cwd).map_err(|e| format!("cwd: {e}"))?;
    let ret =
        // SAFETY: `file_actions` is an init'd posix_spawn_file_actions_t; `c`
        // is a live CString kept alive until the spawn call returns.
        unsafe { libc::posix_spawn_file_actions_addchdir_np(&raw mut *file_actions, c.as_ptr()) };
    if ret != 0 {
        return Err(format!("chdir: {}", io::Error::from_raw_os_error(ret)));
    }
    Ok(Some(c))
}

/// sends ExecStdout/ExecStderr/ExecExit.
#[allow(
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]
fn run_exec(
    id: ExecId,
    argv: &[String],
    env: &[String],
    cwd: &str,
    stdin_rx: &std::sync::mpsc::Receiver<Option<Vec<u8>>>,
    wake_fd: i32,
    paused: &AtomicBool,
    tx: &mpsc::Sender<GuestMessage>,
) {
    const READ_BUF_SIZE: usize = 8192;
    const MAX_EXEC_PAYLOAD: usize = 48 * 1024;

    kmsg_fmt(format_args!(
        "run_exec id={id} start argv[0]={:?} cwd={cwd:?}",
        argv.first()
    ));

    let sa = match prepare_spawn(argv, env) {
        Ok(sa) => sa,
        Err(e) => {
            send_exec_fail(tx, id, format!("{e}"));
            return;
        }
    };

    // Create pipes
    let (stdin_r, stdin_w) = match make_pipe() {
        Ok(p) => p,
        Err(e) => {
            send_exec_fail(tx, id, format!("pipe: {e}"));
            return;
        }
    };
    let (stdout_r, stdout_w) = match make_pipe() {
        Ok(p) => p,
        Err(e) => {
            // SAFETY: stdin_r/stdin_w are valid OS fds owned by this scope.
            unsafe {
                libc::close(stdin_r);
                libc::close(stdin_w);
            }
            send_exec_fail(tx, id, format!("pipe: {e}"));
            return;
        }
    };
    let (stderr_r, stderr_w) = match make_pipe() {
        Ok(p) => p,
        Err(e) => {
            // SAFETY: stdin_r/stdin_w/stdout_r/stdout_w are valid OS fds owned
            // by this scope.
            unsafe {
                libc::close(stdin_r);
                libc::close(stdin_w);
                libc::close(stdout_r);
                libc::close(stdout_w);
            }
            send_exec_fail(tx, id, format!("pipe: {e}"));
            return;
        }
    };

    // posix_spawn with pipe redirection
    // SAFETY: posix_spawn_file_actions_t is an all-zero-valid POD.
    let mut file_actions: libc::posix_spawn_file_actions_t = unsafe { std::mem::zeroed() };
    // SAFETY: `file_actions` is a stack-local posix_spawn_file_actions_t; init
    // is paired with the destroy calls below.
    unsafe { libc::posix_spawn_file_actions_init(&raw mut file_actions) };

    let _cwd_c = match apply_cwd(&mut file_actions, cwd) {
        Ok(c) => c,
        Err(msg) => {
            // SAFETY: `file_actions` was init'd above (destroy pairs with it);
            // all six fds are valid OS fds owned by this scope.
            unsafe {
                libc::posix_spawn_file_actions_destroy(&raw mut file_actions);
                libc::close(stdin_r);
                libc::close(stdin_w);
                libc::close(stdout_r);
                libc::close(stdout_w);
                libc::close(stderr_r);
                libc::close(stderr_w);
            }
            send_exec_fail(tx, id, msg);
            return;
        }
    };

    // SAFETY: `file_actions` was init'd above; fd args are valid OS fds owned
    // by this scope. adddup2/addclose record actions to replay in the child.
    unsafe {
        libc::posix_spawn_file_actions_adddup2(&raw mut file_actions, stdin_r, 0);
        libc::posix_spawn_file_actions_adddup2(&raw mut file_actions, stdout_w, 1);
        libc::posix_spawn_file_actions_adddup2(&raw mut file_actions, stderr_w, 2);
        libc::posix_spawn_file_actions_addclose(&raw mut file_actions, stdin_r);
        libc::posix_spawn_file_actions_addclose(&raw mut file_actions, stdin_w);
        libc::posix_spawn_file_actions_addclose(&raw mut file_actions, stdout_r);
        libc::posix_spawn_file_actions_addclose(&raw mut file_actions, stdout_w);
        libc::posix_spawn_file_actions_addclose(&raw mut file_actions, stderr_r);
        libc::posix_spawn_file_actions_addclose(&raw mut file_actions, stderr_w);
    }

    let mut child_pid: libc::pid_t = 0;
    // SAFETY: `&raw mut child_pid` is a valid pid_t out-pointer; `sa.spawn_path`
    // is a live CString; `file_actions` was init'd above; attrs pointer is NULL
    // (allowed); argv_ptrs/envp arrays are NULL-terminated and kept alive by
    // `sa`.
    let ret = unsafe {
        libc::posix_spawnp(
            &raw mut child_pid,
            sa.spawn_path.as_ptr(),
            &raw const file_actions,
            std::ptr::null(),
            sa.argv_ptrs.as_ptr(),
            sa.envp(),
        )
    };

    // SAFETY: `file_actions` was init'd above; destroy pairs with that init.
    unsafe { libc::posix_spawn_file_actions_destroy(&raw mut file_actions) };

    // Close child's side of the pipes in the parent
    // SAFETY: stdin_r/stdout_w/stderr_w are valid OS fds owned by this scope.
    unsafe {
        libc::close(stdin_r);
        libc::close(stdout_w);
        libc::close(stderr_w);
    }

    if ret != 0 {
        // SAFETY: stdin_w/stdout_r/stderr_r are valid OS fds owned by this scope.
        unsafe {
            libc::close(stdin_w);
            libc::close(stdout_r);
            libc::close(stderr_r);
        }
        kmsg_fmt(format_args!(
            "run_exec id={id} posix_spawn FAILED ret={ret}"
        ));
        send_exec_fail(
            tx,
            id,
            format!("posix_spawn: {}", io::Error::from_raw_os_error(ret)),
        );
        return;
    }

    kmsg_fmt(format_args!("run_exec id={id} spawned pid={child_pid}"));

    // Read stdout/stderr via poll; drain stdin_rx when eventfd fires.
    let mut fds = [
        libc::pollfd {
            fd: stdout_r,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stderr_r,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // Hysteresis read buffer: aggregate multiple pipe reads into one ring
    // message (up to MAX_EXEC_PAYLOAD), flushing when the buffer fills or the
    // pipe runs dry (partial read). This reduces ring kicks ~12x for sustained
    // transfers while adding zero latency for bursty/interactive workloads.
    let mut read_buf = [0u8; READ_BUF_SIZE];
    let mut stdin_w_opt = Some(stdin_w);

    loop {
        // stdout and stderr both closed — nothing left to poll
        if fds[0].fd < 0 && fds[1].fd < 0 {
            break;
        }

        // Backpressure: disable output polling when paused. When resumed,
        // events are re-enabled and the next poll() picks up pending data.
        // POLLHUP is always reported regardless of events, so pipe closure
        // (child exit) is still detected even while paused.
        if paused.load(Ordering::Relaxed) {
            if fds[0].fd >= 0 {
                fds[0].events = 0;
            }
            if fds[1].fd >= 0 {
                fds[1].events = 0;
            }
        } else {
            if fds[0].fd >= 0 {
                fds[0].events = libc::POLLIN;
            }
            if fds[1].fd >= 0 {
                fds[1].events = libc::POLLIN;
            }
        }

        // Event-driven: block until stdout/stderr data or stdin wakeup.
        // SAFETY: `fds` points to `fds.len()` pollfd entries for the duration of the call.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            break;
        }

        // Wake fd fired — drain eventfd counter, then drain stdin_rx.
        if fds[2].fd >= 0 && (fds[2].revents & libc::POLLIN) != 0 {
            let mut val: u64 = 0;
            // SAFETY: `wake_fd` is a valid eventfd; `&raw mut val` is a valid u64 out-pointer.
            unsafe { libc::eventfd_read(wake_fd, &raw mut val) };
        }
        // Drain pending stdin chunks from the host.
        if let Some(stdin_w) = stdin_w_opt {
            let mut close_it = false;
            loop {
                match stdin_rx.try_recv() {
                    Ok(Some(data)) => {
                        let mut written = 0;
                        while written < data.len() {
                            // SAFETY: `stdin_w` is a valid OS fd; the slice
                            // covers `data.len() - written` readable bytes.
                            let n = unsafe {
                                libc::write(
                                    stdin_w,
                                    data[written..].as_ptr().cast(),
                                    data.len() - written,
                                )
                            };
                            if n <= 0 {
                                close_it = true;
                                break;
                            }
                            written += n as usize;
                        }
                        if close_it {
                            break;
                        }
                    }
                    Ok(None) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        close_it = true;
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                }
            }
            if close_it {
                // SAFETY: `stdin_w` is a valid OS fd owned by this scope.
                unsafe { libc::close(stdin_w) };
                stdin_w_opt = None;
                // No more stdin — stop polling wake_fd
                fds[2].fd = -1;
            } else {
                stdin_w_opt = Some(stdin_w);
            }
        }

        // stdout — aggregate reads with hysteresis
        if fds[0].fd >= 0
            && (fds[0].revents & (libc::POLLIN | libc::POLLHUP)) != 0
            && !drain_pipe_aggregated(fds[0].fd, &mut read_buf, MAX_EXEC_PAYLOAD, id, true, tx)
        {
            // SAFETY: `fds[0].fd` is a valid OS fd owned by this scope.
            unsafe { libc::close(fds[0].fd) };
            fds[0].fd = -1;
        }

        // stderr — aggregate reads with hysteresis
        if fds[1].fd >= 0
            && (fds[1].revents & (libc::POLLIN | libc::POLLHUP)) != 0
            && !drain_pipe_aggregated(fds[1].fd, &mut read_buf, MAX_EXEC_PAYLOAD, id, false, tx)
        {
            // SAFETY: `fds[1].fd` is a valid OS fd owned by this scope.
            unsafe { libc::close(fds[1].fd) };
            fds[1].fd = -1;
        }
    }

    // Close stdin pipe if still open.
    if let Some(stdin_w) = stdin_w_opt {
        // SAFETY: `stdin_w` is a valid OS fd owned by this scope.
        unsafe { libc::close(stdin_w) };
    }
    // Close the wake eventfd (we own it).
    if wake_fd >= 0 {
        // SAFETY: `wake_fd` is a valid eventfd owned by this scope.
        unsafe { libc::close(wake_fd) };
    }

    // Wait for child exit.
    kmsg_fmt(format_args!(
        "run_exec id={id} pipes closed, waiting pid={child_pid}"
    ));
    let code = wait_child_exit(child_pid);
    kmsg_fmt(format_args!("run_exec id={id} exit code={code}"));
    if let Err(e) = tx.blocking_send(GuestMessage::ExecExit { id, code }) {
        eprintln!("exec {id}: failed to send ExecExit (code={code}): {e}");
    }
}

/// Spawn a `run_exec` on a blocking thread with stdin channel and eventfd wakeup.
///
/// Inline cat builtin: copies stdin→stdout (throughput benchmark).
#[allow(clippy::too_many_arguments)]
fn spawn_exec(
    id: ExecId,
    argv: Vec<String>,
    env: Vec<String>,
    cwd: String,
    exec_senders: &mut HashMap<ExecId, ExecSender>,
    echo_tx: &mpsc::Sender<GuestMessage>,
    cleanup_tx: &mpsc::Sender<ExecId>,
) {
    let (stdin_tx, stdin_rx) = std::sync::mpsc::channel();
    // SAFETY: initval 0 and valid EFD_* flags; eventfd has no other preconditions.
    let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    let paused = Arc::new(AtomicBool::new(false));
    exec_senders.insert(
        id,
        ExecSender {
            tx: stdin_tx,
            wake_fd,
            pty_master_fd: -1,
            paused: Arc::clone(&paused),
        },
    );
    let tx = echo_tx.clone();
    let done = cleanup_tx.clone();
    tokio::task::spawn_blocking(move || {
        run_exec(id, &argv, &env, &cwd, &stdin_rx, wake_fd, &paused, &tx);
        if let Err(err) = done.blocking_send(id) {
            eprintln!("exec {id}: failed to signal cleanup (run_exec): {err}");
        }
    });
}

/// Spawn `run_exec_pty` on a blocking thread — like `spawn_exec` but with a PTY.
///
/// The PTY master fd is stored in `exec_senders` so `SessionResize` can
/// call `ioctl(TIOCSWINSZ)` on it.
#[allow(clippy::too_many_arguments)]
fn spawn_exec_pty(
    id: ExecId,
    argv: Vec<String>,
    env: Vec<String>,
    cwd: String,
    exec_senders: &mut HashMap<ExecId, ExecSender>,
    echo_tx: &mpsc::Sender<GuestMessage>,
    cleanup_tx: &mpsc::Sender<ExecId>,
    outgoing_buf: &mut std::collections::VecDeque<GuestMessage>,
) {
    let (stdin_tx, stdin_rx) = std::sync::mpsc::channel();
    // SAFETY: initval 0 and valid EFD_* flags; eventfd has no other preconditions.
    let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };

    // openpty before spawning the thread so the master fd is available
    // in exec_senders for SessionResize.
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: `&raw mut master`/`&raw mut slave` are valid c_int out-pointers;
    // name/termios/winsize are NULL (allowed — openpty skips those outputs).
    let ret = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        kmsg_fmt(format_args!("exec_pty id={id} openpty failed: {err}"));
        outgoing_buf.push_back(GuestMessage::ExecStderr {
            id,
            data: format!("openpty: {err}").into_bytes(),
        });
        outgoing_buf.push_back(GuestMessage::ExecExit { id, code: -1 });
        return;
    }

    // Get the slave PTY path for TIOCSCTTY setup in the child.
    // SAFETY: `master` is an openpty() master fd; ptsname returns either NULL
    // or a pointer to a static NUL-terminated string owned by libc — we copy
    // it to an owned CString before any other libc call can invalidate it.
    let slave_path = unsafe {
        let ptr = libc::ptsname(master);
        if ptr.is_null() {
            None
        } else {
            Some(std::ffi::CStr::from_ptr(ptr).to_owned())
        }
    };

    let paused = Arc::new(AtomicBool::new(false));
    exec_senders.insert(
        id,
        ExecSender {
            tx: stdin_tx,
            wake_fd,
            pty_master_fd: master,
            paused: Arc::clone(&paused),
        },
    );
    let tx = echo_tx.clone();
    let done = cleanup_tx.clone();
    tokio::task::spawn_blocking(move || {
        run_exec_pty(
            id,
            &argv,
            &env,
            &cwd,
            master,
            slave,
            slave_path.as_deref(),
            &stdin_rx,
            wake_fd,
            &paused,
            &tx,
        );
        if let Err(err) = done.blocking_send(id) {
            eprintln!("exec {id}: failed to signal cleanup (run_exec_pty): {err}");
        }
    });
}

/// Run a command with a PTY. Like `run_exec` but the child gets a real terminal.
///
/// Uses `posix_spawnp` with the PTY slave as stdin/stdout/stderr.
/// When `slave_path` is available, the child gets a new session (`setsid`)
/// and re-opens the slave to acquire it as controlling terminal.
/// The parent reads/writes the single PTY master fd (stdout+stderr merged).
#[allow(
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn run_exec_pty(
    id: ExecId,
    argv: &[String],
    env: &[String],
    cwd: &str,
    master: i32,
    slave: i32,
    slave_path: Option<&std::ffi::CStr>,
    stdin_rx: &std::sync::mpsc::Receiver<Option<Vec<u8>>>,
    wake_fd: i32,
    paused: &AtomicBool,
    tx: &mpsc::Sender<GuestMessage>,
) {
    const READ_BUF_SIZE: usize = 8192;
    const MAX_EXEC_PAYLOAD: usize = 48 * 1024;

    kmsg_fmt(format_args!(
        "run_exec_pty id={id} start argv[0]={:?}",
        argv.first()
    ));

    let sa = match prepare_spawn(argv, env) {
        Ok(sa) => sa,
        Err(e) => {
            // SAFETY: master/slave are openpty() result fds owned by this scope.
            unsafe {
                libc::close(master);
                libc::close(slave);
            }
            send_exec_fail(tx, id, format!("{e}"));
            return;
        }
    };

    // posix_spawn with PTY slave as stdin/stdout/stderr.
    // POSIX_SPAWN_SETSID + re-open slave → child gets controlling terminal.
    // SAFETY: posix_spawn_file_actions_t is an all-zero-valid POD.
    let mut file_actions: libc::posix_spawn_file_actions_t = unsafe { std::mem::zeroed() };
    // SAFETY: `file_actions` is stack-local; init pairs with destroy below.
    unsafe { libc::posix_spawn_file_actions_init(&raw mut file_actions) };

    let _cwd_c = match apply_cwd(&mut file_actions, cwd) {
        Ok(c) => c,
        Err(msg) => {
            // SAFETY: `file_actions` was init'd above; master/slave are valid fds.
            unsafe {
                libc::posix_spawn_file_actions_destroy(&raw mut file_actions);
                libc::close(master);
                libc::close(slave);
            }
            send_exec_fail(tx, id, msg);
            return;
        }
    };

    // Set up spawn attrs with SETSID when we have the slave path.
    // SAFETY: posix_spawnattr_t is an all-zero-valid POD.
    let mut attrs: libc::posix_spawnattr_t = unsafe { std::mem::zeroed() };
    let has_setsid = slave_path.is_some();
    if has_setsid {
        // SAFETY: `attrs` is stack-local; init pairs with the destroy below
        // (gated on `has_setsid`).
        unsafe {
            libc::posix_spawnattr_init(&raw mut attrs);
            #[allow(clippy::cast_possible_truncation)]
            libc::posix_spawnattr_setflags(&raw mut attrs, libc::POSIX_SPAWN_SETSID as _);
        }
    }

    // SAFETY: `file_actions` was init'd above; `slave`/`master` are valid fds
    // owned by this scope; when `slave_path` is Some, it's a live CStr returned
    // from `ptsname` and copied to an owned CString kept alive on the stack
    // for the whole duration.
    unsafe {
        if let Some(path) = slave_path {
            // Close inherited slave, re-open as fd 0 to acquire controlling tty.
            libc::posix_spawn_file_actions_addclose(&raw mut file_actions, slave);
            libc::posix_spawn_file_actions_addopen(
                &raw mut file_actions,
                0,
                path.as_ptr(),
                libc::O_RDWR,
                0,
            );
        } else {
            // Fallback: just dup the inherited slave fd.
            libc::posix_spawn_file_actions_adddup2(&raw mut file_actions, slave, 0);
        }
        libc::posix_spawn_file_actions_adddup2(&raw mut file_actions, 0, 1);
        libc::posix_spawn_file_actions_adddup2(&raw mut file_actions, 0, 2);
        if slave != 0 && slave != 1 && slave != 2 {
            libc::posix_spawn_file_actions_addclose(&raw mut file_actions, slave);
        }
        libc::posix_spawn_file_actions_addclose(&raw mut file_actions, master);
    }

    let mut child_pid: libc::pid_t = 0;
    let attrs_ptr = if has_setsid {
        &raw const attrs
    } else {
        std::ptr::null()
    };
    // SAFETY: `&raw mut child_pid` is a valid pid_t out-pointer; `sa.spawn_path`
    // is a live CString; `file_actions` was init'd above; `attrs_ptr` is either
    // &attrs (which was init'd when has_setsid) or NULL; argv/envp arrays are
    // NULL-terminated and kept alive by `sa`.
    let ret = unsafe {
        libc::posix_spawnp(
            &raw mut child_pid,
            sa.spawn_path.as_ptr(),
            &raw const file_actions,
            attrs_ptr,
            sa.argv_ptrs.as_ptr(),
            sa.envp(),
        )
    };
    // SAFETY: `file_actions` was init'd above; destroy pairs with that init.
    unsafe { libc::posix_spawn_file_actions_destroy(&raw mut file_actions) };
    if has_setsid {
        // SAFETY: `attrs` was init'd above; destroy pairs with that init.
        unsafe { libc::posix_spawnattr_destroy(&raw mut attrs) };
    }
    // SAFETY: `slave` is an openpty() result fd owned by this scope.
    unsafe { libc::close(slave) };

    if ret != 0 {
        // SAFETY: `master` is an openpty() result fd owned by this scope.
        unsafe { libc::close(master) };
        kmsg_fmt(format_args!(
            "run_exec_pty id={id} posix_spawn FAILED ret={ret}"
        ));
        send_exec_fail(
            tx,
            id,
            format!("posix_spawn: {}", io::Error::from_raw_os_error(ret)),
        );
        return;
    }

    kmsg_fmt(format_args!("run_exec_pty id={id} spawned pid={child_pid}"));

    // Poll PTY master (output) + wake_fd (stdin from host).
    let mut fds = [
        libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let mut read_buf = [0u8; READ_BUF_SIZE];

    loop {
        if fds[0].fd < 0 {
            break;
        }

        // Backpressure: disable PTY output polling when paused.
        if paused.load(Ordering::Relaxed) {
            if fds[0].fd >= 0 {
                fds[0].events = 0;
            }
        } else if fds[0].fd >= 0 {
            fds[0].events = libc::POLLIN;
        }

        // SAFETY: `fds` points to `fds.len()` pollfd entries for the duration of the call.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            break;
        }

        // Drain eventfd counter on wake.
        if fds[1].fd >= 0 && (fds[1].revents & libc::POLLIN) != 0 {
            let mut val: u64 = 0;
            // SAFETY: `wake_fd` is a valid eventfd; `&raw mut val` is a valid u64 out-pointer.
            unsafe { libc::eventfd_read(wake_fd, &raw mut val) };
        }
        // Host stdin → PTY master.
        if fds[1].fd >= 0 {
            drain_stdin_to_fd(stdin_rx, master, &mut fds[1].fd);
        }

        // PTY master → ExecStdout.
        if fds[0].fd >= 0
            && (fds[0].revents & (libc::POLLIN | libc::POLLHUP)) != 0
            && !drain_pipe_aggregated(fds[0].fd, &mut read_buf, MAX_EXEC_PAYLOAD, id, true, tx)
        {
            fds[0].fd = -1;
        }
    }

    // SAFETY: `master` is a valid openpty() fd; `wake_fd` is a valid eventfd
    // (both owned by this scope).
    unsafe {
        libc::close(master);
        if wake_fd >= 0 {
            libc::close(wake_fd);
        }
    }

    kmsg_fmt(format_args!(
        "run_exec_pty id={id} pty closed, waiting pid={child_pid}"
    ));
    let code = wait_child_exit(child_pid);
    kmsg_fmt(format_args!("run_exec_pty id={id} exit code={code}"));
    if let Err(e) = tx.blocking_send(GuestMessage::ExecExit { id, code }) {
        eprintln!("exec {id}: failed to send ExecExit (pty, code={code}): {e}");
    }
}

/// Drain pending stdin chunks from the host and write them to a PTY master fd.
///
/// On EOF or disconnect, writes EOT (`^D`) so canonical-mode programs such as
/// shells and `cat` see stdin EOF, then sets `wake_poll_fd` to -1 to stop
/// polling for more host input.
#[allow(clippy::cast_sign_loss)]
fn drain_stdin_to_fd(
    stdin_rx: &std::sync::mpsc::Receiver<Option<Vec<u8>>>,
    write_fd: i32,
    wake_poll_fd: &mut i32,
) {
    loop {
        match stdin_rx.try_recv() {
            Ok(Some(data)) => {
                let mut written = 0;
                while written < data.len() {
                    // SAFETY: `write_fd` is a valid OS fd; the slice covers
                    // `data.len() - written` readable bytes.
                    let n = unsafe {
                        libc::write(
                            write_fd,
                            data[written..].as_ptr().cast(),
                            data.len() - written,
                        )
                    };
                    if n <= 0 {
                        *wake_poll_fd = -1;
                        return;
                    }
                    written += n as usize;
                }
            }
            Ok(None) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                let eot = [0x04u8];
                // SAFETY: `write_fd` is the PTY master fd owned by the caller;
                // `eot` points to one initialized byte for the duration of the call.
                unsafe {
                    libc::write(write_fd, eot.as_ptr().cast(), eot.len());
                }
                *wake_poll_fd = -1;
                return;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
        }
    }
}

// =============================================================================
// Async Helpers
// =============================================================================

/// Set a file descriptor to non-blocking mode.
fn set_nonblocking(fd: i32) {
    // SAFETY: `fd` is a valid OS fd; F_GETFL/F_SETFL take an int flags arg.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// Build a [`CString`] from a string, returning an error on NUL bytes.
fn to_cstring(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::other(format!("NUL byte in string: {s:?}")))
}

/// Log a warning if a ring buffer is near-full or completely full.
///
/// Thresholds: >=75% triggers a warning, 100% (or `try_send` returned false)
/// triggers a louder "FULL" warning. Rate-limited to avoid spamming kmsg —
/// only logs when crossing a threshold boundary (tracked via `last_pct`).
const fn pct_bucket(p: u8) -> u8 {
    match p {
        100.. => 3,
        90..=99 => 2,
        75..=89 => 1,
        _ => 0,
    }
}

fn check_ring_usage(label: &str, used: u32, capacity: u32, last_pct: &mut u8, backlog: usize) {
    if capacity == 0 {
        return;
    }
    #[allow(clippy::cast_possible_truncation)] // pct is 0..=100, always fits u8
    let pct = ((u64::from(used) * 100) / u64::from(capacity)) as u8;

    let cur = pct_bucket(pct);
    let prev = pct_bucket(*last_pct);

    // Only log when entering a new (higher) bucket.
    // Also re-log when dropping back below 75% then climbing again.
    if cur >= 1 && cur > prev {
        let used_mb = used / (1024 * 1024);
        let cap_mb = capacity / (1024 * 1024);
        if cur >= 3 {
            kmsg_warn(format_args!(
                "{label} ring FULL — {used_mb}/{cap_mb} MB used ({pct}%), backlog={backlog} msgs"
            ));
        } else {
            kmsg_warn(format_args!(
                "{label} ring near full — {used_mb}/{cap_mb} MB used ({pct}%), backlog={backlog} msgs"
            ));
        }
    }

    *last_pct = pct;
}

/// Flush buffered outgoing messages to the GH ring.
///
/// Writes as many buffered messages as the ring can accept, kicks once.
fn flush_outgoing_buf(
    transport: &RingTransport,
    buf: &mut std::collections::VecDeque<GuestMessage>,
    gh_last_pct: &mut u8,
) {
    if buf.is_empty() {
        return;
    }
    let mut flushed = false;
    while let Some(msg) = buf.front() {
        match transport.try_send(msg) {
            Ok(true) => {
                buf.pop_front();
                flushed = true;
            }
            Ok(false) | Err(_) => break,
        }
    }
    if flushed {
        transport.kick();
    }
    match transport.gh_usage() {
        Ok((used, cap)) => check_ring_usage("GH (guest→host)", used, cap, gh_last_pct, buf.len()),
        Err(e) => eprintln!("ring: GH usage failed: {e}"),
    }
}

// =============================================================================
// Ring Buffer Control Channel
// =============================================================================

/// Discover the ring buffer transport and wait for the host's proactive Setup.
///
/// Reads ring GPA from cmdline, mmaps shared memory, opens `/dev/vport0p1`
/// for kicks, then polls the ring for the host's proactive Setup message.
fn ring_handshake() -> (RingTransport, AgentSetup) {
    let mut transport = match RingTransport::discover() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("FATAL: ring transport discovery: {e}");
            std::process::exit(1);
        }
    };

    // Wait for Setup (host queues it proactively)
    let setup = loop {
        match transport.try_recv() {
            Ok(Some(HostMessage::Setup(setup))) => break setup,
            Ok(_) => {}
            Err(e) => {
                eprintln!("FATAL: try_recv: {e}");
                std::process::exit(1);
            }
        }
        if let Err(e) = transport.wait_kick() {
            eprintln!("FATAL: wait_kick: {e}");
            std::process::exit(1);
        }
    };

    (transport, setup)
}

/// Per-exec-session stdin sender with optional wakeup fd.
///
/// For `posix_spawn`'d commands, `wake_fd` is an eventfd that wakes the
/// `poll()` loop when stdin data arrives. For builtin commands (echo, cat),
/// `wake_fd` is -1 (they block on the channel directly).
///
/// The eventfd is owned by `run_exec` (which closes it on return).
/// This struct only holds the fd value for signaling.
struct ExecSender {
    tx: std::sync::mpsc::Sender<Option<Vec<u8>>>,
    wake_fd: i32,
    /// PTY master fd for sessions started with `ExecPty`. -1 for pipe-based exec.
    /// Used by `SessionResize` to call `ioctl(TIOCSWINSZ)`.
    /// Owned by `run_exec_pty` — this field is only for the resize lookup.
    pty_master_fd: i32,
    /// Per-session backpressure flag. When true, the exec thread disables
    /// POLLIN on stdout/stderr fds, causing the child to block on `write()`.
    paused: Arc<AtomicBool>,
}

/// Send a batch of outgoing guest messages, flushing any backpressure buffer first.
fn send_outgoing_batch(
    transport: &RingTransport,
    outgoing_buf: &mut std::collections::VecDeque<GuestMessage>,
    first: GuestMessage,
    rx: &mut mpsc::Receiver<GuestMessage>,
    gh_last_pct: &mut u8,
) {
    flush_outgoing_buf(transport, outgoing_buf, gh_last_pct);

    match transport.try_send(&first) {
        Ok(true) => {}
        Ok(false) => {
            outgoing_buf.push_back(first);
            transport.kick();
            match transport.gh_usage() {
                Ok((used, cap)) => check_ring_usage(
                    "GH (guest→host)",
                    used,
                    cap,
                    gh_last_pct,
                    outgoing_buf.len(),
                ),
                Err(e) => eprintln!("ring: GH usage failed: {e}"),
            }
            return;
        }
        Err(e) => {
            eprintln!("ring: send failed: {e}");
            return;
        }
    }

    while let Ok(m) = rx.try_recv() {
        match transport.try_send(&m) {
            Ok(true) => {}
            Ok(false) => {
                outgoing_buf.push_back(m);
                break;
            }
            Err(_) => break,
        }
    }

    transport.kick();
    match transport.gh_usage() {
        Ok((used, cap)) => check_ring_usage(
            "GH (guest→host)",
            used,
            cap,
            gh_last_pct,
            outgoing_buf.len(),
        ),
        Err(e) => eprintln!("ring: GH usage failed: {e}"),
    }
}

/// Start the ring-buffer-based control loop.
///
/// Spawns a reader/writer task using the vport for host↔guest kick
/// notifications and the shared ring buffer for message data.
fn start_ring_control_loop(
    transport: RingTransport,
    enable_psi: bool,
) -> mpsc::Sender<GuestMessage> {
    let (tx, mut rx) = mpsc::channel::<GuestMessage>(256);

    // Combined reader/writer task over ring buffer
    let echo_tx = tx.clone();
    tokio::spawn(async move {
        let mut transport = transport;
        set_nonblocking(transport.vport_raw_fd());
        let vport_async = match
            // SAFETY: vport File is valid and owned by RingTransport which outlives this task.
            AsyncFd::new(unsafe { BorrowedFd::borrow_raw(transport.vport_raw_fd()) })
        {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("FATAL: AsyncFd(vport): {e}");
                return;
            }
        };

        // PSI memory pressure monitor (None if disabled or unavailable)
        let mut psi = if enable_psi { PsiMonitor::new() } else { None };

        // Per-session stdin senders for programmatic exec
        let mut exec_senders: HashMap<ExecId, ExecSender> = HashMap::new();
        // Inline cat sessions — echoed directly in dispatch without thread hops.
        let mut cat_sessions: HashSet<ExecId> = HashSet::new();

        // Cleanup channel: spawn_blocking tasks send exec IDs here when done,
        // so exec_senders entries don't leak.
        let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<ExecId>(256);

        // Outgoing buffer for GH ring backpressure (messages that couldn't
        // be written because the ring was full).
        let mut outgoing_buf: std::collections::VecDeque<GuestMessage> =
            std::collections::VecDeque::new();

        // Ring utilization tracking for rate-limited warnings.
        // Tracks the last-seen percentage bucket to avoid spamming kmsg.
        let mut gh_last_pct: u8 = 0;
        let mut hg_last_pct: u8 = 0;

        // Drain any HG ring messages that arrived before the control loop
        // started (e.g., host sent Exec while guest was still booting).
        ring_dispatch_messages(
            &mut transport,
            &echo_tx,
            &mut exec_senders,
            &mut cat_sessions,
            &cleanup_tx,
            &mut outgoing_buf,
        );
        flush_outgoing_buf(&transport, &mut outgoing_buf, &mut gh_last_pct);

        loop {
            tokio::select! {
                biased;

                // Host-to-guest: vport becomes readable (kick from host)
                result = vport_async.readable() => {
                    let Ok(mut guard) = result else { continue };

                    // Consume kick bytes (non-blocking read)
                    let mut buf = [0u8; 64];
                    // SAFETY: `vport_async` borrows the vport OwnedFd from
                    // `transport`, which outlives this task; `buf` has
                    // `buf.len()` bytes writable.
                    let _n = unsafe {
                        libc::read(vport_async.get_ref().as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
                    };
                    guard.clear_ready();

                    // Drain all available messages from the HG ring
                    ring_dispatch_messages(
                        &mut transport,
                        &echo_tx,
                        &mut exec_senders,
                        &mut cat_sessions,
                        &cleanup_tx,
                        &mut outgoing_buf,
                    );

                    // Flush buffered outgoing (host may have freed GH space)
                    flush_outgoing_buf(&transport, &mut outgoing_buf, &mut gh_last_pct);

                    // Re-poll: the host may have already written new HG data in
                    // response to our GH flush. Processing it now avoids waiting
                    // for the next vport kick (saves a full VM exit round-trip).
                    ring_dispatch_messages(
                        &mut transport,
                        &echo_tx,
                        &mut exec_senders,
                        &mut cat_sessions,
                        &cleanup_tx,
                        &mut outgoing_buf,
                    );
                    flush_outgoing_buf(&transport, &mut outgoing_buf, &mut gh_last_pct);

                    // Check HG ring after draining — if it was near-full, the
                    // host may be producing faster than we can consume.
                    match transport.hg_usage() {
                        Ok((hg_used, hg_cap)) => {
                            check_ring_usage("HG (host→guest)", hg_used, hg_cap, &mut hg_last_pct, 0);
                        }
                        Err(e) => eprintln!("ring: HG usage failed: {e}"),
                    }
                }

                // Exec cleanup: remove completed exec sessions
                Some(id) = cleanup_rx.recv() => {
                    exec_senders.remove(&id);
                }

                // PSI memory pressure check (every 1s, if enabled)
                _ = async {
                    match psi.as_mut() {
                        Some(p) => p.interval.tick().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(ref mut p) = psi
                        && let Some(msg) = p.check()
                    {
                        outgoing_buf.push_back(msg);
                        flush_outgoing_buf(&transport, &mut outgoing_buf, &mut gh_last_pct);
                        transport.kick();
                    }
                }

                // Outgoing messages from internal channels (batched)
                msg = rx.recv() => {
                    match msg {
                        Some(first) => {
                            send_outgoing_batch(&transport, &mut outgoing_buf, first, &mut rx, &mut gh_last_pct);
                        }
                        None => break,
                    }
                }
            }
        }
    });

    tx
}

/// Drain all messages from the HG ring and dispatch them.
///
/// Inline responses (`@builtin:echo`, `SetOnlineCpus`) are pushed directly
/// into `outgoing_buf` — the ring transport's backpressure buffer. The caller
/// flushes this buffer to the ring after dispatch returns. This avoids routing
/// through the mpsc channel (which would deadlock under backpressure since the
/// producer and consumer are in the same task).
#[allow(clippy::too_many_lines)]
fn ring_dispatch_messages(
    transport: &mut RingTransport,
    echo_tx: &mpsc::Sender<GuestMessage>,
    exec_senders: &mut HashMap<ExecId, ExecSender>,
    cat_sessions: &mut HashSet<ExecId>,
    cleanup_tx: &mpsc::Sender<ExecId>,
    outgoing_buf: &mut std::collections::VecDeque<GuestMessage>,
) {
    loop {
        let msg = match transport.try_recv() {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(e) => {
                eprintln!("ring: recv error: {e}");
                break;
            }
        };

        match msg {
            HostMessage::Shutdown => {
                eprintln!("control: received Shutdown");
                transport::vm_exit(0);
            }
            HostMessage::Pong
            | HostMessage::Ok
            | HostMessage::Error { .. }
            | HostMessage::Setup(_) => {}
            HostMessage::Exec { id, argv, env, cwd } => {
                kmsg_fmt(format_args!(
                    "exec id={id} argv={argv:?} env_len={} cwd={cwd:?}",
                    env.len()
                ));

                let cmd = argv.first().map(String::as_str);
                if cmd == Some("@builtin:echo") {
                    let text = argv[1..].join(" ");
                    let mut data = text.into_bytes();
                    data.push(b'\n');
                    outgoing_buf.push_back(GuestMessage::ExecStdout { id, data });
                    outgoing_buf.push_back(GuestMessage::ExecExit { id, code: 0 });
                } else if cmd == Some("@builtin:cat") {
                    cat_sessions.insert(id);
                } else {
                    spawn_exec(id, argv, env, cwd, exec_senders, echo_tx, cleanup_tx);
                }
            }
            HostMessage::ExecStdin { id, data } => {
                if cat_sessions.contains(&id) {
                    // Inline echo — no thread hop, data goes directly to outgoing buffer.
                    outgoing_buf.push_back(GuestMessage::ExecStdout { id, data });
                } else if let Some(sender) = exec_senders.get(&id) {
                    if let Err(e) = sender.tx.send(Some(data)) {
                        eprintln!("exec {id}: forwarding ExecStdin failed (thread gone?): {e}");
                    }
                    if sender.wake_fd >= 0 {
                        // SAFETY: `sender.wake_fd` is a valid eventfd owned by the exec thread.
                        unsafe { libc::eventfd_write(sender.wake_fd, 1) };
                    }
                }
            }
            HostMessage::ExecStdinEof { id } => {
                if cat_sessions.remove(&id) {
                    outgoing_buf.push_back(GuestMessage::ExecExit { id, code: 0 });
                } else if let Some(sender) = exec_senders.get(&id) {
                    if let Err(e) = sender.tx.send(None) {
                        eprintln!("exec {id}: forwarding ExecStdinEof failed (thread gone?): {e}");
                    }
                    if sender.wake_fd >= 0 {
                        // SAFETY: `sender.wake_fd` is a valid eventfd owned by the exec thread.
                        unsafe { libc::eventfd_write(sender.wake_fd, 1) };
                    }
                }
            }
            HostMessage::SetOnlineCpus { count } => {
                let result = set_online_cpus(count);
                outgoing_buf.push_back(result);
            }
            HostMessage::MemoryAdded { total_mb } => {
                kmsg_fmt(format_args!("memory added: total={total_mb}MB"));
            }
            HostMessage::ExecPty { id, argv, env, cwd } => {
                kmsg_fmt(format_args!(
                    "exec_pty id={id} argv={argv:?} env_len={} cwd={cwd:?}",
                    env.len()
                ));
                spawn_exec_pty(
                    id,
                    argv,
                    env,
                    cwd,
                    exec_senders,
                    echo_tx,
                    cleanup_tx,
                    outgoing_buf,
                );
            }
            HostMessage::SessionResize { id, rows, cols } => {
                if let Some(sender) = exec_senders.get(&id)
                    && sender.pty_master_fd >= 0
                {
                    let ws = libc::winsize {
                        ws_row: rows,
                        ws_col: cols,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    // SAFETY: `sender.pty_master_fd` is an openpty() master fd
                    // owned by this sender; `&ws` points to a valid winsize.
                    let ret = unsafe { libc::ioctl(sender.pty_master_fd, libc::TIOCSWINSZ, &ws) };
                    if ret != 0 {
                        kmsg_fmt(format_args!(
                            "SessionResize id={id} ioctl failed: {}",
                            io::Error::last_os_error()
                        ));
                    }
                }
            }
            HostMessage::PauseExecOutput { id } => {
                if let Some(sender) = exec_senders.get(&id) {
                    sender.paused.store(true, Ordering::Relaxed);
                    if sender.wake_fd >= 0 {
                        // SAFETY: `sender.wake_fd` is a valid eventfd owned by the exec thread.
                        unsafe { libc::eventfd_write(sender.wake_fd, 1) };
                    }
                }
            }
            HostMessage::ResumeExecOutput { id } => {
                if let Some(sender) = exec_senders.get(&id) {
                    sender.paused.store(false, Ordering::Relaxed);
                    if sender.wake_fd >= 0 {
                        // SAFETY: `sender.wake_fd` is a valid eventfd owned by the exec thread.
                        unsafe { libc::eventfd_write(sender.wake_fd, 1) };
                    }
                }
            }
        }
    }
}

/// Set the number of online CPUs by writing to sysfs.
///
/// CPU 0 is always online (kernel won't allow offlining it).
/// For CPUs 1..max: online if index < count, offline otherwise.
fn set_online_cpus(count: u32) -> GuestMessage {
    let count = count.max(1); // CPU 0 is always on

    // Discover max CPU index from sysfs
    let max_cpu = match fs::read_to_string("/sys/devices/system/cpu/possible") {
        Ok(s) => {
            // Format: "0-N" or "0"
            s.trim()
                .rsplit('-')
                .next()
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap_or(0)
        }
        Err(e) => {
            return GuestMessage::CpuOnlineResult {
                count: 0,
                error: Some(format!("read possible: {e}")),
            };
        }
    };

    let mut errors = Vec::new();
    for cpu in 1..=max_cpu {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/online");
        let value = if cpu < count { "1" } else { "0" };
        if let Err(e) = fs::write(&path, value) {
            errors.push(format!("cpu{cpu}: {e}"));
        }
    }

    #[allow(clippy::cast_possible_truncation)] // CPU count always fits u32
    let actual = (1..=max_cpu)
        .filter(|cpu| {
            fs::read_to_string(format!("/sys/devices/system/cpu/cpu{cpu}/online"))
                .is_ok_and(|s| s.trim() == "1")
        })
        .count() as u32
        + 1; // +1 for CPU 0

    GuestMessage::CpuOnlineResult {
        count: actual,
        error: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
    }
}

// =============================================================================
// PSI Memory Pressure Monitor
// =============================================================================

/// Parse `MemAvailable` and `MemTotal` from `/proc/meminfo`.
///
/// Returns `(available_kb, total_kb)` or `None` if the file can't be read
/// or the fields are missing.
fn parse_meminfo() -> Option<(u64, u64)> {
    let contents = fs::read_to_string("/proc/meminfo").ok()?;
    let mut available = None;
    let mut total = None;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = rest
                .trim()
                .strip_suffix("kB")
                .and_then(|s| s.trim().parse().ok());
        } else if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest
                .trim()
                .strip_suffix("kB")
                .and_then(|s| s.trim().parse().ok());
        }
        if available.is_some() && total.is_some() {
            break;
        }
    }
    Some((available?, total?))
}

/// Parse `total=<N>` from the `some` line of `/proc/pressure/memory`.
///
/// Returns the cumulative stall time in microseconds, or `None` if
/// the file can't be read or parsed.
fn read_psi_total_us() -> Option<u64> {
    let path = b"/proc/pressure/memory\0";
    // SAFETY: `path` is a NUL-terminated byte string.
    let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 256];
    // SAFETY: `fd` is a valid OS fd; `buf` has `buf.len()` bytes writable.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    // SAFETY: `fd` is a valid OS fd owned by this scope.
    unsafe { libc::close(fd) };
    if n <= 0 {
        return None;
    }
    // Format: "some avg10=X avg60=X avg300=X total=<N>\nfull ...\n"
    #[allow(clippy::cast_sign_loss)]
    let s = core::str::from_utf8(&buf[..n as usize]).ok()?;
    for line in s.lines() {
        if line.starts_with("some ")
            && let Some(pos) = line.find("total=")
        {
            return line[pos + 6..].split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// State for the PSI memory pressure monitor.
///
/// Checks `/proc/pressure/memory` on a timer from within the tokio runtime.
/// Running inside tokio (vs. a dedicated OS thread) avoids thread starvation
/// on single-vCPU VMs under heavy memory pressure, where the kernel scheduler
/// may not wake a sleeping OS thread for extended periods.
struct PsiMonitor {
    prev_total: u64,
    interval: tokio::time::Interval,
}

impl PsiMonitor {
    fn new() -> Option<Self> {
        let baseline = read_psi_total_us()?;
        kmsg_fmt(format_args!("psi: monitor active (baseline={baseline}us)"));
        Some(Self {
            prev_total: baseline,
            interval: tokio::time::interval(std::time::Duration::from_secs(1)),
        })
    }

    /// Check for new memory pressure. Returns a `GuestMessage` if the stall
    /// delta exceeds the threshold since the last check.
    fn check(&mut self) -> Option<GuestMessage> {
        // Threshold: 500us of new stall time per sample.
        const STALL_THRESHOLD_US: u64 = 500;

        let total = read_psi_total_us()?;
        let delta = total.saturating_sub(self.prev_total);
        self.prev_total = total;

        if delta < STALL_THRESHOLD_US {
            return None;
        }

        // parse_meminfo() heap-allocates via read_to_string — under extreme
        // memory pressure it can fail. Use fallback values rather than
        // silently dropping the pressure event (prev_total is already advanced,
        // so the delta would be lost).
        let (available_kb, total_kb) = parse_meminfo().unwrap_or((0, 0));
        kmsg_fmt(format_args!(
            "psi: pressure detected (delta={delta}us), \
             available={available_kb}KB total={total_kb}KB"
        ));

        Some(GuestMessage::MemoryPressure {
            level: 0,
            available_kb,
            total_kb,
        })
    }
}

// =============================================================================
// Boot checkpoint timing
// =============================================================================

/// No-op boot checkpoint. Enable `AMLA_BOOT_TRACE=1` for full timing.
#[inline]
const fn ckpt(_step: &str) {}

// =============================================================================
// Main
// =============================================================================

#[allow(clippy::too_many_lines, clippy::expect_used)]
pub fn run() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(run_async());
}

#[allow(clippy::too_many_lines)]
async fn run_async() {
    let is_pid_1 = std::process::id() == 1;

    // 1. Mount essential filesystems (PID 1 responsibility only)
    if is_pid_1 {
        mount_essential_filesystems();
    }

    // 2. Bring up networking (needs /sys from step 1)
    if is_pid_1 {
        setup_network();
    }

    // 3. Ring buffer handshake
    let (transport, setup) = ring_handshake();
    ckpt("ring_handshake_done");

    // 4. Process mount instructions from host (pmem, virtiofs, overlays)
    process_mounts(&setup.mounts);
    ckpt("host_mounts_done");

    // 5. Ignore SIGPIPE process-wide (exec may write to closed pipes).
    //    Must happen BEFORE the control loop starts spawning exec handlers.
    if is_pid_1 {
        // SAFETY: SIG_IGN is async-signal-safe; SIGPIPE is a valid signal number.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
    }

    // 6. Start ring buffer control loop (PSI monitor disabled — CONFIG_PSI
    //    removed from guest kernel, /proc/pressure/memory not available).
    let _tx = start_ring_control_loop(transport, false);

    // 8. Block forever — spawned tasks handle all I/O.
    std::future::pending::<()>().await;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_meminfo_returns_values() {
        // This test runs on the host (Linux), where /proc/meminfo exists.
        let result = parse_meminfo();
        assert!(
            result.is_some(),
            "parse_meminfo should return Some on Linux"
        );
        let (available, total) = result.unwrap();
        assert!(total > 0, "total memory should be > 0");
        assert!(available <= total, "available should be <= total");
    }
}
