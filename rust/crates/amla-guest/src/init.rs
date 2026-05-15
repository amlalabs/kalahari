//! Container namespace holder with Wayland compositor.
//!
//! Sets up an OCI container namespace (overlay, `pivot_root`, /proc mount)
//! and runs a Wayland compositor inside the container PID namespace.
//!
//! Architecture:
//!   Parent (daemon's stdin/stdout):
//!     - Waits for child's ready signal
//!     - Forwards display pipe → stdout (compositor frames to daemon)
//!     - Forwards stdin → input pipe (browser input to compositor)
//!   Child (PID 1 in container namespace):
//!     - Namespace setup, `pivot_root`, mounts
//!     - Creates Wayland compositor
//!     - Runs compositor event loop
//!     - Spawns CMD (Chrome) as grandchild
//!   Grandchild (Chrome):
//!     - stdio redirected to /dev/null
//!     - Connects to compositor via `WAYLAND_DISPLAY`
//!
//! Usage: `amla-init <name> --config <json>`

use std::ffi::CString;
use std::fs;
use std::os::fd::AsRawFd;

use crate::oci::{self, OciConfig, cstr};

const CONTAINER_STATE: &str = "/run/containers";

/// Run the init subcommand. Returns exit code.
pub fn run(args: &[String]) -> i32 {
    // Ensure panics are visible in daemon logs via stderr.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("PANIC: {info}");
    }));

    match run_inner(args) {
        Ok(()) => 0,
        Err(msg) => {
            eprintln!("amla-init: {msg}");
            1
        }
    }
}

// OCI config parsing is in crate::oci (shared with exec).

// ─── CMD spawn ──────────────────────────────────────────────────────────

/// Fork and exec the OCI CMD process. Returns the child pid, or 0 if no CMD.
///
/// The grandchild redirects stdio to /dev/null so Chrome cannot corrupt the
/// compositor's display pipe. Pipe fds have `O_CLOEXEC` and auto-close on exec.
/// Reads env vars from `/run/container-env` (written by `write_resolved_env`).
fn spawn_cmd(config: &OciConfig) -> libc::pid_t {
    if config.args.is_empty() {
        return 0;
    }

    // SAFETY: fork has no preconditions.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("amla-init: fork CMD: {}", std::io::Error::last_os_error());
        return -1;
    }
    if pid > 0 {
        return pid;
    }

    // Grandchild: redirect stdio to /dev/null before exec.
    // SAFETY: post-fork grandchild; single-threaded per POSIX until exec.
    // close(0/1/2) close stdio fds we own; `devnull` is a live CString so
    // `devnull.as_ptr()` is a NUL-terminated string; dup2 takes valid fds.
    unsafe {
        libc::close(0);
        libc::close(1);
        libc::close(2);
        let devnull = cstr("/dev/null");
        libc::open(devnull.as_ptr(), libc::O_RDWR); // fd 0
        libc::dup2(0, 1); // fd 1
        libc::dup2(0, 2); // fd 2
    }

    // Load env from /run/container-env (single source of truth).
    if let Ok(data) = fs::read_to_string("/run/container-env") {
        for line in data.lines() {
            if let Some(eq) = line.find('=') {
                // SAFETY: single-threaded guest init — no concurrent env access.
                unsafe { std::env::set_var(&line[..eq], &line[eq + 1..]) };
            }
        }
    }

    if let Err(e) = std::env::set_current_dir(&config.cwd) {
        eprintln!("amla-init: set_current_dir {:?}: {e}", config.cwd);
    }

    // Drop capabilities to the Docker-default set and enable NoNewPrivs
    // BEFORE setuid. `PR_CAPBSET_DROP` needs `CAP_SETPCAP` which setuid to
    // a non-zero uid strips, so the order matters.
    if let Err(e) = crate::hardening::drop_to_container_caps() {
        eprintln!("amla-init: drop caps: {e}");
    }

    // SAFETY: post-fork grandchild; setgid/setuid take integer ids and have
    // no pointer preconditions.
    unsafe {
        libc::setgid(config.gid);
        libc::setuid(config.uid);
    }

    let c_args: Vec<CString> = config.args.iter().map(|a| cstr(a)).collect();
    let mut c_ptrs: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
    c_ptrs.push(std::ptr::null());
    // SAFETY: `c_ptrs` is NULL-terminated and every non-null entry points into
    // a live CString kept alive by `c_args`. _exit has no preconditions.
    unsafe {
        libc::execvp(c_ptrs[0], c_ptrs.as_ptr());
        libc::_exit(127);
    }
}

// ─── main logic ─────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn run_inner(args: &[String]) -> Result<(), String> {
    let parsed = parse_args(args)?;
    let name = parsed.name;
    oci::validate_name(&name)?;

    // /mnt is already a writable overlay (PID 1 agent set it up).
    // Prepare it for pivot_root.
    let merged = "/mnt";
    let pivot_old_dir = format!("{merged}/.pivot_old");
    fs::create_dir_all(&pivot_old_dir)
        .map_err(|e| format!("create_dir_all {pivot_old_dir}: {e}"))?;

    // Ensure host /etc files exist, then inject into the container overlay.
    ensure_etc_files();
    inject_host_etc(merged, &name);

    // Create state directory and write config for amla-exec.
    let state_dir = std::path::Path::new(CONTAINER_STATE).join(&name);
    fs::create_dir_all(&state_dir).map_err(|e| format!("mkdir state: {e}"))?;
    fs::write(state_dir.join("config.json"), &parsed.config)
        .map_err(|e| format!("write config: {e}"))?;

    // New session so we don't get terminal signals.
    // SAFETY: setsid has no preconditions (beyond that the caller not already
    // be a process-group leader, which we aren't at this point).
    unsafe { libc::setsid() };

    // Create pipes for parent↔child communication.
    // display: child writes compositor frames → parent forwards to stdout
    // input:   parent forwards stdin → child reads browser input
    // ready:   child signals compositor is listening → parent writes READY
    let (display_read, display_write) = pipe_cloexec()?;
    let (input_read, input_write) = pipe_cloexec()?;
    let (ready_read, ready_write) = pipe_cloexec()?;

    // Create PID namespace. This only affects children — the calling process
    // stays in the parent PID namespace. We fork below so the child becomes
    // PID 1 in the new namespace.
    // SAFETY: flags is a valid CLONE_NEW* constant; caller has CAP_SYS_ADMIN.
    if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
        return Err(format!(
            "unshare NEWPID: {}",
            std::io::Error::last_os_error()
        ));
    }

    // SAFETY: fork has no preconditions.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if child_pid > 0 {
        // ── Parent: bridge daemon stdio ↔ child pipes ─────────────
        // SAFETY: these fds are raw pipe fds from `pipe_cloexec` owned by this
        // process — parent closes its child-side copies.
        unsafe {
            libc::close(display_write);
            libc::close(input_read);
            libc::close(ready_write);
        }

        fs::write(state_dir.join("pid"), child_pid.to_string())
            .map_err(|e| format!("write pid: {e}"))?;

        // Block until compositor is ready.
        let mut ready_byte = [0u8; 1];
        // SAFETY: `ready_read` is a valid OS fd; `ready_byte` has 1 byte of writable memory.
        unsafe { libc::read(ready_read, ready_byte.as_mut_ptr().cast(), 1) };
        // SAFETY: `ready_read` is a valid OS fd owned by this scope.
        unsafe { libc::close(ready_read) };

        // Signal readiness to daemon (stdout is for frames, use stderr). Use
        // one write syscall so the marker is not fragmented across guest-side
        // stderr writers.
        write_ready_marker(child_pid);

        // Forward data: stdin→input_write, display_read→stdout.
        parent_forward_loop(display_read, input_write);
        eprintln!("parent: forward loop exited");

        // Tear down.
        // SAFETY: display_read/input_write are valid OS fds owned by the parent;
        // kill takes a pid and signal; waitpid accepts NULL for status.
        unsafe {
            libc::close(display_read);
            libc::close(input_write);
            libc::kill(child_pid, libc::SIGKILL);
            libc::waitpid(child_pid, std::ptr::null_mut(), 0);
        }
        return Ok(());
    }

    // ── Child: PID 1 in container namespace ───────────────────────────
    // SAFETY: post-fork child; these fds are valid OS fds owned by this scope.
    unsafe {
        libc::close(display_read);
        libc::close(input_write);
        libc::close(ready_read);
        // Close daemon's stdio — parent owns those.
        libc::close(0);
        libc::close(1);
    }

    // Unshare mount/IPC/UTS in the child only, so parent's mount namespace
    // is not affected by our pivot_root below.
    let ns_flags = libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    // SAFETY: flags is a valid CLONE_NEW* bitmask; caller has CAP_SYS_ADMIN.
    if unsafe { libc::unshare(ns_flags) } != 0 {
        return Err(format!("unshare: {}", std::io::Error::last_os_error()));
    }

    // Set hostname in the new UTS namespace.
    let hostname = cstr(&name);
    // SAFETY: `hostname` is a live CString; `name.len()` matches its payload.
    unsafe { libc::sethostname(hostname.as_ptr(), name.len()) };

    // Make all mounts private.
    let none = cstr("none");
    let slash = cstr("/");
    // SAFETY: `none`/`slash` are live CStrings; filesystemtype and data are NULL
    // (allowed when flags include MS_PRIVATE); caller has CAP_SYS_ADMIN.
    if unsafe {
        libc::mount(
            none.as_ptr(),
            slash.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(format!(
            "mount private: {}",
            std::io::Error::last_os_error()
        ));
    }

    // pivot_root directly into /mnt (already a writable overlay from PID 1).
    let merged_c = cstr(merged);
    let pivot_old =
        CString::new(format!("{merged}/.pivot_old")).map_err(|e| format!("CString: {e}"))?;

    // SAFETY: both paths are NUL-terminated CStrings; caller has CAP_SYS_ADMIN
    // in the current user namespace.
    if unsafe { libc::syscall(libc::SYS_pivot_root, merged_c.as_ptr(), pivot_old.as_ptr()) } != 0 {
        return Err(format!("pivot_root: {}", std::io::Error::last_os_error()));
    }

    if let Err(e) = std::env::set_current_dir("/") {
        eprintln!("amla-init: set_current_dir /: {e}");
    }

    // Bind-mount the VM root into the container so users can inspect
    // overlay layers, EROFS images, and guest mounts from inside.
    if let Err(e) = fs::create_dir_all("/run/vm-root") {
        eprintln!("amla-init: create_dir_all /run/vm-root: {e}");
    }
    {
        let src = cstr("/.pivot_old");
        let dst = cstr("/run/vm-root");
        let flags = libc::MS_BIND | libc::MS_REC;
        // SAFETY: `src`/`dst` are live CStrings; filesystemtype and data are
        // NULL (allowed for MS_BIND); caller has CAP_SYS_ADMIN.
        if unsafe {
            libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        } != 0
        {
            eprintln!(
                "amla-init: warning: rbind vm-root: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // Unmount old root.
    let old_mount = cstr("/.pivot_old");
    // SAFETY: `old_mount` is a live CString; umount2/rmdir take NUL-terminated
    // path strings.
    unsafe {
        libc::umount2(old_mount.as_ptr(), libc::MNT_DETACH);
        libc::rmdir(old_mount.as_ptr());
    }

    // Mount essential filesystems.
    do_mount("proc", "/proc", "proc", 0, None)?;

    // Minimal tmpfs /dev instead of the full host devtmpfs: a container must
    // not reach /dev/mem, /dev/kmem, /dev/pmem*, /dev/vport*, /dev/vsock,
    // /dev/hvc*, /dev/kmsg, etc. — all of which are legitimately present in
    // the VM's devtmpfs but break the host↔guest boundary if exposed to
    // container userspace. `populate_container_dev` mknods only the standard
    // container device nodes plus GPU/input/fuse mirrored from the VM.
    do_mount(
        "tmpfs",
        "/dev",
        "tmpfs",
        libc::MS_NOSUID,
        Some("mode=0755,size=65536k"),
    )?;
    crate::hardening::populate_container_dev()?;

    if let Err(e) = do_mount(
        "devpts",
        "/dev/pts",
        "devpts",
        0,
        Some("newinstance,ptmxmode=0666"),
    ) {
        eprintln!("amla-init: warning: {e}");
    }
    if let Err(e) = do_mount("sysfs", "/sys", "sysfs", libc::MS_RDONLY, None) {
        eprintln!("amla-init: warning: {e}");
    }
    if let Err(e) = do_mount("tmpfs", "/dev/shm", "tmpfs", 0, None) {
        eprintln!("amla-init: warning: {e}");
    }

    // Hide the VM's devtmpfs that was exposed via the earlier /run/vm-root
    // rbind. Without this overmount, the container could still reach
    // /run/vm-root/dev/mem, /run/vm-root/dev/pmem*, etc. This is a security
    // boundary — refuse to start the container if the overmount fails.
    do_mount(
        "tmpfs",
        "/run/vm-root/dev",
        "tmpfs",
        libc::MS_NOSUID,
        Some("mode=0755,size=16k"),
    )
    .map_err(|e| format!("overmount /run/vm-root/dev (security boundary): {e}"))?;

    // Parse OCI config now that /etc/passwd is available for user resolution.
    let mut config = oci::parse_oci_config(&parsed.config)?;
    oci::resolve_named_user(&mut config)?;

    // Create XDG_RUNTIME_DIR for the target user (compositor socket lives here).
    // fs::create_dir() AlreadyExists is fine — the agent may have pre-created
    // these on the tmpfs, or a previous container set them up.
    let xdg_dir = format!("/run/user/{}", config.uid);
    for path in ["/run", "/run/user", xdg_dir.as_str()] {
        if let Err(e) = fs::create_dir(path)
            && e.kind() != std::io::ErrorKind::AlreadyExists
        {
            eprintln!("amla-init: create_dir {path}: {e}");
        }
    }
    if let Err(e) = fs::set_permissions(
        &xdg_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    ) {
        eprintln!("amla-init: set_permissions {xdg_dir}: {e}");
    }
    // SAFETY: `cstr(&xdg_dir)` returns a CString kept alive for the full
    // statement; chown takes a NUL-terminated path and integer uid/gid.
    unsafe { libc::chown(cstr(&xdg_dir).as_ptr(), config.uid, config.gid) };

    // Write resolved env vars to state dir so amla-exec can read them.
    // This is the single source of truth for container environment.
    write_resolved_env(&config, &xdg_dir);

    // Create Wayland compositor.
    let socket_path = format!("{xdg_dir}/wayland-0");
    let mut compositor =
        crate::wayland::Compositor::new(&socket_path).map_err(|e| format!("compositor: {e}"))?;

    // Signal ready to parent.
    // SAFETY: `ready_write` is a valid OS fd; the 1-byte buffer lives for the
    // duration of the write; close takes a valid fd.
    unsafe {
        libc::write(ready_write, [1u8].as_ptr().cast(), 1);
        libc::close(ready_write);
    }

    // Install SIGCHLD handler so poll() wakes on child exit.
    // SAFETY: `sigaction` is an all-zero-valid POD; `noop_handler` is an
    // extern "C" fn with correct signature; old-handler out-pointer is NULL.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = noop_handler as *const () as usize;
        sa.sa_flags = libc::SA_NOCLDSTOP;
        libc::sigaction(libc::SIGCHLD, &raw const sa, std::ptr::null_mut());
    }

    // Run compositor event loop (spawns and manages Chrome).
    run_compositor_loop(&mut compositor, display_write, input_read, &config);

    // SAFETY: both fds are valid OS fds owned by this scope.
    unsafe {
        libc::close(display_write);
        libc::close(input_read);
    }

    Ok(())
}

fn write_ready_marker(child_pid: libc::pid_t) {
    let marker = format!("READY {child_pid}\n");
    // SAFETY: `marker.as_ptr()` points to `marker.len()` initialized bytes for
    // the duration of the call; fd 2 is stderr by process convention. A single
    // write smaller than PIPE_BUF is atomic when stderr is backed by a pipe.
    let _ = unsafe { libc::write(2, marker.as_ptr().cast(), marker.len()) };
}

// ─── Parent forwarding loop ──────────────────────────────────────────────

/// Forward data between daemon stdio and child pipes.
/// stdin → `input_write` (browser input to compositor)
/// `display_read` → stdout (compositor frames to daemon)
fn parent_forward_loop(display_read: libc::c_int, input_write: libc::c_int) {
    let mut buf = vec![0u8; 65536];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: display_read,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // SAFETY: `fds` points to 2 pollfd entries for the duration of the call.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if ret < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        // stdin → input_write
        if fds[0].revents & libc::POLLIN != 0 {
            // SAFETY: fd 0 is stdin (valid); `buf` has `buf.len()` bytes writable.
            let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            #[allow(clippy::cast_sign_loss)]
            write_all_fd(input_write, &buf[..n as usize]);
        }
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0
            && fds[0].revents & libc::POLLIN == 0
        {
            break;
        }

        // display_read → stdout
        if fds[1].revents & libc::POLLIN != 0 {
            // SAFETY: `display_read` is a valid OS fd; `buf` has `buf.len()` bytes writable.
            let n = unsafe { libc::read(display_read, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                eprintln!("parent: display_read EOF/error (n={n})");
                break;
            }
            #[allow(clippy::cast_sign_loss)]
            write_all_fd(1, &buf[..n as usize]);
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0
            && fds[1].revents & libc::POLLIN == 0
        {
            eprintln!("parent: display_read HUP");
            break;
        }
    }
}

// ─── Compositor event loop ───────────────────────────────────────────────

/// Poll wayland fds + input pipe, dispatch events, write frames to display pipe.
#[allow(clippy::cast_sign_loss)]
fn run_compositor_loop(
    compositor: &mut crate::wayland::Compositor,
    display_fd: libc::c_int,
    input_fd: libc::c_int,
    config: &OciConfig,
) {
    // Set input fd non-blocking for poll.
    // SAFETY: `input_fd` is a valid OS fd; F_GETFL/F_SETFL take an int flags arg.
    unsafe {
        let flags = libc::fcntl(input_fd, libc::F_GETFL);
        libc::fcntl(input_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let listen_raw = compositor.listen_fd().as_raw_fd();
    let poll_raw = compositor.poll_fd().as_raw_fd();

    let mut input_buf = Vec::new();
    let mut read_buf = [0u8; 4096];
    let mut cmd_pid = spawn_cmd(config);

    loop {
        let mut fds = [
            libc::pollfd {
                fd: input_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: listen_raw,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: poll_raw,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // 16ms timeout ≈ 60fps — used to throttle frame callbacks.
        // SAFETY: `fds` points to 3 pollfd entries for the duration of the call.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 3, 16) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                break;
            }
            // EINTR from SIGCHLD — fall through to reap below
        }

        // Browser input (JSON text lines from daemon via parent).
        if fds[0].revents & libc::POLLIN != 0 {
            // SAFETY: `input_fd` is a valid OS fd; `read_buf` has `read_buf.len()` bytes writable.
            let n = unsafe { libc::read(input_fd, read_buf.as_mut_ptr().cast(), read_buf.len()) };
            if n > 0 {
                input_buf.extend_from_slice(&read_buf[..n as usize]);
                process_input_lines(compositor, &mut input_buf);
            }
        }
        if fds[0].revents & libc::POLLHUP != 0 && fds[0].revents & libc::POLLIN == 0 {
            break; // Input pipe closed — daemon disconnected.
        }

        // Wayland: new client connection.
        if fds[1].revents & libc::POLLIN != 0 {
            compositor.accept();
        }

        // Wayland: client protocol messages.
        if fds[2].revents & libc::POLLIN != 0 {
            compositor.dispatch();
        }

        // Write pending frames to display pipe (length-prefixed).
        for frame in compositor.drain_frames() {
            #[allow(clippy::cast_possible_truncation)]
            let len = (frame.len() as u32).to_le_bytes();
            write_all_fd(display_fd, &len);
            write_all_fd(display_fd, &frame);
        }

        // Throttled frame callbacks — tells Chrome it can render the next frame.
        // Fired every ~16ms (poll timeout) instead of immediately on commit.
        compositor.fire_frame_callbacks();

        // Reap zombies. As PID 1 in the container namespace, orphaned
        // processes (from amla-exec forks, etc.) are reparented to us.
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: `&mut status` via `from_mut` is a valid out-pointer.
            let pid = unsafe { libc::waitpid(-1, std::ptr::from_mut(&mut status), libc::WNOHANG) };
            if pid <= 0 {
                break;
            }
            if pid == cmd_pid && cmd_pid > 0 {
                #[allow(clippy::cast_sign_loss)]
                let code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status) as u32
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status) as u32
                } else {
                    1
                };
                eprintln!("amla-init: CMD exited with code {code}");
                cmd_pid = 0;
            }
        }
    }

    // Kill CMD on exit.
    if cmd_pid > 0 {
        // SAFETY: kill takes a pid and signal; waitpid accepts NULL for status.
        unsafe {
            libc::kill(cmd_pid, libc::SIGKILL);
            libc::waitpid(cmd_pid, std::ptr::null_mut(), 0);
        }
    }
}

/// Parse complete JSON lines from the input buffer and dispatch to compositor.
fn process_input_lines(compositor: &mut crate::wayland::Compositor, buf: &mut Vec<u8>) {
    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        if let Ok(line) = std::str::from_utf8(&buf[..pos])
            && !line.is_empty()
        {
            handle_browser_input(compositor, line);
        }
        buf.drain(..=pos);
    }
}

/// Parse a single JSON input message from the browser and dispatch.
fn handle_browser_input(compositor: &mut crate::wayland::Compositor, line: &str) {
    let val: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return,
    };

    let event_type = val.get("type").and_then(|t| t.as_str()).unwrap_or("");
    match event_type {
        "keyframe" => {
            compositor.request_keyframe();
        }
        "resize" => {
            #[allow(clippy::cast_possible_truncation)]
            let w = val
                .get("width")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            #[allow(clippy::cast_possible_truncation)]
            let h = val
                .get("height")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            compositor.set_size(w, h);
        }
        "mouse_move" => {
            let x = val
                .get("x")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0);
            let y = val
                .get("y")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0);
            compositor.inject_input(crate::wayland::InputEvent::PointerMotion { x, y });
        }
        "mouse_button" => {
            #[allow(clippy::cast_possible_truncation)]
            let button = val
                .get("button")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let pressed = val
                .get("pressed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            compositor.inject_input(crate::wayland::InputEvent::PointerButton { button, pressed });
        }
        "mouse_wheel" => {
            #[allow(clippy::cast_possible_truncation)]
            let axis = val
                .get("axis")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let value = val
                .get("value")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0);
            compositor.inject_input(crate::wayland::InputEvent::PointerAxis { axis, value });
        }
        "key" => {
            #[allow(clippy::cast_possible_truncation)]
            let keycode = val
                .get("keycode")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let pressed = val
                .get("pressed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            compositor.inject_input(crate::wayland::InputEvent::Key { keycode, pressed });
        }
        _ => {}
    }
}

// ─── argument parsing ────────────────────────────────────────────────────

struct ParsedArgs {
    name: String,
    config: String,
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    use lexopt::prelude::*;

    let mut name: Option<String> = None;
    let mut config: Option<String> = None;
    let mut parser = lexopt::Parser::from_args(args.iter().map(String::as_str));

    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Long("config") => {
                config = Some(
                    parser
                        .value()
                        .map_err(|e| format!("--config requires a value: {e}"))?
                        .into_string()
                        .map_err(|_| "--config value is not valid UTF-8".to_string())?,
                );
            }
            Value(val) if name.is_none() => {
                name = Some(
                    val.into_string()
                        .map_err(|_| "container name is not valid UTF-8".to_string())?,
                );
            }
            _ => return Err(arg.unexpected().to_string()),
        }
    }

    let name = name.ok_or("usage: amla-init <name> --config <json>")?;
    let config = config.ok_or("--config <json> is required")?;
    Ok(ParsedArgs { name, config })
}

// ─── helpers ────────────────────────────────────────────────────────────

fn do_mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), String> {
    if let Err(e) = fs::create_dir_all(target) {
        // mount() will still fail with a clearer error if the dir really
        // doesn't exist; but surfacing the underlying cause helps diagnose
        // read-only rootfs / permissions issues before the syscall.
        eprintln!("amla-init: create_dir_all {target}: {e}");
    }
    let src = cstr(source);
    let tgt = cstr(target);
    let fst = cstr(fstype);
    let data_ptr = data.map(cstr);
    // SAFETY: `src`/`tgt`/`fst` are live CStrings; `data_ptr` is either a live
    // CString ptr or NULL (via map_or); caller has CAP_SYS_ADMIN.
    let ret = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fst.as_ptr(),
            flags,
            data_ptr
                .as_ref()
                .map_or(std::ptr::null(), |d| d.as_ptr().cast()),
        )
    };
    if ret != 0 {
        return Err(format!(
            "mount {target} ({fstype}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn ensure_etc_files() {
    if !std::path::Path::new("/etc/resolv.conf").exists()
        && let Err(e) = fs::write("/etc/resolv.conf", "nameserver 8.8.8.8\n")
    {
        eprintln!("amla-init: write /etc/resolv.conf: {e}");
    }
    if !std::path::Path::new("/etc/hosts").exists()
        && let Err(e) = fs::write("/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n")
    {
        eprintln!("amla-init: write /etc/hosts: {e}");
    }
}

fn inject_host_etc(merged: &str, container_name: &str) {
    let etc = format!("{merged}/etc");
    if let Err(e) = fs::create_dir_all(&etc) {
        eprintln!("amla-init: create_dir_all {etc}: {e}");
        return;
    }

    // Copy resolv.conf from host.
    let src = "/etc/resolv.conf";
    let dst = format!("{etc}/resolv.conf");
    if let Ok(data) = fs::read(src)
        && let Err(e) = fs::write(&dst, data)
    {
        eprintln!("amla-init: write {dst}: {e}");
    }

    // Build /etc/hosts with the container hostname.
    let mut hosts = String::new();
    if let Ok(data) = fs::read_to_string("/etc/hosts") {
        hosts.push_str(&data);
    }
    if !hosts.contains(container_name) {
        use std::fmt::Write;
        // writeln! to String is infallible; matches the `let _w = write!(...)`
        // idiom used for String writes elsewhere in this guest.
        let _w = writeln!(hosts, "127.0.0.1 {container_name}");
    }
    let hosts_path = format!("{etc}/hosts");
    if let Err(e) = fs::write(&hosts_path, hosts) {
        eprintln!("amla-init: write {hosts_path}: {e}");
    }
}

/// Write the resolved environment to `/run/containers/{name}/env`.
/// amla-exec reads this file — single source of truth for container env.
fn write_resolved_env(config: &OciConfig, xdg_dir: &str) {
    let mut env = config.env.clone();

    // Ensure PATH is set.
    if !env.iter().any(|v| v.starts_with("PATH=")) {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }

    // Ensure TERM is set.
    if !env.iter().any(|v| v.starts_with("TERM=")) {
        env.push("TERM=xterm".into());
    }

    // Wayland compositor.
    if !env.iter().any(|v| v.starts_with("XDG_RUNTIME_DIR=")) {
        env.push(format!("XDG_RUNTIME_DIR={xdg_dir}"));
    }
    if !env.iter().any(|v| v.starts_with("WAYLAND_DISPLAY=")) {
        env.push("WAYLAND_DISPLAY=wayland-0".into());
    }
    if !env.iter().any(|v| v.starts_with("OZONE_PLATFORM=")) {
        env.push("OZONE_PLATFORM=wayland".into());
    }

    let mut content = env.join("\n");
    content.push('\n');
    if let Err(e) = fs::write("/run/container-env", content) {
        // amla-exec reads this file — failing here means every exec'd
        // command will run without the resolved container env.
        eprintln!("amla-init: WARNING: write /run/container-env: {e}");
    }
}

/// Create a pipe with `O_CLOEXEC` (auto-close on exec, so Chrome doesn't inherit).
fn pipe_cloexec() -> Result<(libc::c_int, libc::c_int), String> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a 2-element array; pipe2 writes both fds into it.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!("pipe2: {}", std::io::Error::last_os_error()));
    }
    Ok(fds.into())
}

/// Write all bytes to a raw fd, retrying on partial writes.
fn write_all_fd(fd: libc::c_int, data: &[u8]) {
    let mut written = 0;
    while written < data.len() {
        // SAFETY: `fd` is a valid OS fd; the slice covers `data.len() - written` bytes.
        let n = unsafe { libc::write(fd, data[written..].as_ptr().cast(), data.len() - written) };
        if n <= 0 {
            break;
        }
        #[allow(clippy::cast_sign_loss)]
        {
            written += n as usize;
        }
    }
}

const extern "C" fn noop_handler(_sig: libc::c_int) {}
