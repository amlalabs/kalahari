//! Guest-side container command execution tool.
//!
//! Runs inside KVM VMs to execute commands in OCI container namespaces.
//! Container namespace setup is handled by `amla-init`.
//!
//! # Subcommands
//!
//! - `amla-exec run <name> [--env K=V]... [-- cmd args...]` — run in container
//! - `amla-exec stop <name>` — stop and delete a container
//! - `amla-exec write-file <name> <path>` — write stdin to a file in the container (as root)
//! - `amla-exec read-file <name> <path>` — read a file from the container to stdout (as root)
//! - `amla-exec write-user-file <name> <path>` — write stdin to a file as the container user
//! - `amla-exec read-user-file <name> <path>` — read a file as the container user
//! - `amla-exec run <name> -- @kalahari:fs-* ...` — Kalahari guest-agent
//!   filesystem builtins used by the public SDK
//!
//! The `run` subcommand reads the OCI config from the container state directory
//! (written by `amla-init`). If `-- cmd` is provided, it overrides the image's
//! entrypoint. `--env` flags override or extend the image's configured environment.
//!
//! Namespace entry, uid/gid switching, and exec are done directly via libc
//! syscalls (setns, setgid, setuid, execvp) — no external `nsenter` binary.

use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;

use base64::Engine;
use lexopt::prelude::*;
use serde::Serialize;

use crate::oci::{self, cstr};

/// Container state directory (stores PID + config files).
const CONTAINER_STATE: &str = "/run/containers";

/// Namespaces to enter, in the order nsenter uses.
const NAMESPACES: &[(&str, libc::c_int)] = &[
    ("pid", libc::CLONE_NEWPID),
    ("mnt", libc::CLONE_NEWNS),
    ("ipc", libc::CLONE_NEWIPC),
    ("uts", libc::CLONE_NEWUTS),
];

#[derive(Serialize)]
struct KalahariDirEntry {
    name: String,
    path: String,
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Serialize)]
struct KalahariFileStat {
    name: String,
    path: String,
    #[serde(rename = "type")]
    kind: &'static str,
    size: u64,
    #[serde(rename = "modTimeMs")]
    mod_time_ms: u64,
}

/// Run the exec subcommand. Returns exit code.
pub fn run(args: &[String]) -> i32 {
    let mut parser = lexopt::Parser::from_args(args.iter().map(String::as_str));

    let result = match parser.next() {
        Ok(Some(Value(sub))) => {
            let sub = sub
                .into_string()
                .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()));
            match sub.as_deref() {
                Ok("run" | "exec") => cmd_run(parser),
                Ok("stop") => cmd_stop(parser),
                Ok("write-file") => cmd_write_file(parser),
                Ok("read-file") => cmd_read_file(parser),
                Ok("write-user-file") => cmd_write_user_file(parser),
                Ok("read-user-file") => cmd_read_user_file(parser),
                Ok(other) => Err(format!("unknown subcommand: {other}")),
                Err(e) => Err(e.clone()),
            }
        }
        Ok(Some(other)) => Err(other.unexpected().to_string()),
        Ok(None) => Err(
            "usage: amla-exec <run|stop|write-file|read-file|write-user-file|read-user-file> ..."
                .into(),
        ),
        Err(e) => Err(e.to_string()),
    };

    match result {
        Ok(()) => 0,
        Err(msg) => {
            eprintln!("amla-exec: {msg}");
            1
        }
    }
}

// ─── run ─────────────────────────────────────────────────────────────────

/// Run a command in the container namespace.
///
/// Opens `/proc/<pid>/ns/*` for the container init process and calls `setns()`
/// to enter each namespace, then switches uid/gid and execs the command.
#[allow(clippy::too_many_lines)]
fn cmd_run(mut parser: lexopt::Parser) -> Result<(), String> {
    let mut name: Option<String> = None;
    let mut cli_env: Vec<String> = Vec::new();
    let mut cli_cwd: Option<String> = None;
    let mut cmd_override: Vec<String> = Vec::new();

    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Long("env") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                let s = val
                    .into_string()
                    .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?;
                cli_env.push(s);
            }
            Long("cwd") => {
                let val = parser.value().map_err(|e| e.to_string())?;
                cli_cwd = Some(
                    val.into_string()
                        .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?,
                );
            }
            Value(val) => {
                let s = val
                    .into_string()
                    .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?;
                if name.is_none() {
                    name = Some(s);
                } else {
                    // Positional after name, or anything after `--`
                    // (lexopt emits all post-`--` tokens as Value).
                    cmd_override.push(s);
                }
            }
            _ => return Err(arg.unexpected().to_string()),
        }
    }

    // Collect any remaining raw args (e.g. if parser stopped early).
    for raw in parser.raw_args().map_err(|e| e.to_string())? {
        let s = raw
            .into_string()
            .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?;
        cmd_override.push(s);
    }

    let name = name.ok_or("usage: amla-exec run <name> [--env K=V]... [-- cmd args...]")?;
    oci::validate_name(&name)?;

    // Read config from state directory (written by amla-init).
    let state_dir = std::path::Path::new(CONTAINER_STATE).join(&name);
    let config_json = fs::read_to_string(state_dir.join("config.json"))
        .map_err(|e| format!("read config: {e}"))?;
    let mut config = oci::parse_oci_config(&config_json)?;

    // Determine command to run.
    let cmd_args: Vec<String> = if cmd_override.is_empty() {
        // Use entrypoint from config.json process.args.
        config.args.clone()
    } else {
        cmd_override
    };

    if cmd_args.is_empty() {
        return Err("no command to run (image has no entrypoint?)".into());
    }

    let pid = read_init_pid(&name)?;

    // Enter namespaces via setns().
    enter_namespaces(pid)?;

    // Resolve named users now that we're in the container's mount namespace.
    oci::resolve_named_user(&mut config)?;

    // Ignore SIGHUP before fork — the child's TIOCSCTTY steal sends
    // SIGHUP to our foreground pgrp and we must survive it.
    // SAFETY: SIG_IGN is async-signal-safe; SIGHUP is a valid signal number.
    unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };

    // Fork so the child is actually in the container's PID namespace.
    // setns(CLONE_NEWPID) only affects children — the calling process stays
    // in the original PID namespace. Without fork(), /proc/self resolves to
    // a PID that doesn't exist in the container's procfs, breaking the
    // dynamic linker and allocators that read /proc/self/maps.
    // SAFETY: fork has no preconditions.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if child_pid > 0 {
        // Parent: wait for child and forward its exit status.
        let mut status: libc::c_int = 0;
        // SAFETY: `&raw mut status` is a valid out-pointer for the duration of the call.
        unsafe { libc::waitpid(child_pid, &raw mut status, 0) };
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            1
        };
        // SAFETY: _exit has no preconditions and does not return.
        unsafe { libc::_exit(code) };
    }

    // Child: now truly in the container's PID namespace.
    //
    // Create a new session and steal the controlling terminal from the
    // parent's session. arg=1 forces the steal (requires CAP_SYS_ADMIN,
    // which we have as root). This makes isatty(0) return true so shells
    // like dash/busybox-sh enable line editing.
    // SAFETY: post-fork child; single-threaded per POSIX until exec. signal()
    // handler is SIG_DFL (async-signal-safe). setsid/setpgrp have no
    // preconditions. ioctl on fd 0 uses TIOCSCTTY request with int arg=1.
    // tcsetpgrp uses fd 0 with pid from getpid().
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_DFL); // restore before exec
        libc::setsid();
        libc::ioctl(0, libc::TIOCSCTTY, 1);
        libc::tcsetpgrp(0, libc::getpid());
    }

    // Load env from /run/container-env (written by amla-init).
    // This is the single source of truth — amla-init resolves OCI config
    // env + PATH + TERM + XDG_RUNTIME_DIR + WAYLAND_DISPLAY.
    let mut env_vars: Vec<String> = fs::read_to_string("/run/container-env")
        .map(|data| data.lines().map(String::from).collect())
        .map_err(|e| format!("read /run/container-env: {e}"))?;

    // Apply CLI --env overrides on top.
    for var in &cli_env {
        if let Some(eq) = var.find('=') {
            let key = &var[..eq];
            if let Some(existing) = env_vars
                .iter_mut()
                .find(|v| v.starts_with(key) && v.as_bytes().get(key.len()) == Some(&b'='))
            {
                existing.clone_from(var);
            } else {
                env_vars.push(var.clone());
            }
        } else {
            env_vars.push(var.clone());
        }
    }

    // Set environment.
    clear_env();
    for var in &env_vars {
        put_env(var);
    }

    // Change working directory (CLI --cwd overrides OCI config).
    let cwd = cli_cwd.as_deref().unwrap_or(&config.cwd);
    std::env::set_current_dir(cwd).map_err(|e| format!("chdir({cwd}): {e}"))?;

    // Drop capabilities to the Docker-default set and enable NoNewPrivs
    // BEFORE setuid. `PR_CAPBSET_DROP` needs `CAP_SETPCAP` which setuid to
    // a non-zero uid strips, so the order matters.
    crate::hardening::drop_to_container_caps()?;

    // Switch gid before uid — can't change groups after dropping root.
    // SAFETY: setgid takes an integer gid and has no pointer preconditions.
    if config.gid != 0 && unsafe { libc::setgid(config.gid) } != 0 {
        return Err(format!(
            "setgid({}): {}",
            config.gid,
            std::io::Error::last_os_error()
        ));
    }

    // SAFETY: setuid takes an integer uid and has no pointer preconditions.
    if config.uid != 0 && unsafe { libc::setuid(config.uid) } != 0 {
        return Err(format!(
            "setuid({}): {}",
            config.uid,
            std::io::Error::last_os_error()
        ));
    }

    if let Some(exit_code) = run_kalahari_builtin(&cmd_args) {
        // SAFETY: _exit has no preconditions and does not return.
        unsafe { libc::_exit(exit_code) };
    }

    // Exec the command.
    let argv: Vec<CString> = cmd_args.iter().map(|a| cstr(a)).collect();
    exec_argv(&argv)
}

fn run_kalahari_builtin(args: &[String]) -> Option<i32> {
    match args.first().map(String::as_str) {
        Some("@kalahari:fs-exists") => Some(kalahari_fs_exists(args)),
        Some("@kalahari:fs-chmod") => Some(kalahari_fs_chmod(args)),
        Some("@kalahari:fs-list") => Some(kalahari_fs_list(args)),
        Some("@kalahari:fs-mkdir") => Some(kalahari_fs_mkdir(args)),
        Some("@kalahari:fs-read") => Some(kalahari_fs_read(args)),
        Some("@kalahari:fs-read-b64") => Some(kalahari_fs_read_b64(args)),
        Some("@kalahari:fs-remove") => Some(kalahari_fs_remove(args)),
        Some("@kalahari:fs-rename") => Some(kalahari_fs_rename(args)),
        Some("@kalahari:fs-stat") => Some(kalahari_fs_stat(args)),
        Some("@kalahari:fs-write") => Some(kalahari_fs_write(args)),
        Some("@kalahari:fs-write-b64") => Some(kalahari_fs_write_b64(args)),
        _ => None,
    }
}

fn kalahari_fs_exists(args: &[String]) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-exists <path>");
        return 2;
    };
    i32::from(fs::symlink_metadata(path).is_err())
}

fn kalahari_fs_chmod(args: &[String]) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-chmod <path> <mode>");
        return 2;
    };
    let Some(mode) = args.get(2) else {
        eprintln!("usage: @kalahari:fs-chmod <path> <mode>");
        return 2;
    };
    match kalahari_chmod(path, mode) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("@kalahari:fs-chmod: {path}: {error}");
            1
        }
    }
}

fn kalahari_fs_list(args: &[String]) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-list <path>");
        return 2;
    };

    match kalahari_list_dir(path) {
        Ok(entries) => match serde_json::to_writer(std::io::stdout(), &entries) {
            Ok(()) => {
                println!();
                0
            }
            Err(error) => {
                eprintln!("@kalahari:fs-list: write stdout: {error}");
                1
            }
        },
        Err(error) => {
            eprintln!("@kalahari:fs-list: {path}: {error}");
            1
        }
    }
}

fn kalahari_fs_mkdir(args: &[String]) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-mkdir <path>");
        return 2;
    };
    match fs::create_dir_all(path) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("@kalahari:fs-mkdir: {path}: {error}");
            1
        }
    }
}

fn kalahari_fs_read(args: &[String]) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-read <path>");
        return 2;
    };
    match fs::read(path) {
        Ok(bytes) => {
            let mut stdout = std::io::stdout().lock();
            match stdout.write_all(&bytes).and_then(|()| stdout.flush()) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("@kalahari:fs-read: write stdout: {error}");
                    1
                }
            }
        }
        Err(error) => {
            eprintln!("@kalahari:fs-read: {path}: {error}");
            1
        }
    }
}

fn kalahari_fs_read_b64(args: &[String]) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-read-b64 <path>");
        return 2;
    };
    match fs::read(path) {
        Ok(bytes) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            match writeln!(std::io::stdout(), "{encoded}") {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("@kalahari:fs-read-b64: write stdout: {error}");
                    1
                }
            }
        }
        Err(error) => {
            eprintln!("@kalahari:fs-read-b64: {path}: {error}");
            1
        }
    }
}

fn kalahari_fs_remove(args: &[String]) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-remove <path>");
        return 2;
    };
    match kalahari_remove_path(path) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("@kalahari:fs-remove: {path}: {error}");
            1
        }
    }
}

fn kalahari_fs_rename(args: &[String]) -> i32 {
    let Some(old_path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-rename <old-path> <new-path>");
        return 2;
    };
    let Some(new_path) = args.get(2) else {
        eprintln!("usage: @kalahari:fs-rename <old-path> <new-path>");
        return 2;
    };
    match fs::rename(old_path, new_path) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("@kalahari:fs-rename: {old_path} -> {new_path}: {error}");
            1
        }
    }
}

fn kalahari_fs_stat(args: &[String]) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-stat <path>");
        return 2;
    };

    match kalahari_stat_path(path) {
        Ok(stat) => match serde_json::to_writer(std::io::stdout(), &stat) {
            Ok(()) => {
                println!();
                0
            }
            Err(error) => {
                eprintln!("@kalahari:fs-stat: write stdout: {error}");
                1
            }
        },
        Err(error) => {
            eprintln!("@kalahari:fs-stat: {path}: {error}");
            1
        }
    }
}

fn kalahari_fs_write(args: &[String]) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-write <path>");
        return 2;
    };
    match kalahari_write_stdin(path) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("@kalahari:fs-write: {path}: {error}");
            1
        }
    }
}

fn kalahari_fs_write_b64(args: &[String]) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: @kalahari:fs-write-b64 <path> <base64>");
        return 2;
    };
    let Some(encoded) = args.get(2) else {
        eprintln!("usage: @kalahari:fs-write-b64 <path> <base64>");
        return 2;
    };
    match kalahari_write_b64(path, encoded) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("@kalahari:fs-write-b64: {path}: {error}");
            1
        }
    }
}

fn kalahari_write_stdin(path: &str) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    fs::write(path, bytes).map_err(|error| error.to_string())
}

fn kalahari_chmod(path: &str, mode: &str) -> Result<(), String> {
    let parsed_mode = kalahari_parse_mode(mode)?;
    let permissions = fs::Permissions::from_mode(parsed_mode);
    fs::set_permissions(path, permissions).map_err(|error| error.to_string())
}

fn kalahari_parse_mode(mode: &str) -> Result<u32, String> {
    let trimmed = mode.trim();
    let digits = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
        .unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(format!("invalid octal mode: {mode}"));
    }
    let parsed = u32::from_str_radix(digits, 8).map_err(|error| error.to_string())?;
    if parsed > 0o7777 {
        return Err(format!("mode out of range: {mode}"));
    }
    Ok(parsed)
}

fn kalahari_stat_path(path: &str) -> Result<KalahariFileStat, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    let mod_time_ms = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });
    let name = std::path::Path::new(path).file_name().map_or_else(
        || path.to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    Ok(KalahariFileStat {
        name,
        path: path.to_string(),
        kind: if metadata.is_dir() { "dir" } else { "file" },
        size: metadata.len(),
        mod_time_ms,
    })
}

fn kalahari_list_dir(path: &str) -> Result<Vec<KalahariDirEntry>, String> {
    let mut entries = Vec::new();
    let read_dir = fs::read_dir(path).map_err(|error| error.to_string())?;
    for entry in read_dir {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        entries.push(KalahariDirEntry {
            name,
            path: entry.path().to_string_lossy().into_owned(),
            kind: if file_type.is_dir() { "dir" } else { "file" },
        });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn kalahari_remove_path(path: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path).map_err(|error| error.to_string())
        }
        Ok(_) => fs::remove_file(path).map_err(|error| error.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn kalahari_write_b64(path: &str, encoded: &str) -> Result<(), String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| error.to_string())?;
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(path, bytes).map_err(|error| error.to_string())
}

// ─── stop ───────────────────────────────────────────────────────────────

/// Stop and delete a container.
fn cmd_stop(mut parser: lexopt::Parser) -> Result<(), String> {
    let mut name: Option<String> = None;

    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Value(val) if name.is_none() => {
                name = Some(
                    val.into_string()
                        .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?,
                );
            }
            _ => return Err(arg.unexpected().to_string()),
        }
    }

    let name = name.ok_or("usage: amla-exec stop <name>")?;
    oci::validate_name(&name)?;

    if let Ok(pid) = read_init_pid(&name) {
        #[allow(clippy::cast_possible_truncation)]
        // SAFETY: kill takes a pid and signal; SIGKILL is async-signal-safe to deliver.
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }

    let state_path = std::path::Path::new(CONTAINER_STATE).join(&name);
    if let Err(e) = fs::remove_dir_all(&state_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("amla-exec: remove state {}: {e}", state_path.display());
    }
    let ov_path = std::path::Path::new("/run/ov").join(&name);
    if let Err(e) = fs::remove_dir_all(&ov_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("amla-exec: remove overlay {}: {e}", ov_path.display());
    }

    Ok(())
}

// ─── write-file ─────────────────────────────────────────────────────────

/// Write stdin to a file inside the container namespace.
///
/// Creates parent directories automatically. No shell required.
fn cmd_write_file(mut parser: lexopt::Parser) -> Result<(), String> {
    let mut name: Option<String> = None;
    let mut path: Option<String> = None;

    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Value(val) if name.is_none() => {
                name = Some(
                    val.into_string()
                        .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?,
                );
            }
            Value(val) if path.is_none() => {
                path = Some(
                    val.into_string()
                        .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?,
                );
            }
            _ => return Err(arg.unexpected().to_string()),
        }
    }

    let name = name.ok_or("usage: amla-exec write-file <name> <path>")?;
    let path = path.ok_or("usage: amla-exec write-file <name> <path>")?;
    oci::validate_name(&name)?;

    let pid = read_init_pid(&name)?;
    enter_namespaces(pid)?;

    // Fork to enter PID namespace properly
    // SAFETY: fork has no preconditions.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if child_pid > 0 {
        let mut status: libc::c_int = 0;
        // SAFETY: `&raw mut status` is a valid out-pointer for the duration of the call.
        unsafe { libc::waitpid(child_pid, &raw mut status, 0) };
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            1
        };
        // SAFETY: _exit has no preconditions and does not return.
        unsafe { libc::_exit(code) };
    }

    // Child: in container namespace. Create parent dirs and write file.
    if let Some(parent) = std::path::Path::new(&path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir -p {}: {e}", parent.display()))?;
    }

    let mut data = Vec::new();
    std::io::Read::read_to_end(&mut std::io::stdin(), &mut data)
        .map_err(|e| format!("read stdin: {e}"))?;
    fs::write(&path, &data).map_err(|e| format!("write {path}: {e}"))?;
    Ok(())
}

// ─── read-file ──────────────────────────────────────────────────────────

/// Read a file from the container namespace to stdout.
fn cmd_read_file(mut parser: lexopt::Parser) -> Result<(), String> {
    let mut name: Option<String> = None;
    let mut path: Option<String> = None;

    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Value(val) if name.is_none() => {
                name = Some(
                    val.into_string()
                        .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?,
                );
            }
            Value(val) if path.is_none() => {
                path = Some(
                    val.into_string()
                        .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?,
                );
            }
            _ => return Err(arg.unexpected().to_string()),
        }
    }

    let name = name.ok_or("usage: amla-exec read-file <name> <path>")?;
    let path = path.ok_or("usage: amla-exec read-file <name> <path>")?;
    oci::validate_name(&name)?;

    let pid = read_init_pid(&name)?;
    enter_namespaces(pid)?;

    // Fork to enter PID namespace properly
    // SAFETY: fork has no preconditions.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if child_pid > 0 {
        let mut status: libc::c_int = 0;
        // SAFETY: `&raw mut status` is a valid out-pointer for the duration of the call.
        unsafe { libc::waitpid(child_pid, &raw mut status, 0) };
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            1
        };
        // SAFETY: _exit has no preconditions and does not return.
        unsafe { libc::_exit(code) };
    }

    // Child: read file and write to stdout
    let data = fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    std::io::Write::write_all(&mut std::io::stdout(), &data)
        .map_err(|e| format!("write stdout: {e}"))?;
    Ok(())
}

/// Resolve the container user's home directory.
///
/// Reads HOME from `/run/container-env` (the same source `cmd_run` uses)
/// to stay consistent with the agent process environment. Falls back to
/// `/etc/passwd` lookup if HOME is not set in the env file.
fn resolve_home_dir(uid: u32) -> Result<String, String> {
    let home = fs::read_to_string("/run/container-env")
        .ok()
        .and_then(|data| {
            data.lines()
                .find(|l| l.starts_with("HOME="))
                .map(|l| l["HOME=".len()..].to_string())
        })
        .filter(|h| !h.is_empty());
    home.map_or_else(|| oci::lookup_home_dir(uid), Ok)
}

// ─── write-user-file ────────────────────────────────────────────────────

/// Write stdin to a file inside the container, as the container user.
///
/// The path is relative to the container user's home directory (resolved
/// from `/etc/passwd`). Creates parent directories automatically.
/// Files are owned by the container user, not root.
fn cmd_write_user_file(mut parser: lexopt::Parser) -> Result<(), String> {
    let (name, rel_path) = parse_name_path(&mut parser, "write-user-file")?;

    let state_dir = std::path::Path::new(CONTAINER_STATE).join(&name);
    let config_json = fs::read_to_string(state_dir.join("config.json"))
        .map_err(|e| format!("read config: {e}"))?;
    let mut config = oci::parse_oci_config(&config_json)?;

    let pid = read_init_pid(&name)?;
    enter_namespaces(pid)?;
    oci::resolve_named_user(&mut config)?;

    let home = resolve_home_dir(config.uid)?;
    let path = format!("{home}/{rel_path}");

    // Drop capabilities before setuid (same constraint as cmd_run).
    crate::hardening::drop_to_container_caps()?;

    // Switch gid before uid — can't change groups after dropping root.
    // SAFETY: setgid takes an integer gid and has no pointer preconditions.
    if config.gid != 0 && unsafe { libc::setgid(config.gid) } != 0 {
        return Err(format!(
            "setgid({}): {}",
            config.gid,
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: setuid takes an integer uid and has no pointer preconditions.
    if config.uid != 0 && unsafe { libc::setuid(config.uid) } != 0 {
        return Err(format!(
            "setuid({}): {}",
            config.uid,
            std::io::Error::last_os_error()
        ));
    }

    // Fork to enter PID namespace properly.
    // SAFETY: fork has no preconditions.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if child_pid > 0 {
        let mut status: libc::c_int = 0;
        // SAFETY: `&raw mut status` is a valid out-pointer for the duration of the call.
        unsafe { libc::waitpid(child_pid, &raw mut status, 0) };
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            1
        };
        // SAFETY: _exit has no preconditions and does not return.
        unsafe { libc::_exit(code) };
    }

    // Child: create parent dirs and write file — all as container user.
    if let Some(parent) = std::path::Path::new(&path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir -p {}: {e}", parent.display()))?;
    }

    let mut data = Vec::new();
    std::io::Read::read_to_end(&mut std::io::stdin(), &mut data)
        .map_err(|e| format!("read stdin: {e}"))?;
    fs::write(&path, &data).map_err(|e| format!("write {path}: {e}"))?;
    Ok(())
}

// ─── read-user-file ─────────────────────────────────────────────────────

/// Read a file from the container as the container user.
///
/// The path is relative to the container user's home directory.
fn cmd_read_user_file(mut parser: lexopt::Parser) -> Result<(), String> {
    let (name, rel_path) = parse_name_path(&mut parser, "read-user-file")?;

    let state_dir = std::path::Path::new(CONTAINER_STATE).join(&name);
    let config_json = fs::read_to_string(state_dir.join("config.json"))
        .map_err(|e| format!("read config: {e}"))?;
    let mut config = oci::parse_oci_config(&config_json)?;

    let pid = read_init_pid(&name)?;
    enter_namespaces(pid)?;
    oci::resolve_named_user(&mut config)?;

    let home = resolve_home_dir(config.uid)?;
    let path = format!("{home}/{rel_path}");

    crate::hardening::drop_to_container_caps()?;

    // SAFETY: setgid takes an integer gid and has no pointer preconditions.
    if config.gid != 0 && unsafe { libc::setgid(config.gid) } != 0 {
        return Err(format!(
            "setgid({}): {}",
            config.gid,
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: setuid takes an integer uid and has no pointer preconditions.
    if config.uid != 0 && unsafe { libc::setuid(config.uid) } != 0 {
        return Err(format!(
            "setuid({}): {}",
            config.uid,
            std::io::Error::last_os_error()
        ));
    }

    // SAFETY: fork has no preconditions.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if child_pid > 0 {
        let mut status: libc::c_int = 0;
        // SAFETY: `&raw mut status` is a valid out-pointer for the duration of the call.
        unsafe { libc::waitpid(child_pid, &raw mut status, 0) };
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            1
        };
        // SAFETY: _exit has no preconditions and does not return.
        unsafe { libc::_exit(code) };
    }

    // Child: read file as container user.
    let data = fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    std::io::Write::write_all(&mut std::io::stdout(), &data)
        .map_err(|e| format!("write stdout: {e}"))?;
    Ok(())
}

/// Parse `<name> <path>` positional args shared by file subcommands.
fn parse_name_path(parser: &mut lexopt::Parser, cmd: &str) -> Result<(String, String), String> {
    let mut name: Option<String> = None;
    let mut path: Option<String> = None;

    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Value(val) if name.is_none() => {
                name = Some(
                    val.into_string()
                        .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?,
                );
            }
            Value(val) if path.is_none() => {
                path = Some(
                    val.into_string()
                        .map_err(|e| format!("invalid utf-8: {}", e.to_string_lossy()))?,
                );
            }
            _ => return Err(arg.unexpected().to_string()),
        }
    }

    let name = name.ok_or_else(|| format!("usage: amla-exec {cmd} <name> <path>"))?;
    let path = path.ok_or_else(|| format!("usage: amla-exec {cmd} <name> <path>"))?;
    oci::validate_name(&name)?;
    Ok((name, path))
}

// ─── namespace entry ─────────────────────────────────────────────────────

/// Enter the container's namespaces by calling `setns()` on each,
/// then change root to match the container's root filesystem.
///
/// Opens ALL namespace fds and the container root fd first, THEN calls
/// `setns()`. This is critical because after `setns(CLONE_NEWNS)`, /proc
/// shows the container's PID namespace where the init PID is different
/// from the root namespace PID.
fn enter_namespaces(pid: i64) -> Result<(), String> {
    // Open all fds first while still in the root mount namespace.
    // OwnedFd provides RAII — remaining fds auto-close on error return.
    let mut fds: Vec<(&str, libc::c_int, OwnedFd)> = Vec::new();
    for &(ns_name, ns_type) in NAMESPACES {
        let ns_path = format!("/proc/{pid}/ns/{ns_name}");
        let fd = open_readonly(&ns_path)?;
        fds.push((ns_name, ns_type, fd));
    }

    // Open the container's root directory BEFORE setns changes /proc.
    // /proc/<pid>/root is a magic symlink to the container's rootfs.
    let root_fd = open_readonly(&format!("/proc/{pid}/root"))?;

    // Now setns() on each. OwnedFd closes automatically at end of each
    // iteration, and remaining fds drop on early return.
    for (ns_name, ns_type, fd) in fds {
        // SAFETY: `fd` is a valid namespace fd owned by this scope; `ns_type`
        // is a CLONE_NEW* constant.
        let ret = unsafe { libc::setns(fd.as_raw_fd(), ns_type) };
        if ret != 0 {
            return Err(format!(
                "setns({ns_name}): {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // Change to the container's root. setns(CLONE_NEWNS) joins the mount
    // namespace but doesn't change our root — we still see the host's /.
    // fchdir + chroot makes / resolve to the container's rootfs.
    // SAFETY: `root_fd` is a valid OwnedFd opened on the container root dir.
    if unsafe { libc::fchdir(root_fd.as_raw_fd()) } != 0 {
        return Err(format!(
            "fchdir(container root): {}",
            std::io::Error::last_os_error()
        ));
    }
    let dot = oci::cstr(".");
    // SAFETY: `dot` is a live CString, so `dot.as_ptr()` is a NUL-terminated string;
    // caller has CAP_SYS_CHROOT as PID 1 in the guest.
    if unsafe { libc::chroot(dot.as_ptr()) } != 0 {
        return Err(format!("chroot(.): {}", std::io::Error::last_os_error()));
    }

    Ok(())
}

fn open_readonly(path: &str) -> Result<OwnedFd, String> {
    fs::File::open(path)
        .map(OwnedFd::from)
        .map_err(|e| format!("open({path}): {e}"))
}

// OCI config parsing is in crate::oci (shared with init).

// ─── helpers ────────────────────────────────────────────────────────────

fn read_init_pid(name: &str) -> Result<i64, String> {
    let pid_path = std::path::Path::new(CONTAINER_STATE).join(name).join("pid");
    let data = fs::read_to_string(&pid_path).map_err(|e| format!("read pid: {e}"))?;
    data.trim()
        .parse::<i64>()
        .map_err(|e| format!("parse pid: {e}"))
}

fn clear_env() {
    let keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    for key in keys {
        // SAFETY: single-threaded guest binary — no concurrent env access.
        unsafe { std::env::remove_var(&key) };
    }
}

fn put_env(var: &str) {
    if let Some(eq) = var.find('=') {
        // SAFETY: single-threaded guest binary — no concurrent env access.
        unsafe { std::env::set_var(&var[..eq], &var[eq + 1..]) };
    }
}

fn exec_argv(argv: &[CString]) -> Result<(), String> {
    let ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // SAFETY: argv[0] is a live CString; `ptrs` is a NULL-terminated array of
    // pointers to live CStrings (kept alive by `argv`).
    unsafe { libc::execvp(argv[0].as_ptr(), ptrs.as_ptr()) };

    let err = std::io::Error::last_os_error();
    let cmd = argv[0].to_string_lossy();

    // ENOENT or ENOTDIR usually means the binary isn't where the caller
    // thinks it is. Dump kernel log + rootfs tree so the operator can see
    // mount errors and what IS in the container.
    if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("?"));
        eprintln!("amla-exec: cwd={}", cwd.display());
        eprintln!("amla-exec: dmesg (last 500 lines) ↓");
        dump_dmesg(500);
        eprintln!("amla-exec: rootfs tree ↓");
        walk(std::path::Path::new("/"), 0);
    }

    Err(format!("execvp {cmd}: {err}"))
}

/// Print the last `tail_lines` lines of the kernel ring buffer to stderr.
/// Uses `klogctl(SYSLOG_ACTION_READ_ALL=3)` directly — works even after
/// chroot, since it's a syscall and doesn't depend on `/proc/kmsg` or
/// `/dev/kmsg` being present in the container's filesystem.
fn dump_dmesg(tail_lines: usize) {
    // klogctl SYSLOG_ACTION_SIZE_BUFFER = 10 returns the buffer size.
    // SAFETY: SIZE_BUFFER ignores the buffer pointer/len; NULL+0 is accepted.
    let size = unsafe { libc::klogctl(10, std::ptr::null_mut(), 0) };
    if size <= 0 {
        eprintln!("  <klogctl size: {}>", std::io::Error::last_os_error());
        return;
    }
    #[allow(clippy::cast_sign_loss)]
    let mut buf = vec![0u8; size as usize];
    // SYSLOG_ACTION_READ_ALL = 3 — non-destructive snapshot of the buffer.
    // SAFETY: `buf` is a Vec<u8> with `buf.len()` bytes of writable memory.
    let n = unsafe {
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        libc::klogctl(3, buf.as_mut_ptr().cast(), buf.len() as libc::c_int)
    };
    if n <= 0 {
        eprintln!("  <klogctl read: {}>", std::io::Error::last_os_error());
        return;
    }
    #[allow(clippy::cast_sign_loss)]
    let text = String::from_utf8_lossy(&buf[..n as usize]);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(tail_lines);
    for line in &lines[start..] {
        eprintln!("  {line}");
    }
}

/// Recursively print every entry under `dir` to stderr. Skips kernel
/// virtual filesystems (/proc, /sys, /dev) — millions of entries that
/// describe the kernel, not the container's rootfs.
fn walk(dir: &std::path::Path, depth: usize) {
    // Skip kernel virtual filesystems regardless of where they appear.
    if matches!(
        dir.file_name().and_then(|s| s.to_str()),
        Some("proc" | "sys" | "dev")
    ) {
        eprintln!(
            "{}{}/  <skipped: kernel virtual filesystem>",
            "  ".repeat(depth),
            dir.file_name().and_then(|s| s.to_str()).unwrap_or("?")
        );
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(it) => it,
        Err(e) => {
            eprintln!("{}<cannot read {}: {e}>", "  ".repeat(depth), dir.display());
            return;
        }
    };
    let mut children: Vec<std::fs::DirEntry> = entries.flatten().collect();
    children.sort_by_key(std::fs::DirEntry::file_name);
    for entry in children {
        let name = entry.file_name();
        let path = entry.path();
        let ft = entry.file_type().ok();
        let indent = "  ".repeat(depth + 1);
        match ft {
            Some(t) if t.is_symlink() => match std::fs::read_link(&path) {
                Ok(target) => {
                    eprintln!("{indent}{} -> {}", name.to_string_lossy(), target.display());
                }
                Err(_) => eprintln!("{indent}{}@", name.to_string_lossy()),
            },
            Some(t) if t.is_dir() => {
                eprintln!("{indent}{}/", name.to_string_lossy());
                walk(&path, depth + 1);
            }
            Some(_) => eprintln!("{indent}{}", name.to_string_lossy()),
            None => eprintln!("{indent}{}?", name.to_string_lossy()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kalahari_list_dir_reports_sorted_file_and_directory_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_dir("kalahari-list");
        fs::create_dir_all(root.join("beta"))?;
        fs::write(root.join("alpha"), b"alpha")?;

        let root_string = root.to_string_lossy().into_owned();
        let entries = kalahari_list_dir(&root_string).map_err(std::io::Error::other)?;

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "alpha");
        assert_eq!(entries[0].kind, "file");
        assert!(entries[0].path.ends_with("/alpha"));
        assert_eq!(entries[1].name, "beta");
        assert_eq!(entries[1].kind, "dir");
        assert!(entries[1].path.ends_with("/beta"));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn kalahari_write_b64_creates_parent_and_remove_deletes_tree()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_dir("kalahari-write");
        let file = root.join("nested").join("message.txt");
        let file_string = file.to_string_lossy().into_owned();

        kalahari_write_b64(&file_string, "aGVsbG8=").map_err(std::io::Error::other)?;
        assert_eq!(fs::read_to_string(&file)?, "hello");

        let root_string = root.to_string_lossy().into_owned();
        kalahari_remove_path(&root_string).map_err(std::io::Error::other)?;
        assert!(!root.exists());
        Ok(())
    }

    #[test]
    fn kalahari_stat_and_chmod_use_guest_agent_filesystem_ops()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_dir("kalahari-stat");
        fs::create_dir_all(&root)?;
        let file = root.join("message.txt");
        fs::write(&file, b"hello")?;
        let file_string = file.to_string_lossy().into_owned();

        let stat = kalahari_stat_path(&file_string).map_err(std::io::Error::other)?;
        assert_eq!(stat.name, "message.txt");
        assert_eq!(stat.path, file_string);
        assert_eq!(stat.kind, "file");
        assert_eq!(stat.size, 5);

        kalahari_chmod(&file_string, "640").map_err(std::io::Error::other)?;
        let mode = fs::metadata(&file)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert_eq!(
            kalahari_parse_mode("0o755").map_err(std::io::Error::other)?,
            0o755
        );
        assert!(kalahari_parse_mode("888").is_err());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
        path
    }
}
