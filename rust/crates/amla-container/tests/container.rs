#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for the amla-container layer.
//!
//! Boots a VM with a minimal OCI container image, exercises
//! `init_container`, `ContainerHandle::run()`, and streaming I/O.

use std::sync::Mutex;
use std::time::Duration;

use amla_container::init_container;
use amla_vmm::backend::BackendPools;
use amla_vmm::{Backends, ConsoleStream, VirtualMachine, VmConfig};

/// Boot-budget ceiling. Isolated runs boot a VM in ~1s; the headroom exists
/// for `pre-commit run --all-files`, which parallelizes every test binary in
/// the workspace, so multiple VMs from other crates (`amla-vm-vmm/tests/*`)
/// race against these for host CPU. The happy path still finishes in ~1s, so
/// a generous ceiling costs nothing but prevents spurious failures.
const TIMEOUT: Duration = Duration::from_mins(2);

/// Serializes test VM runs WITHIN THIS BINARY. Cross-binary serialization is
/// not attempted — a file lock would slow down healthy CI runs for no gain,
/// and `TIMEOUT` already absorbs the cross-binary contention.
static TEST_VM_LOCK: Mutex<()> = Mutex::new(());

/// OCI config JSON for the test container.
const TEST_CONFIG_JSON: &str = r#"{"process":{"args":["/bin/amla-guest","echo","ready"],"env":["PATH=/bin","TERM=xterm"],"cwd":"/","user":{"uid":0,"gid":0}}}"#;

fn worker_config() -> amla_vmm::WorkerProcessConfig {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        macos_worker_config()
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        amla_vmm::WorkerProcessConfig::path("unused-test-worker")
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn macos_worker_config() -> amla_vmm::WorkerProcessConfig {
    if let Some(path) = std::env::var_os("AMLA_HVF_WORKER") {
        return amla_vmm::WorkerProcessConfig::path(path);
    }

    amla_vmm::WorkerProcessConfig::path(worker_path_next_to_target_dir("amla-hvf-worker"))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn worker_path_next_to_target_dir(binary_name: &str) -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("resolve test executable path");
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    path.push(binary_name);
    path
}

/// Build a minimal container image as an EROFS disk.
///
/// Flat filesystem (no config.json or rootfs wrapper) — the OCI config
/// is passed to `amla-init` via `--config` argv.
fn build_container_image() -> amla_vmm::MemHandle {
    use amla_erofs::{Body, Entry, Metadata, Permissions};
    let meta = |mode| Metadata {
        permissions: Permissions::from_mode(mode),
        uid: 0,
        gid: 0,
        mtime: 0,
        mtime_nsec: 0,
        xattrs: vec![],
    };
    let image = amla_erofs::build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/bin".into(),
            metadata: meta(0o040_755),
            body: Body::Directory,
        },
        Entry {
            path: "/tmp".into(),
            metadata: meta(0o041_777),
            body: Body::Directory,
        },
        Entry {
            path: "/bin/amla-guest".into(),
            metadata: meta(0o100_755),
            body: Body::RegularFile(amla_guest_rootfs::AMLA_GUEST.to_vec()),
        },
    ])
    .expect("build erofs");
    amla_vmm::MemHandle::allocate_and_write(c"erofs", image.image_size(), |buf| {
        image
            .write_to(buf)
            .map_err(|e| std::io::Error::other(e.to_string()))
    })
    .expect("erofs handle")
}

fn with_container<F>(f: F)
where
    F: AsyncFnOnce(&amla_container::DirectContainerHandle<'_, '_>),
{
    if !amla_vmm::available() {
        eprintln!("Skipping: hypervisor not available");
        return;
    }
    // Serialize: see TEST_VM_LOCK docs. If a prior test panicked, the lock is
    // poisoned — still safe to take (we don't care about protected state).
    let _guard = match TEST_VM_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    drop(
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init(),
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let kernel = amla_container::KERNEL;
        let p = amla_container::build_rootfs().expect("build rootfs");
        let rootfs = amla_vmm::MemHandle::allocate_and_write(c"rootfs", p.image_size(), |buf| {
            p.write_to(buf)
                .map_err(|e| std::io::Error::other(e.to_string()))
        })
        .expect("rootfs handle");
        let container_image = build_container_image();

        let config = VmConfig::default()
            .memory_mb(256)
            .pmem_root(rootfs.size().as_u64())
            .try_pmem_overlay(
                vec![amla_vmm::PmemImageConfig::overlay(
                    container_image.size().as_u64(),
                )],
                "/mnt",
            )
            .expect("valid overlay config");

        let pools = BackendPools::new(2, &config, worker_config()).expect("pools");
        let console = ConsoleStream::new();
        let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
            console: &console,
            net: None,
            fs: None,
            pmem: vec![rootfs, container_image],
        };
        let vm = VirtualMachine::create(config).await.expect("create VM");
        let vm = vm
            .load_kernel(&pools, kernel, backends)
            .await
            .expect("load kernel");

        let (_vm, ()) = vm
            .run(async move |handle| {
                let handle = handle.start();
                let mut container = tokio::time::timeout(
                    TIMEOUT,
                    init_container(&handle, "test", TEST_CONFIG_JSON),
                )
                .await
                .expect("init timed out")
                .expect("init failed");
                if let Some(mut stdout) = container.init.take_stdout() {
                    tokio::spawn(async move { while stdout.recv().await.is_some() {} });
                }
                f(&container.handle).await;
                drop(container.init.close_stdin().await);
                drop(tokio::time::timeout(TIMEOUT, container.init.wait()).await);
            })
            .await
            .expect("run VM");
    });
}

// ─── Permission / user resolution test infrastructure ───────────────────

/// Build a container image with /etc/passwd, various file ownerships, and
/// the amla-guest binary.
fn build_permission_test_image() -> amla_vmm::MemHandle {
    use amla_erofs::{Body, Entry, Metadata, Permissions};

    let meta = |mode, uid, gid| Metadata {
        permissions: Permissions::from_mode(mode),
        uid,
        gid,
        mtime: 0,
        mtime_nsec: 0,
        xattrs: vec![],
    };

    let passwd = b"root:x:0:0:root:/root:/bin/sh\n\
                   testuser:x:1000:1000:Test User:/home/testuser:/bin/sh\n\
                   nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
    let group = b"root:x:0:\ntestgroup:x:1000:\nnogroup:x:65534:\n";

    let image = amla_erofs::build_to_vec([
        Entry {
            path: "/".into(),
            metadata: meta(0o040_755, 0, 0),
            body: Body::Directory,
        },
        Entry {
            path: "/bin".into(),
            metadata: meta(0o040_755, 0, 0),
            body: Body::Directory,
        },
        Entry {
            path: "/etc".into(),
            metadata: meta(0o040_755, 0, 0),
            body: Body::Directory,
        },
        Entry {
            path: "/tmp".into(),
            metadata: meta(0o041_777, 0, 0),
            body: Body::Directory,
        },
        Entry {
            path: "/home".into(),
            metadata: meta(0o040_755, 0, 0),
            body: Body::Directory,
        },
        Entry {
            path: "/home/testuser".into(),
            metadata: meta(0o040_750, 1000, 1000),
            body: Body::Directory,
        },
        Entry {
            path: "/bin/amla-guest".into(),
            metadata: meta(0o100_755, 0, 0),
            body: Body::RegularFile(amla_guest_rootfs::AMLA_GUEST.to_vec()),
        },
        Entry {
            path: "/etc/passwd".into(),
            metadata: meta(0o100_644, 0, 0),
            body: Body::RegularFile(passwd.to_vec()),
        },
        Entry {
            path: "/etc/group".into(),
            metadata: meta(0o100_644, 0, 0),
            body: Body::RegularFile(group.to_vec()),
        },
        // Root-owned file (mode 600) — only root can read.
        Entry {
            path: "/etc/shadow".into(),
            metadata: meta(0o100_600, 0, 0),
            body: Body::RegularFile(b"root:*:19000:0:99999:7:::\n".to_vec()),
        },
        // testuser-owned file.
        Entry {
            path: "/home/testuser/myfile.txt".into(),
            metadata: meta(0o100_644, 1000, 1000),
            body: Body::RegularFile(b"hello from testuser\n".to_vec()),
        },
    ])
    .expect("build erofs");

    amla_vmm::MemHandle::allocate_and_write(c"erofs", image.image_size(), |buf| {
        image
            .write_to(buf)
            .map_err(|e| std::io::Error::other(e.to_string()))
    })
    .expect("erofs handle")
}

/// OCI runtime config with a named user ("testuser") that requires /etc/passwd resolution.
const TESTUSER_CONFIG_JSON: &str = r#"{"process":{"args":["/bin/amla-guest","echo","ready"],"env":["PATH=/bin","TERM=xterm"],"cwd":"/","user":{"uid":0,"gid":0,"username":"testuser"}}}"#;

/// Boot a container with the permission test image and a specific OCI config.
fn with_permission_container<F>(config_json: &str, f: F)
where
    F: AsyncFnOnce(&amla_container::DirectContainerHandle<'_, '_>),
{
    if !amla_vmm::available() {
        eprintln!("Skipping: hypervisor not available");
        return;
    }
    let _guard = match TEST_VM_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    drop(
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init(),
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let kernel = amla_container::KERNEL;
        let p = amla_container::build_rootfs().expect("build rootfs");
        let rootfs = amla_vmm::MemHandle::allocate_and_write(c"rootfs", p.image_size(), |buf| {
            p.write_to(buf)
                .map_err(|e| std::io::Error::other(e.to_string()))
        })
        .expect("rootfs handle");
        let container_image = build_permission_test_image();

        let config = VmConfig::default()
            .memory_mb(256)
            .pmem_root(rootfs.size().as_u64())
            .try_pmem_overlay(
                vec![amla_vmm::PmemImageConfig::overlay(
                    container_image.size().as_u64(),
                )],
                "/mnt",
            )
            .expect("valid overlay config");

        let pools = BackendPools::new(2, &config, worker_config()).expect("pools");
        let console = ConsoleStream::new();
        let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
            console: &console,
            net: None,
            fs: None,
            pmem: vec![rootfs, container_image],
        };
        let vm = VirtualMachine::create(config).await.expect("create VM");
        let vm = vm
            .load_kernel(&pools, kernel, backends)
            .await
            .expect("load kernel");

        let (_vm, ()) = vm
            .run(async move |handle| {
                let handle = handle.start();
                let mut container =
                    tokio::time::timeout(TIMEOUT, init_container(&handle, "test", config_json))
                        .await
                        .expect("init timed out")
                        .expect("init failed");
                if let Some(mut stdout) = container.init.take_stdout() {
                    tokio::spawn(async move { while stdout.recv().await.is_some() {} });
                }
                f(&container.handle).await;
                drop(container.init.close_stdin().await);
                drop(tokio::time::timeout(TIMEOUT, container.init.wait()).await);
            })
            .await
            .expect("run VM");
    });
}

/// Helper: run a command and return its collected output.
async fn run_cmd(
    c: &amla_container::DirectContainerHandle<'_, '_>,
    argv: &[&str],
) -> amla_vmm::CollectedOutput {
    let mut cmd = c.run(argv).await.expect("run");
    tokio::time::timeout(TIMEOUT, cmd.collect_output())
        .await
        .expect("timed out")
        .expect("collect")
}

// ─── Permission tests ──────────────────────────────────────────────────

/// Named user resolution: OCI config has "username": "testuser",
/// guest resolves via /etc/passwd to uid=1000, gid=1000.
#[test]
fn test_named_user_resolution() {
    with_permission_container(TESTUSER_CONFIG_JSON, async |c| {
        // `id` prints the effective uid — should be 1000 (testuser).
        let out = run_cmd(c, &["/bin/amla-guest", "id"]).await;
        assert_eq!(
            out.exit_code,
            0,
            "id failed: stdout={:?} stderr={:?}",
            out.stdout_str(),
            out.stderr_str()
        );
        let stdout = out.stdout_str();
        let uid_str = stdout.trim();
        assert_eq!(uid_str, "1000", "expected uid 1000, got {uid_str:?}");
    });
}

/// File ownership is preserved through the EROFS overlay.
#[test]
fn test_file_ownership_preserved() {
    with_permission_container(TESTUSER_CONFIG_JSON, async |c| {
        // stat /home/testuser/myfile.txt — should be 1000:1000 mode 644.
        let out = run_cmd(c, &["/bin/amla-guest", "stat", "/home/testuser/myfile.txt"]).await;
        assert_eq!(out.exit_code, 0);
        let stdout = out.stdout_str();
        let line = stdout.trim();
        assert!(
            line.starts_with("1000 1000 644"),
            "expected '1000 1000 644 ...', got {line:?}"
        );

        // stat /etc/shadow — should be 0:0 mode 600.
        let out = run_cmd(c, &["/bin/amla-guest", "stat", "/etc/shadow"]).await;
        assert_eq!(out.exit_code, 0);
        let stdout = out.stdout_str();
        let line = stdout.trim();
        assert!(
            line.starts_with("0 0 600"),
            "expected '0 0 600 ...', got {line:?}"
        );
    });
}

/// testuser can read their own file but NOT root's shadow file.
#[test]
fn test_permission_enforcement() {
    with_permission_container(TESTUSER_CONFIG_JSON, async |c| {
        // testuser (uid 1000) can read their own file.
        let out = run_cmd(c, &["/bin/amla-guest", "cat", "/home/testuser/myfile.txt"]).await;
        assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr_str());
        assert!(out.stdout_str().contains("hello from testuser"));

        // testuser cannot read /etc/shadow (mode 600, owned by root).
        let out = run_cmd(c, &["/bin/amla-guest", "cat", "/etc/shadow"]).await;
        assert_ne!(out.exit_code, 0, "shadow should be unreadable by testuser");
    });
}

/// /etc/passwd is readable and contains the expected users.
#[test]
fn test_passwd_readable() {
    with_permission_container(TESTUSER_CONFIG_JSON, async |c| {
        let out = run_cmd(c, &["/bin/amla-guest", "cat", "/etc/passwd"]).await;
        assert_eq!(out.exit_code, 0);
        let content = out.stdout_str();
        assert!(content.contains("testuser:x:1000:1000"), "got: {content:?}");
        assert!(content.contains("root:x:0:0"), "got: {content:?}");
    });
}

// ─── Original tests ────────────────────────────────────────────────────

/// Basic command inside the container namespace.
#[test]
fn test_container_run_echo() {
    with_container(async |c| {
        let mut cmd = c
            .run(["/bin/amla-guest", "echo", "container-ok"])
            .await
            .expect("run");
        let output = tokio::time::timeout(TIMEOUT, cmd.collect_output())
            .await
            .expect("timed out")
            .expect("collect");
        assert_eq!(output.exit_code, 0);
        assert!(
            output.stdout_str().contains("container-ok"),
            "got: {:?}",
            output.stdout_str()
        );
    });
}

/// Exit codes forwarded from container.
#[test]
fn test_container_exit_code() {
    with_container(async |c| {
        let mut cmd = c
            .run(["/bin/amla-guest", "exit-with", "42"])
            .await
            .expect("run");
        let output = tokio::time::timeout(TIMEOUT, cmd.collect_output())
            .await
            .expect("timed out")
            .expect("collect");
        assert_eq!(output.exit_code, 42);
    });
}

/// Env vars via builder pattern.
#[test]
fn test_container_env_vars() {
    with_container(async |c| {
        let mut cmd = c
            .run(["/bin/amla-guest", "printenv", "MY"])
            .env(["MY=container-42"])
            .await
            .expect("run");
        let output = tokio::time::timeout(TIMEOUT, cmd.collect_output())
            .await
            .expect("timed out")
            .expect("collect");
        assert_eq!(output.exit_code, 0);
        assert!(
            output.stdout_str().contains("container-42"),
            "got: {:?}",
            output.stdout_str()
        );
    });
}

/// Streaming output via `recv_output()`.
#[test]
fn test_container_streaming() {
    with_container(async |c| {
        let mut all_stdout = Vec::new();

        for word in ["one", "two", "three"] {
            let mut cmd = c.run(["/bin/amla-guest", "echo", word]).await.expect("run");
            let output = tokio::time::timeout(TIMEOUT, cmd.collect_output())
                .await
                .expect("timed out")
                .expect("collect");
            assert_eq!(output.exit_code, 0);
            all_stdout.extend_from_slice(output.stdout_str().as_bytes());
        }

        let text = String::from_utf8_lossy(&all_stdout);
        assert!(text.contains("one"), "missing 'one': {text:?}");
        assert!(text.contains("two"), "missing 'two': {text:?}");
        assert!(text.contains("three"), "missing 'three': {text:?}");
    });
}

/// Multiple sequential commands share the same container state.
#[test]
fn test_container_sequential() {
    with_container(async |c| {
        // First command: run echo and verify it works.
        let mut cmd = c
            .run(["/bin/amla-guest", "echo", "step-one"])
            .await
            .expect("echo");
        let out = tokio::time::timeout(TIMEOUT, cmd.collect_output())
            .await
            .expect("timed out")
            .expect("collect");
        assert_eq!(out.exit_code, 0);
        assert!(
            out.stdout_str().contains("step-one"),
            "got: {:?}",
            out.stdout_str()
        );

        // Second command: verify container is still alive and responsive.
        let mut cmd = c
            .run(["/bin/amla-guest", "echo", "step-two"])
            .await
            .expect("echo");
        let out = tokio::time::timeout(TIMEOUT, cmd.collect_output())
            .await
            .expect("timed out")
            .expect("collect");
        assert_eq!(out.exit_code, 0);
        assert!(
            out.stdout_str().contains("step-two"),
            "got: {:?}",
            out.stdout_str()
        );
    });
}
