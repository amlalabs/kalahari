// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cast_possible_truncation)]

//! Integration tests for virtio-fs with an in-memory filesystem backend.
//!
//! Boots a VM with a simple `MemFs` backend, mounts it inside the guest,
//! then uses `exec` to read files from the mount.
//!
//! # Running
//!
//! ```bash
//! cargo test -p amla-vmm --test virtiofs -- --nocapture
//! ```

mod common;

use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;

use amla_fuse::fs_types::{ATTR_VALID_SECS, ENTRY_VALID_SECS, FUSE_ROOT_ID, mode_to_dtype};
use amla_fuse::fuse::{
    FUSE_ASYNC_READ, FsBackend, FuseAttrOut, FuseEntryOut, FuseInitOut, FuseOpenOut, FuseStatfsOut,
    pack_dirent,
};
use amla_fuse::fuse_abi::FuseError;
use amla_vmm::backend::BackendPools;
use amla_vmm::{Backends, ConsoleStream, FsConfig, VirtualMachine};
use tokio::sync::Notify;

const EXEC_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCKED_READ_TIMEOUT: Duration = Duration::from_secs(90);

// =============================================================================
// In-memory filesystem backend
// =============================================================================

const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;

/// A trivial in-memory filesystem for testing virtiofs.
///
/// Supports a single root directory with flat file entries (no subdirectories).
/// Files are read-only with fixed content.
struct MemFs {
    /// inode 1 = root dir, inode 2+ = files
    files: HashMap<u64, MemFile>,
    /// name -> inode for root directory children
    name_to_ino: HashMap<Vec<u8>, u64>,
    next_fh: AtomicU64,
    read_blocker: Option<ReadBlocker>,
}

struct MemFile {
    name: Vec<u8>,
    content: Vec<u8>,
    mode: u32,
}

struct ReadBlocker {
    nodeid: u64,
    armed: AtomicBool,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

struct NotifyOnDrop {
    notify: Arc<Notify>,
}

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.notify.notify_one();
    }
}

impl MemFs {
    fn new(files: Vec<(&str, &[u8])>) -> Self {
        let mut map = HashMap::new();
        let mut name_to_ino = HashMap::new();
        for (i, (name, content)) in files.into_iter().enumerate() {
            let ino = (i as u64) + 2; // inodes start at 2 (1 = root)
            name_to_ino.insert(name.as_bytes().to_vec(), ino);
            map.insert(
                ino,
                MemFile {
                    name: name.as_bytes().to_vec(),
                    content: content.to_vec(),
                    mode: S_IFREG | 0o644,
                },
            );
        }
        Self {
            files: map,
            name_to_ino,
            next_fh: AtomicU64::new(1),
            read_blocker: None,
        }
    }

    fn with_blocked_first_read(files: Vec<(&str, &[u8])>, blocked_name: &str) -> Self {
        let mut fs = Self::new(files);
        let nodeid = *fs
            .name_to_ino
            .get(blocked_name.as_bytes())
            .expect("blocked file exists");
        fs.read_blocker = Some(ReadBlocker {
            nodeid,
            armed: AtomicBool::new(true),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        });
        fs
    }

    const fn read_blocker(&self) -> &ReadBlocker {
        self.read_blocker.as_ref().expect("read blocker configured")
    }

    fn root_attr(&self) -> amla_fuse::fuse::FuseAttr {
        amla_fuse::fuse::FuseAttr {
            ino: FUSE_ROOT_ID,
            size: 4096,
            blocks: 8,
            mode: S_IFDIR | 0o755,
            nlink: 2 + self.files.len() as u32,
            blksize: 4096,
            ..Default::default()
        }
    }

    fn file_attr(ino: u64, file: &MemFile) -> amla_fuse::fuse::FuseAttr {
        amla_fuse::fuse::FuseAttr {
            ino,
            size: file.content.len() as u64,
            blocks: (file.content.len() as u64).div_ceil(512),
            mode: file.mode,
            nlink: 1,
            blksize: 4096,
            ..Default::default()
        }
    }
}

impl FsBackend for MemFs {
    async fn init(&self) -> Result<FuseInitOut, FuseError> {
        Ok(FuseInitOut {
            major: 7,
            minor: 31,
            max_readahead: 128 * 1024,
            flags: FUSE_ASYNC_READ,
            max_background: 64,
            congestion_threshold: 48,
            ..FuseInitOut::default()
        })
    }

    async fn lookup(&self, parent: u64, name: &[u8]) -> Result<FuseEntryOut, FuseError> {
        if parent != FUSE_ROOT_ID {
            return Err(FuseError::not_found());
        }
        let &ino = self.name_to_ino.get(name).ok_or(FuseError::not_found())?;
        let file = self.files.get(&ino).ok_or(FuseError::not_found())?;
        let attr = Self::file_attr(ino, file);
        Ok(FuseEntryOut {
            nodeid: ino,
            generation: 0,
            entry_valid: ENTRY_VALID_SECS,
            attr_valid: ATTR_VALID_SECS,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr,
        })
    }

    async fn forget(&self, _nodeid: u64, _nlookup: u64) {}
    async fn batch_forget(&self, _forgets: &[(u64, u64)]) {}

    async fn getattr(&self, nodeid: u64) -> Result<FuseAttrOut, FuseError> {
        let attr = if nodeid == FUSE_ROOT_ID {
            self.root_attr()
        } else {
            let file = self.files.get(&nodeid).ok_or(FuseError::not_found())?;
            Self::file_attr(nodeid, file)
        };
        Ok(FuseAttrOut::new(attr))
    }

    async fn readlink(&self, _nodeid: u64) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::invalid())
    }

    async fn open(&self, nodeid: u64, _flags: u32) -> Result<FuseOpenOut, FuseError> {
        if nodeid == FUSE_ROOT_ID || !self.files.contains_key(&nodeid) {
            return Err(FuseError::not_found());
        }
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        Ok(FuseOpenOut {
            fh,
            open_flags: 0,
            padding: 0,
        })
    }

    async fn read(
        &self,
        nodeid: u64,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        if let Some(blocker) = &self.read_blocker
            && nodeid == blocker.nodeid
            && offset == 0
            && blocker.armed.swap(false, Ordering::AcqRel)
        {
            blocker.entered.notify_one();
            blocker.release.notified().await;
        }

        let file = self.files.get(&nodeid).ok_or(FuseError::not_found())?;
        let offset = offset as usize;
        if offset >= file.content.len() {
            return Ok(Vec::new());
        }
        let end = file.content.len().min(offset + size as usize);
        Ok(file.content[offset..end].to_vec())
    }

    async fn release(&self, _nodeid: u64, _fh: u64) {}

    async fn opendir(&self, nodeid: u64) -> Result<FuseOpenOut, FuseError> {
        if nodeid != FUSE_ROOT_ID {
            return Err(FuseError::not_dir());
        }
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        Ok(FuseOpenOut {
            fh,
            open_flags: 0,
            padding: 0,
        })
    }

    async fn readdir(
        &self,
        _nodeid: u64,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        let max_size = size as usize;
        let mut buf = Vec::with_capacity(max_size.min(4096));
        let mut idx = offset;

        // Entry 0: "."
        if idx == 0 {
            if pack_dirent(
                &mut buf,
                max_size,
                FUSE_ROOT_ID,
                b".",
                1,
                mode_to_dtype(S_IFDIR | 0o755),
            ) == 0
            {
                return Ok(buf);
            }
            idx = 1;
        }
        // Entry 1: ".."
        if idx == 1 {
            if pack_dirent(
                &mut buf,
                max_size,
                FUSE_ROOT_ID,
                b"..",
                2,
                mode_to_dtype(S_IFDIR | 0o755),
            ) == 0
            {
                return Ok(buf);
            }
            idx = 2;
        }

        // Sorted file entries
        let mut entries: Vec<_> = self.files.iter().collect();
        entries.sort_by_key(|(_, f)| &f.name);
        let start = (idx as usize).saturating_sub(2);
        for (i, (ino, file)) in entries.iter().enumerate().skip(start) {
            let dir_offset = (i + 3) as u64;
            if pack_dirent(
                &mut buf,
                max_size,
                **ino,
                &file.name,
                dir_offset,
                mode_to_dtype(file.mode),
            ) == 0
            {
                break;
            }
        }

        Ok(buf)
    }

    async fn readdirplus(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        // Fall back to readdir -- the kernel will use lookup() for attrs.
        self.readdir(nodeid, fh, offset, size).await
    }

    async fn releasedir(&self, _nodeid: u64, _fh: u64) {}

    async fn statfs(&self) -> Result<FuseStatfsOut, FuseError> {
        Ok(FuseStatfsOut::default())
    }

    async fn access(&self, nodeid: u64, _mask: u32) -> Result<(), FuseError> {
        if nodeid == FUSE_ROOT_ID || self.files.contains_key(&nodeid) {
            Ok(())
        } else {
            Err(FuseError::not_found())
        }
    }

    async fn getxattr(&self, _nodeid: u64, _name: &[u8], _size: u32) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::no_data())
    }

    async fn listxattr(&self, _nodeid: u64, _size: u32) -> Result<Vec<u8>, FuseError> {
        Ok(Vec::new())
    }

    async fn get_parent(&self, _nodeid: u64) -> Result<FuseEntryOut, FuseError> {
        // MemFs root is the only directory; its parent is itself.
        Ok(FuseEntryOut::new(1, self.root_attr()))
    }
}

// =============================================================================
// Tests
// =============================================================================

struct ExecResult {
    stdout: String,
    stderr: String,
    exit_code: i32,
    #[allow(dead_code)]
    console: String,
}

/// Boot a VM with virtiofs + `MemFs`, exec a command, return results.
async fn boot_with_memfs(files: Vec<(&str, &[u8])>, cmd: &[&str]) -> ExecResult {
    boot_with_memfs_queues(files, cmd, 1).await
}

/// Boot a VM with virtiofs + `MemFs` and configurable request queue count.
async fn boot_with_memfs_queues(
    files: Vec<(&str, &[u8])>,
    cmd: &[&str],
    num_request_queues: u32,
) -> ExecResult {
    let kernel = amla_guest_rootfs::KERNEL;
    let image = common::rootfs_handle();

    let fs_backend = MemFs::new(files);

    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .fs(FsConfig::try_new("testfs", "/tmp/testfs")
            .expect("valid fs config")
            .with_request_queues(num_request_queues)
            .expect("num_request_queues in range"));

    let pools = BackendPools::new(2, &config, common::worker_config()).expect("create pools");

    let vm = VirtualMachine::create(config).await.expect("create VM");
    let console = ConsoleStream::new();
    let backends: Backends<'_, MemFs> = Backends {
        console: &console,
        net: None,
        fs: Some(&fs_backend),
        pmem: vec![image],
    };
    let vm = vm
        .load_kernel(&pools, kernel, backends)
        .await
        .expect("load kernel");

    let cmd_owned: Vec<String> = cmd.iter().map(std::string::ToString::to_string).collect();

    let (_vm, output) = vm
        .run(async move |handle| {
            let handle = handle.start();
            let cmd_refs: Vec<&str> = cmd_owned.iter().map(String::as_str).collect();
            let exec_cmd = handle.exec(&cmd_refs).await.expect("start command");
            tokio::time::timeout(EXEC_TIMEOUT, common::collect_output(exec_cmd))
                .await
                .expect("exec timed out")
        })
        .await
        .expect("run VM");

    ExecResult {
        stdout: output.stdout_str().to_string(),
        stderr: output.stderr_str().to_string(),
        exit_code: output.exit_code,
        console: String::new(),
    }
}

/// Read a single file from a virtiofs mount.
#[tokio::test(flavor = "multi_thread")]
async fn test_virtiofs_cat_file() {
    common::init_logging();
    if let Some(reason) = common::skip_checks() {
        eprintln!("Skipping: {reason}");
        return;
    }

    let content = b"Hello from virtiofs!\n";
    let result = boot_with_memfs(
        vec![("hello.txt", content)],
        &["/bin/amla-guest", "cat", "/tmp/testfs/hello.txt"],
    )
    .await;

    assert_eq!(
        result.exit_code, 0,
        "cat failed: stderr={:?}",
        result.stderr
    );
    assert_eq!(result.stdout, "Hello from virtiofs!\n");
}

/// Read multiple files from the same mount.
#[tokio::test(flavor = "multi_thread")]
async fn test_virtiofs_multiple_files() {
    common::init_logging();
    if let Some(reason) = common::skip_checks() {
        eprintln!("Skipping: {reason}");
        return;
    }

    let result = boot_with_memfs(
        vec![
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("c.txt", b"charlie"),
        ],
        &[
            "/bin/amla-guest",
            "cat",
            "/tmp/testfs/a.txt",
            "/tmp/testfs/b.txt",
            "/tmp/testfs/c.txt",
        ],
    )
    .await;

    assert!(
        result.stdout.contains("alpha"),
        "missing 'alpha', got: {:?}",
        result.stdout
    );
    assert!(
        result.stdout.contains("bravo"),
        "missing 'bravo', got: {:?}",
        result.stdout
    );
    assert!(
        result.stdout.contains("charlie"),
        "missing 'charlie', got: {:?}",
        result.stdout
    );
}

/// List the root directory of the virtiofs mount.
#[tokio::test(flavor = "multi_thread")]
async fn test_virtiofs_ls() {
    common::init_logging();
    if let Some(reason) = common::skip_checks() {
        eprintln!("Skipping: {reason}");
        return;
    }

    let result = boot_with_memfs(
        vec![("foo.txt", b"data"), ("bar.txt", b"data")],
        &["/bin/amla-guest", "ls", "/tmp/testfs/"],
    )
    .await;

    assert!(
        result.stdout.contains("foo.txt"),
        "missing 'foo.txt' in ls, got: {:?}",
        result.stdout
    );
    assert!(
        result.stdout.contains("bar.txt"),
        "missing 'bar.txt' in ls, got: {:?}",
        result.stdout
    );
}

/// Read a large file (64 KB) to exercise multi-read paths.
#[tokio::test(flavor = "multi_thread")]
async fn test_virtiofs_large_file() {
    common::init_logging();
    if let Some(reason) = common::skip_checks() {
        eprintln!("Skipping: {reason}");
        return;
    }

    // 64 KB of repeated pattern
    let pattern = b"ABCDEFGHIJKLMNOP";
    let mut content = Vec::with_capacity(64 * 1024);
    while content.len() < 64 * 1024 {
        content.extend_from_slice(pattern);
    }
    content.truncate(64 * 1024);

    let result = boot_with_memfs(
        vec![("big.bin", &content)],
        &["/bin/amla-guest", "cat", "/tmp/testfs/big.bin"],
    )
    .await;

    assert_eq!(
        result.exit_code, 0,
        "cat failed: stderr={:?}",
        result.stderr
    );
    let size = result.stdout.len();
    assert_eq!(size, 64 * 1024, "expected 65536 bytes, got {size}");
}

// =============================================================================
// Multi-queue tests
// =============================================================================

/// Read files with 4 request queues — verifies multi-queue device negotiation.
#[tokio::test(flavor = "multi_thread")]
async fn test_virtiofs_multi_queue_read() {
    common::init_logging();
    if let Some(reason) = common::skip_checks() {
        eprintln!("Skipping: {reason}");
        return;
    }

    let result = boot_with_memfs_queues(
        vec![
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("c.txt", b"charlie"),
        ],
        &[
            "/bin/amla-guest",
            "cat",
            "/tmp/testfs/a.txt",
            "/tmp/testfs/b.txt",
            "/tmp/testfs/c.txt",
        ],
        4, // 4 request queues
    )
    .await;

    assert_eq!(
        result.exit_code, 0,
        "multi-queue read failed: stderr={:?}",
        result.stderr
    );
    assert!(result.stdout.contains("alpha"));
    assert!(result.stdout.contains("bravo"));
    assert!(result.stdout.contains("charlie"));
}

/// Concurrent reads with maximum queues (9) — stress test queue negotiation.
#[tokio::test(flavor = "multi_thread")]
async fn test_virtiofs_max_queues() {
    common::init_logging();
    if let Some(reason) = common::skip_checks() {
        eprintln!("Skipping: {reason}");
        return;
    }

    // Create many small files to generate concurrent FUSE requests
    let mut files: Vec<(&str, &[u8])> = Vec::new();
    let names: Vec<String> = (0..20).map(|i| format!("file{i:02}.txt")).collect();
    for name in &names {
        files.push((name.as_str(), b"ok"));
    }

    let result = boot_with_memfs_queues(
        files,
        &["/bin/amla-guest", "ls", "/tmp/testfs/"],
        9, // maximum request queues
    )
    .await;

    assert_eq!(
        result.exit_code, 0,
        "max-queue ls failed: stderr={:?}",
        result.stderr
    );
    // Count lines in ls output — each file gets one line.
    let count = result.stdout.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(count, 20, "expected 20 files, got {count}");
}

/// Boot a real VM and keep several guest processes reading virtiofs at once.
///
/// This exercises the owned async fs path through the real MMIO/ioeventfd,
/// fs-worker, and used-ring publication flow. The first read is held pending
/// in the backend while later guest reads complete, which catches accidental
/// head-of-line blocking in the fs worker.
#[tokio::test(flavor = "multi_thread")]
async fn test_virtiofs_boot_concurrent_reads() {
    common::init_logging();
    if let Some(reason) = common::skip_checks() {
        eprintln!("Skipping: {reason}");
        return;
    }

    let a = vec![b'a'; 64 * 1024];
    let b = vec![b'b'; 64 * 1024];
    let c = vec![b'c'; 64 * 1024];
    let d = vec![b'd'; 64 * 1024];
    let fs_backend = MemFs::with_blocked_first_read(
        vec![("a.bin", &a), ("b.bin", &b), ("c.bin", &c), ("d.bin", &d)],
        "a.bin",
    );
    let entered = Arc::clone(&fs_backend.read_blocker().entered);
    let release = Arc::clone(&fs_backend.read_blocker().release);

    let kernel = amla_guest_rootfs::KERNEL;
    let image = common::rootfs_handle();
    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .fs(FsConfig::try_new("testfs", "/tmp/testfs")
            .expect("valid fs config")
            .with_request_queues(1)
            .expect("num_request_queues in range"));
    let pools = BackendPools::new(2, &config, common::worker_config()).expect("create pools");
    let vm = VirtualMachine::create(config).await.expect("create VM");
    let console = ConsoleStream::new();
    let backends: Backends<'_, MemFs> = Backends {
        console: &console,
        net: None,
        fs: Some(&fs_backend),
        pmem: vec![image],
    };
    let vm = vm
        .load_kernel(&pools, kernel, backends)
        .await
        .expect("load kernel");

    let (_vm, outputs) = vm
        .run(async move |handle| {
            let handle = handle.start();
            let cat_a = handle
                .exec(["/bin/amla-guest", "cat", "/tmp/testfs/a.bin"])
                .await
                .expect("start cat a");

            tokio::time::timeout(EXEC_TIMEOUT, entered.notified())
                .await
                .expect("slow read should enter backend");
            let release_guard = NotifyOnDrop {
                notify: Arc::clone(&release),
            };

            let cat_b = handle
                .exec(["/bin/amla-guest", "cat", "/tmp/testfs/b.bin"])
                .await
                .expect("start cat b");
            let cat_c = handle
                .exec(["/bin/amla-guest", "cat", "/tmp/testfs/c.bin"])
                .await
                .expect("start cat c");
            let cat_d = handle
                .exec(["/bin/amla-guest", "cat", "/tmp/testfs/d.bin"])
                .await
                .expect("start cat d");

            let (out_b, out_c, out_d) = tokio::join!(
                async {
                    tokio::time::timeout(BLOCKED_READ_TIMEOUT, common::collect_output(cat_b))
                        .await
                        .expect("cat b should complete while cat a is pending")
                },
                async {
                    tokio::time::timeout(BLOCKED_READ_TIMEOUT, common::collect_output(cat_c))
                        .await
                        .expect("cat c should complete while cat a is pending")
                },
                async {
                    tokio::time::timeout(BLOCKED_READ_TIMEOUT, common::collect_output(cat_d))
                        .await
                        .expect("cat d should complete while cat a is pending")
                },
            );

            release.notify_one();
            let out_a = tokio::time::timeout(BLOCKED_READ_TIMEOUT, common::collect_output(cat_a))
                .await
                .expect("cat a should complete after release");
            drop(release_guard);

            [out_a, out_b, out_c, out_d]
        })
        .await
        .expect("run VM");

    for (idx, output) in outputs.iter().enumerate() {
        assert_eq!(output.exit_code, 0, "cat {idx} failed: {output:?}");
        assert_eq!(output.stdout_str().len(), 64 * 1024);
    }
    assert!(outputs[0].stdout_str().bytes().all(|ch| ch == b'a'));
    assert!(outputs[1].stdout_str().bytes().all(|ch| ch == b'b'));
    assert!(outputs[2].stdout_str().bytes().all(|ch| ch == b'c'));
    assert!(outputs[3].stdout_str().bytes().all(|ch| ch == b'd'));
}
