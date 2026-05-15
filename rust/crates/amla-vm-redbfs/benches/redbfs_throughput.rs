// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::doc_markdown)]
//! RedbFs benchmarks — exercises the FsBackend trait methods directly
//! (no FUSE/VM required).

use std::time::Duration;

use amla_fuse::fuse::{FsBackend, FuseContext};
use amla_vm_redbfs::RedbFs;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use tempfile::TempDir;
use tokio::runtime::Runtime;

const ROOT: u64 = 1;

const fn ctx() -> FuseContext {
    FuseContext {
        uid: 1000,
        gid: 1000,
    }
}

fn fresh_fs() -> (RedbFs, TempDir) {
    let td = tempfile::tempdir().unwrap();
    let p = td.path().join("bench.db");
    (RedbFs::create(&p).unwrap(), td)
}

async fn create_and_write(fs: &RedbFs, parent: u64, name: &[u8], data: &[u8]) -> u64 {
    let (entry, _) = fs.create(parent, name, 0o644, 0, ctx()).await.unwrap();
    if !data.is_empty() {
        fs.write(entry.nodeid, 0, 0, data, 0).await.unwrap();
    }
    entry.nodeid
}

fn short() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1))
}

fn bench_write(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut g = c.benchmark_group("write");
    g.sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1));

    // 64K aligned write (best case — one chunk, no RMW)
    g.throughput(Throughput::Bytes(64 * 1024));
    g.bench_function("64K_append", |b| {
        let (fs, _td) = fresh_fs();
        let ino = rt.block_on(async {
            fs.create(ROOT, b"f", 0o644, 0, ctx())
                .await
                .unwrap()
                .0
                .nodeid
        });
        let data = vec![0xABu8; 64 * 1024];
        let mut off = 0u64;
        b.iter(|| {
            rt.block_on(async { fs.write(ino, 0, off, &data, 0).await.unwrap() });
            off += data.len() as u64;
        });
    });

    // 1-byte write into existing 64K chunk (worst case — full RMW)
    g.throughput(Throughput::Bytes(1));
    g.bench_function("1B_partial_chunk_rmw", |b| {
        let (fs, _td) = fresh_fs();
        let ino = rt.block_on(create_and_write(&fs, ROOT, b"f", &vec![0u8; 65536]));
        let mut i = 0u64;
        b.iter(|| {
            let off = (i * 7919) % 65536;
            i += 1;
            rt.block_on(async { fs.write(ino, 0, off, &[0xFF], 0).await.unwrap() });
        });
    });
    g.finish();
}

fn bench_read(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut g = c.benchmark_group("read");
    g.sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1));

    let (fs, _td) = fresh_fs();
    let ino = rt.block_on(create_and_write(&fs, ROOT, b"f", &vec![0xCDu8; 256 * 1024]));

    g.throughput(Throughput::Bytes(64 * 1024));
    g.bench_function("64K_seq", |b| {
        let mut off = 0u64;
        b.iter(|| {
            rt.block_on(async {
                fs.read(ino, 0, off % (256 * 1024), 64 * 1024)
                    .await
                    .unwrap()
            });
            off += 64 * 1024;
        });
    });

    g.throughput(Throughput::Bytes(4096));
    g.bench_function("4K_random", |b| {
        let mut i = 0u64;
        b.iter(|| {
            let off = (i * 7919) % (256 * 1024 - 4096);
            i += 1;
            rt.block_on(async { fs.read(ino, 0, off, 4096).await.unwrap() });
        });
    });
    g.finish();
}

fn bench_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut g = c.benchmark_group("lookup");
    g.sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1));

    // Lookup in a directory with 500 entries
    let (fs, _td) = fresh_fs();
    let names: Vec<Vec<u8>> = (0..500).map(|i| format!("f_{i:04}").into_bytes()).collect();
    rt.block_on(async {
        for name in &names {
            fs.create(ROOT, name, 0o644, 0, ctx()).await.unwrap();
        }
    });

    g.bench_function("in_500_entry_dir", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let name = &names[i % names.len()];
            i += 1;
            rt.block_on(async { fs.lookup(ROOT, name).await.unwrap() });
        });
    });
    g.finish();
}

fn bench_create(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut g = c.benchmark_group("create");
    g.sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1));

    // Each iteration: create 50 files in a fresh DB
    g.throughput(Throughput::Elements(50));
    g.bench_function("50_files", |b| {
        b.iter(|| {
            let (fs, _td) = fresh_fs();
            rt.block_on(async {
                for i in 0..50u64 {
                    let name = format!("f_{i}").into_bytes();
                    fs.create(ROOT, &name, 0o644, 0, ctx()).await.unwrap();
                }
            });
        });
    });
    g.finish();
}

fn bench_readdir(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut g = c.benchmark_group("readdir");
    g.sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1));

    let (fs, _td) = fresh_fs();
    rt.block_on(async {
        for i in 0..200u64 {
            let name = format!("f_{i:04}").into_bytes();
            fs.create(ROOT, &name, 0o644, 0, ctx()).await.unwrap();
        }
    });

    g.throughput(Throughput::Elements(200));
    g.bench_function("200_entries", |b| {
        b.iter(|| {
            rt.block_on(async { fs.readdir(ROOT, 0, 0, 65536).await.unwrap() });
        });
    });

    g.throughput(Throughput::Elements(200));
    g.bench_function("200_entries_plus", |b| {
        b.iter(|| {
            rt.block_on(async { fs.readdirplus(ROOT, 0, 0, 65536).await.unwrap() });
        });
    });
    g.finish();
}

fn bench_deep_tree(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut g = c.benchmark_group("deep_tree");
    g.sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1));

    let depth = 20u64;
    let (fs, _td) = fresh_fs();
    let mut dirs: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut parent = ROOT;
    rt.block_on(async {
        for i in 0..depth {
            let name = format!("d_{i}").into_bytes();
            let e = fs.mkdir(parent, &name, 0o755, ctx()).await.unwrap();
            dirs.push((parent, name));
            parent = e.nodeid;
        }
    });

    g.throughput(Throughput::Elements(depth));
    g.bench_function("20_level_walk", |b| {
        b.iter(|| {
            rt.block_on(async {
                for (p, name) in &dirs {
                    fs.lookup(*p, name).await.unwrap();
                }
            });
        });
    });
    g.finish();
}

fn bench_large_file(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut g = c.benchmark_group("large_file");
    g.sample_size(10).warm_up_time(Duration::from_secs(1));

    // Write: simulate FUSE splitting into max_write (128K) calls.
    let write_chunk = vec![0xABu8; 128 * 1024];
    for &mb in &[1, 4, 16, 64] {
        let total = mb * 1024 * 1024usize;
        let n_writes = total / write_chunk.len();
        g.throughput(Throughput::Bytes(total as u64));
        g.measurement_time(Duration::from_secs(if mb >= 16 { 5 } else { 3 }));
        g.bench_function(format!("write_{mb}MB"), |b| {
            b.iter(|| {
                let (fs, _td) = fresh_fs();
                rt.block_on(async {
                    let ino = fs
                        .create(ROOT, b"big", 0o644, 0, ctx())
                        .await
                        .unwrap()
                        .0
                        .nodeid;
                    for i in 0..n_writes {
                        fs.write(ino, 0, (i * write_chunk.len()) as u64, &write_chunk, 0)
                            .await
                            .unwrap();
                    }
                });
            });
        });
    }

    // Read: sequential 128K reads through a pre-written large file.
    for &mb in &[1, 4, 16, 64] {
        let total = mb * 1024 * 1024usize;
        g.throughput(Throughput::Bytes(total as u64));
        g.measurement_time(Duration::from_secs(if mb >= 16 { 5 } else { 3 }));
        g.bench_function(format!("read_{mb}MB"), |b| {
            let (fs, _td) = fresh_fs();
            let ino = rt.block_on(async {
                let ino = fs
                    .create(ROOT, b"big", 0o644, 0, ctx())
                    .await
                    .unwrap()
                    .0
                    .nodeid;
                for i in 0..(total / write_chunk.len()) {
                    fs.write(ino, 0, (i * write_chunk.len()) as u64, &write_chunk, 0)
                        .await
                        .unwrap();
                }
                ino
            });
            b.iter(|| {
                rt.block_on(async {
                    let mut off = 0u64;
                    while off < total as u64 {
                        let got = fs.read(ino, 0, off, 128 * 1024).await.unwrap();
                        off += got.len() as u64;
                    }
                });
            });
        });
    }

    // EROFS export of a single large file.
    for &mb in &[1, 16, 64] {
        let total = mb * 1024 * 1024usize;
        g.throughput(Throughput::Bytes(total as u64));
        g.measurement_time(Duration::from_secs(if mb >= 16 { 5 } else { 3 }));
        g.bench_function(format!("erofs_{mb}MB"), |b| {
            let (fs, _td) = fresh_fs();
            rt.block_on(async {
                let ino = fs
                    .create(ROOT, b"big", 0o644, 0, ctx())
                    .await
                    .unwrap()
                    .0
                    .nodeid;
                for i in 0..(total / write_chunk.len()) {
                    fs.write(ino, 0, (i * write_chunk.len()) as u64, &write_chunk, 0)
                        .await
                        .unwrap();
                }
                ino
            });
            b.iter(|| {
                let mut buf = std::io::Cursor::new(Vec::with_capacity(total + 65536));
                fs.to_erofs(&mut buf).unwrap();
            });
        });
    }
    g.finish();
}

fn bench_erofs_export(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut g = c.benchmark_group("erofs_export");
    g.sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1));

    let (fs, _td) = fresh_fs();
    let data = vec![0xBBu8; 1024];
    rt.block_on(async {
        for i in 0..100u64 {
            let name = format!("f_{i:04}").into_bytes();
            create_and_write(&fs, ROOT, &name, &data).await;
        }
    });
    let total = 100 * 1024u64;
    g.throughput(Throughput::Bytes(total));
    g.bench_function("100x1K", |b| {
        b.iter(|| {
            let mut buf = std::io::Cursor::new(Vec::new());
            fs.to_erofs(&mut buf).unwrap();
        });
    });
    g.finish();
}

fn bench_mixed(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut g = c.benchmark_group("mixed");
    g.sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1));

    g.bench_function("container_sim", |b| {
        b.iter(|| {
            let (fs, _td) = fresh_fs();
            rt.block_on(async {
                let upper = fs.mkdir(ROOT, b"upper", 0o755, ctx()).await.unwrap().nodeid;
                let etc = fs.mkdir(upper, b"etc", 0o755, ctx()).await.unwrap().nodeid;
                for i in 0..10u64 {
                    let name = format!("c_{i}").into_bytes();
                    create_and_write(&fs, etc, &name, b"key=val\n").await;
                }
                let log = fs.mkdir(upper, b"log", 0o755, ctx()).await.unwrap().nodeid;
                let log_data = "log line here\n".repeat(3000);
                for i in 0..3u64 {
                    let name = format!("l_{i}").into_bytes();
                    create_and_write(&fs, log, &name, log_data.as_bytes()).await;
                }
                for i in 0..10u64 {
                    let name = format!("c_{i}").into_bytes();
                    let e = fs.lookup(etc, &name).await.unwrap();
                    fs.read(e.nodeid, 0, 0, 4096).await.unwrap();
                }
                let mut buf = std::io::Cursor::new(Vec::new());
                fs.to_erofs_subtree("upper", &mut buf).unwrap();
            });
        });
    });
    g.finish();
}

criterion_group! {
    name = benches;
    config = short();
    targets =
        bench_write,
        bench_read,
        bench_lookup,
        bench_create,
        bench_readdir,
        bench_deep_tree,
        bench_large_file,
        bench_erofs_export,
        bench_mixed,
}
criterion_main!(benches);
