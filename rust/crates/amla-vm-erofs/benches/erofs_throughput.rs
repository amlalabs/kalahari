// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used)]
//! EROFS builder throughput benchmarks.

use std::io::Cursor;

use amla_erofs::{Body, Entry, ErofsWriter, Metadata, Permissions};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn meta(mode: u16) -> Metadata {
    Metadata {
        permissions: Permissions::try_from(mode & Permissions::MASK).unwrap(),
        uid: 1000,
        gid: 1000,
        mtime: 0,
        mtime_nsec: 0,
        xattrs: vec![],
    }
}

fn root() -> Entry {
    Entry {
        path: "/".into(),
        metadata: meta(0o040_755),
        body: Body::Directory,
    }
}

fn bench_small_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("small_files");
    let file_data = vec![0xABu8; 512];

    for &count in &[1_000, 10_000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &n| {
            b.iter(|| {
                let mut ew = ErofsWriter::new(Cursor::new(Vec::new()));
                ew.push(root()).unwrap();
                for i in 0..n {
                    ew.push(Entry {
                        path: format!("/f_{i}"),
                        metadata: meta(0o100_644),
                        body: Body::RegularFile(file_data.clone()),
                    })
                    .unwrap();
                }
                ew.finish().unwrap()
            });
        });
    }
    group.finish();
}

fn bench_large_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_files");
    let file_data = vec![0xCDu8; 1_000_000];

    for &count in &[10, 100] {
        let bytes = count as u64 * file_data.len() as u64;
        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &n| {
            b.iter(|| {
                let mut ew =
                    ErofsWriter::new(Cursor::new(Vec::with_capacity(n * 1_000_000 + 65536)));
                ew.push(root()).unwrap();
                for i in 0..n {
                    ew.push(Entry {
                        path: format!("/f_{i}"),
                        metadata: meta(0o100_644),
                        body: Body::RegularFile(file_data.clone()),
                    })
                    .unwrap();
                }
                ew.finish().unwrap()
            });
        });
    }
    group.finish();
}

fn bench_push_file_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("push_file_streaming");
    let file_data = vec![0xCDu8; 1_000_000];

    for &count in &[10, 100] {
        let bytes = count as u64 * file_data.len() as u64;
        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &n| {
            b.iter(|| {
                let mut ew =
                    ErofsWriter::new(Cursor::new(Vec::with_capacity(n * 1_000_000 + 65536)));
                ew.push(root()).unwrap();
                for i in 0..n {
                    ew.push_file(
                        format!("/f_{i}"),
                        meta(0o100_644),
                        file_data.len() as u64,
                        &mut file_data.as_slice(),
                    )
                    .unwrap();
                }
                ew.finish().unwrap()
            });
        });
    }
    group.finish();
}

fn bench_mixed_oci_layer(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_oci_layer");
    let small_data = vec![0xAAu8; 256];
    let medium_data = vec![0xBBu8; 32_768];
    let large_data = vec![0xCCu8; 5_000_000];
    let total_data = 5000 * 256 + 200 * 32768 + 10 * 5_000_000;

    group.throughput(Throughput::Bytes(total_data));
    group.bench_function("5266_entries", |b| {
        b.iter(|| {
            let mut ew = ErofsWriter::new(Cursor::new(Vec::new()));
            ew.push(root()).unwrap();
            for d in &["/usr", "/usr/bin", "/usr/lib", "/etc", "/var", "/tmp"] {
                ew.push(Entry {
                    path: (*d).into(),
                    metadata: meta(0o040_755),
                    body: Body::Directory,
                })
                .unwrap();
            }
            for i in 0..5000 {
                ew.push(Entry {
                    path: format!("/etc/c_{i}"),
                    metadata: meta(0o100_644),
                    body: Body::RegularFile(small_data.clone()),
                })
                .unwrap();
            }
            for i in 0..200 {
                ew.push(Entry {
                    path: format!("/usr/lib/l_{i}.so"),
                    metadata: meta(0o100_755),
                    body: Body::RegularFile(medium_data.clone()),
                })
                .unwrap();
            }
            for i in 0..10 {
                ew.push_file(
                    format!("/usr/bin/p_{i}"),
                    meta(0o100_755),
                    large_data.len() as u64,
                    &mut large_data.as_slice(),
                )
                .unwrap();
            }
            for i in 0..50 {
                ew.push(Entry {
                    path: format!("/usr/bin/l_{i}"),
                    metadata: meta(0o120_777),
                    body: Body::Symlink(format!("p_{}", i % 10)),
                })
                .unwrap();
            }
            ew.finish().unwrap()
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_small_files,
    bench_large_files,
    bench_push_file_streaming,
    bench_mixed_oci_layer,
);
criterion_main!(benches);
