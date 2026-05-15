# amla-vm-erofs

Pure Rust EROFS image builder and reader.

Crate name: `amla-vm-erofs`. Library name: `amla_erofs`. `#![forbid(unsafe_code)]`.

## What It Does

Builds and reads [EROFS](https://erofs.docs.kernel.org/) images entirely in
Rust. EROFS is a compact, read-only filesystem format — the layout used here
targets VM rootfs images mapped via virtio-pmem (block size = guest page size,
so DAX works).

The builder is streaming and tar-like: you push entries with a path,
metadata, and a body. Large regular-file data is written to the output
during `push()` so memory usage stays O(metadata). Metadata is written on
`finish()`.

## Key Types

From `amla_erofs::`:

- `ErofsWriter<W>` — streaming builder over any `W: Write + Seek`.
  Methods: `new(writer)`, `push(Entry)`, `push_file(path, metadata, size, reader)`,
  `finish() -> (W, ImageStats)`, `finish_to_vec() -> BuiltImage`.
- `Entry { path, metadata, body }` — input item. `body: Body` is one of
  `Directory`, `RegularFile(Vec<u8>)`, `Symlink(String)`, `Hardlink(String)`,
  `DeviceNode { kind, rdev }`, `Fifo`, `Socket`.
- `DeviceKind` — `Character` or `Block` for device nodes.
- `Metadata { permissions, uid, gid, mtime, mtime_nsec, xattrs }` — POSIX metadata.
  `permissions` is a `Permissions` value and never includes `S_IFMT` bits;
  inode file type is derived from `Body`.
- `Xattr { key, value }` — extended attribute.
- `ImageStats { image_size, inode_count, block_count }` — build statistics.
- `BuiltImage` — byte buffer returned from `finish_to_vec()`. Exposes
  `image_size()`, `into_vec()`, `as_bytes()`, `write_to(buf)`.
- `build_erofs(entries, writer) -> ImageStats` — convenience wrapper over
  `ErofsWriter::new` + `push` loop + `finish`.
- `build_to_vec(entries) -> BuiltImage` — same, but into a `Vec<u8>`.
- `ErofsImage<'a>` — read-only image parser. Methods: `new(data)`,
  `root_nid()`, `inode(nid) -> InodeInfo`, `read_file(nid, offset, len)`,
  `read_file_slice(nid, offset, len)`, `readdir(nid)`, `readlink(nid)`,
  `readlink_slice(nid)`, `lookup(dir_nid, name)` (single component),
  `resolve(absolute_path)` (multi-component).
- `InodeInfo` — parsed inode (mode, nlink, size, uid, gid, layout, etc.)
  plus `is_dir()` / `is_reg()` / `is_symlink()` / `is_chrdev()` / `is_blkdev()` /
  `is_fifo()` / `is_socket()` predicates.
- `DirEntry { nid, name, file_type }` — entry returned by `readdir()` /
  `lookup()`, plus `name_str()`.
- `ErofsError` — error enum.

Constants: `EROFS_MAGIC`, `BLOCK_SIZE`, `BLOCK_SIZE_BITS`, `SUPERBLOCK_OFFSET`.

## Usage

### Build an image

```rust,ignore
use std::io::Cursor;
use amla_erofs::{Body, Entry, ErofsWriter, Metadata, Permissions};

fn dir(path: &str) -> Entry {
    Entry {
        path: path.into(),
        metadata: Metadata {
            permissions: Permissions::try_from(0o755).unwrap(),
            uid: 0, gid: 0, mtime: 0, mtime_nsec: 0,
            xattrs: vec![],
        },
        body: Body::Directory,
    }
}

fn file(path: &str, data: Vec<u8>) -> Entry {
    Entry {
        path: path.into(),
        metadata: Metadata {
            permissions: Permissions::try_from(0o755).unwrap(),
            uid: 0, gid: 0, mtime: 0, mtime_nsec: 0,
            xattrs: vec![],
        },
        body: Body::RegularFile(data),
    }
}

let mut w = ErofsWriter::new(Cursor::new(Vec::<u8>::new()));
w.push(dir("/"))?;
w.push(dir("/bin"))?;
w.push(file("/bin/hello", b"#!/bin/sh\necho hello\n".to_vec()))?;
w.push(Entry {
    path: "/bin/link".into(),
    metadata: Metadata {
        permissions: Permissions::try_from(0o777).unwrap(),
        uid: 0, gid: 0, mtime: 0, mtime_nsec: 0,
        xattrs: vec![],
    },
    body: Body::Symlink("hello".into()),
})?;

let (cursor, stats) = w.finish()?;
let image_bytes: Vec<u8> = cursor.into_inner();
let _ = stats.image_size;
```

For large regular files, use `push_file(path, metadata, size, &mut reader)`
to stream bytes straight from a `Read` into the output.

### Read an image

```rust,ignore
use amla_erofs::ErofsImage;

let image = ErofsImage::new(&image_bytes)?;
let root = image.root_nid();

// List a directory.
for entry in image.readdir(root)? {
    if let Some(name) = entry.name_str() {
        println!("{name}");
    }
}

// Look up a single component relative to a directory NID.
if let Some(bin) = image.lookup(root, b"bin")? {
    if let Some(hello) = image.lookup(bin.nid, b"hello")? {
        let info = image.inode(hello.nid)?;
        let data = image.read_file(hello.nid, 0, info.size as usize)?;
        let _ = data;
    }
}

// Or resolve a full absolute path in one call.
let nid = image.resolve("/bin/hello")?;
let info = image.inode(nid)?;
let _ = image.read_file(nid, 0, info.size as usize)?;
```

Note: `lookup` only resolves a single path component. Use `resolve` for
`/a/b/c` style paths.

## Where It Fits

Used by the VM rootfs / pmem image pipeline. `amla-oci` (OCI bundle handling)
and the guest / test rootfs crates build EROFS images through this crate,
and `amla-vm-vmm` exposes them via virtio-pmem with DAX.

## License

AGPL-3.0-or-later OR BUSL-1.1
