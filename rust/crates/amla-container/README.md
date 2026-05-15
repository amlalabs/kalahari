# amla-container

Run OCI containers inside lightweight KVM virtual machines.

## Overview

amla-container provides a programmatic API (and CLI) for booting container images in isolated KVM VMs, executing commands inside them, and managing their lifecycle. Think of it as a Rust-native `docker run` that uses micro-VMs instead of kernel namespaces.

Each container runs in its own KVM VM with:

- Dedicated kernel and memory
- Virtio-pmem EROFS rootfs (read-only, zero-copy)
- Virtio-net networking via userspace NAT
- OCI runtime (runc) for process isolation inside the VM
- Seccomp sandboxing on the host VMM process

## Architecture

```
amla-oci-unpack             OCI image -> OCI bundle -> EROFS conversion
    |
amla-dockerfile-builder     Dockerfile -> EROFS via Docker-in-VM (runtime download)
    |
amla-container              High-level container API (run_oneshot + ContainerRuntime)
    |
amla-container-cli          Docker-like CLI
```

Dependencies from the amla-vm workspace (not part of this workspace):

- `amla-erofs` — Pure Rust EROFS filesystem builder/reader
- `amla-guest-rootfs` — Base VM rootfs (coreutils + guest agent + kernel)
- `amla-vmm` — Virtual machine monitor

### Image pipeline

Container images flow through a build-time pipeline:

1. **OCI layout** (e.g. from `skopeo copy`) is stored as a directory
2. **amla-oci-unpack** extracts layers, merges them with whiteout processing, generates `config.json`
3. **amla-erofs** packs the OCI bundle into a compact read-only EROFS image
4. The EROFS image is embedded as `&'static [u8]` via `include_bytes!` in the rootfs crates
5. At runtime, EROFS images are mapped into VM memory as virtio-pmem devices

### Runtime flow

1. `amla_container::run_oneshot(erofs, config, vcpus, |container| { ... })` boots a VM and calls the closure
2. Inside the closure, `container.run()` executes commands via the guest agent, returning a streaming I/O handle
3. When the closure returns, the VM is torn down automatically

No persistent state, no runtime object to manage.

## Crates

| Crate | Description |
|-------|-------------|
| [amla-oci-unpack](crates/amla-oci-unpack/) | OCI image layout to OCI bundle unpacker |
| [amla-dockerfile-builder](crates/amla-dockerfile-builder/) | Dockerfile to EROFS via Docker-in-VM |
| [amla-container](crates/amla-container/) | High-level container API |
| [amla-container-cli](crates/amla-container-cli/) | Docker-like CLI for running containers |

## Quick start

### Programmatic API

```rust
use amla_container::ContainerConfig;

// Load a container image as EROFS
let erofs = amla_container::load_oci_image("/path/to/oci-image".as_ref())?;

// Boot a VM and run a command
let config = ContainerConfig::default()
    .name("my-app")
    .memory_mb(512);

amla_container::run_oneshot(
    erofs,
    config,
    2, // vCPUs
    async |container| {
        let mut cmd = container.run(&["echo", "hello"], &[]).await.unwrap();
        let _ = cmd.close_stdin().await;
        let exit_code = cmd.wait().await.unwrap();
        assert_eq!(exit_code, 0);
    },
).await?;
```

### CLI

```bash
# Run a command in a container from a local OCI image directory
amla-container run ./my-oci-image -- echo "hello world"

# With custom resources
amla-container run --memory 512 --cpus 2 ./my-oci-image -- sh -c "uname -a"

# With environment variables
amla-container run -e FOO=bar -e BAZ=qux ./my-oci-image -- env
```

### Multi-VM with ContainerRuntime

```rust
// Create a shared runtime (caches kernel + rootfs across boots)
let rt = amla_container::ContainerRuntime::new(4 /* max_vms */, 2 /* vcpus */)?;

// Boot multiple VMs from the same runtime
let erofs = amla_container::load_oci_image("/path/to/image".as_ref())?;
rt.run(erofs, ContainerConfig::default(), async |container| {
    // container.run(), container.run_pty(), container.run_host()
}).await?;
```

### Building images from Dockerfiles

```rust
use amla_dockerfile_builder::{DockerfileBuilder, DockerfileBuilderConfig};

let config = DockerfileBuilderConfig::new("/tmp/cache");
let builder = DockerfileBuilder::new(config)?;

// Build and cache the EROFS image (uses Docker-in-VM)
let erofs = builder.build("FROM alpine:latest\nRUN apk add curl\n").await?;
```

## Testing

```bash
cd src/rust/amla-container

# Unit tests (no KVM required)
cargo test --workspace --lib

# Full test suite (requires KVM)
cargo test --workspace

# Integration tests only
cargo test -p amla-container --test container_boot
cargo test -p amla-container --test container_network
cargo test -p amla-container --test dockerfile_build  # requires network
```

## License

AGPL-3.0-or-later OR BUSL-1.1
