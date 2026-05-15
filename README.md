# @amlalabs/kalahari

This repository is the release source for the
[@amlalabs/kalahari](https://www.npmjs.com/package/@amlalabs/kalahari) npm
package. It exists so that the npm package, its prebuilt native bindings, and
the underlying Rust sources are auditable in one place.

Kalahari is a local microVM sandbox API for agent code. The TypeScript package
is intentionally thin: lifecycle, image preparation, command execution, and VM
scheduling live in the Rust `kalahari` crate (under `rust/`) exposed through
Node-API.

Provider compatibility modules are migration shims. New code should use
`KalahariClient` and `KalahariSandbox` directly; the E2B, Daytona, ComputeSDK,
and Harbor exports exist so teams can adapt existing integrations without
changing their whole call site in one step.

## Install

```sh
npm install @amlalabs/kalahari
```

Prebuilt native bindings ship for linux x64 (glibc), linux arm64 (glibc), and
darwin arm64. Other platforms (Windows, FreeBSD, Alpine/musl Linux, darwin x64)
are not yet supported; please open an issue if you need one.

## Quick start

```ts
import { KalahariClient } from "@amlalabs/kalahari";

const client = new KalahariClient({
  image: "python:3.12-alpine",
  memoryMb: 2048,
  vcpus: 1,
});

const sandbox = await client.createSandbox();
await sandbox.mkdir("/workspace");
await sandbox.writeFile("/workspace/main.py", "print('hello from kalahari')\n");

const result = await sandbox.run("python3", {
  args: ["/workspace/main.py"],
  cwd: "/workspace",
});
console.log(result.stdout);
await sandbox.destroy();
```

One-shot commands:

```ts
import { runCommand } from "@amlalabs/kalahari";

const result = await runCommand({
  image: "node:22-alpine",
  command: "node",
  args: ["--version"],
});
```

Compatibility shims for migration:

```ts
import { kalahari } from "@amlalabs/kalahari/computesdk";
import { Sandbox as E2BSandbox } from "@amlalabs/kalahari/e2b";
import { Daytona } from "@amlalabs/kalahari/daytona";
import { createHarborEnvironment } from "@amlalabs/kalahari/harbor";
```

See the [npm package page](https://www.npmjs.com/package/@amlalabs/kalahari)
for the full API surface.

## Building from source

```sh
npm install
npm run build:native   # builds the Node-API addon from rust/crates/kalahari
npm run build          # also runs tsc
```

The `rust/` directory in this mirror is a pruned cargo workspace containing the
`kalahari` crate and its workspace-internal dependencies. It is regenerated on
each release; do not rely on edits surviving across releases.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Pull requests against this mirror
may conflict with generated release output, so please open an issue before
starting large changes.

## License

AGPL-3.0-or-later OR BUSL-1.1. See `LICENSE` and `LICENSES/`.
