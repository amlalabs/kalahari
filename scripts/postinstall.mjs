import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { reportHvfWorkerCheck } from "./check-hvf-worker.mjs";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "..");

verifyNativeBinding();
verifyHvfWorker();

function verifyNativeBinding() {
  // The actual binding lives in a per-arch optionalDependency package
  // (e.g. `@amlalabs/kalahari-linux-x64-gnu`) that npm installs as a sibling
  // when its `os`/`cpu`/`libc` constraints match. We can't reliably check the
  // sibling here because npm's install order doesn't guarantee it has landed
  // when this hook runs. Instead, fail early when the host is one we know we
  // don't ship a binding for; the napi-rs wrapper produces a more detailed
  // diagnostic at first import if the optionalDep was unexpectedly skipped.
  if (!isHostSupported()) {
    fail(`${describeHost()} is not supported`);
  }
}

function verifyHvfWorker() {
  if (process.platform !== "darwin" || process.arch !== "arm64") {
    return;
  }

  const workerPath = resolveHvfWorkerPath();
  if (!workerPath) {
    // npm does not guarantee optionalDependencies are available when this
    // package's postinstall runs. The darwin optional package runs the same
    // checker against its own worker once its files are present.
    return;
  }

  if (!reportHvfWorkerCheck(workerPath)) {
    process.exit(1);
  }
}

function resolveHvfWorkerPath() {
  const localCandidate = resolve(packageRoot, "native/amla-hvf-worker");
  if (existsSync(localCandidate)) {
    return localCandidate;
  }

  try {
    const subpkg =
      require.resolve("@amlalabs/kalahari-darwin-arm64/package.json");
    const candidate = join(dirname(subpkg), "amla-hvf-worker");
    if (existsSync(candidate)) {
      return candidate;
    }
  } catch {
    // Optional dependency may not be installed yet.
  }

  return undefined;
}

function isHostSupported() {
  if (process.platform === "darwin") {
    return process.arch === "arm64";
  }
  if (process.platform === "linux") {
    if (isMusl()) return false;
    return process.arch === "x64" || process.arch === "arm64";
  }
  return false;
}

function describeHost() {
  const libc =
    process.platform === "linux" ? ` (${isMusl() ? "musl" : "glibc"})` : "";
  return `${process.platform}-${process.arch}${libc}`;
}

function isMusl() {
  if (process.platform !== "linux") return false;
  try {
    if (readFileSync("/usr/bin/ldd", "utf8").includes("musl")) return true;
  } catch {}
  try {
    if (typeof process.report?.getReport === "function") {
      process.report.excludeNetwork = true;
      const report = process.report.getReport();
      if (report?.header?.glibcVersionRuntime) return false;
      const sharedObjects = report?.sharedObjects ?? [];
      if (sharedObjects.some((o) => /libc\.musl-|ld-musl-/.test(o))) {
        return true;
      }
    }
  } catch {}
  return false;
}

function fail(reason) {
  console.error(
    `@amlalabs/kalahari: ${reason}.\n` +
      `Supported platforms: linux x64 (glibc), linux arm64 (glibc), darwin arm64.\n` +
      `If you need another platform, please open an issue.`,
  );
  process.exit(1);
}
