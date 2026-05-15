import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { NativeBinding } from "./types.js";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "..");
const nativeDir = resolve(packageRoot, "native");
const checkedWorkerPaths = new Set<string>();

let binding: NativeBinding | undefined;

export function loadNativeBinding(): NativeBinding {
  if (binding) {
    return binding;
  }

  // Delegate to the napi-rs generated wrapper. It handles platform/arch/libc
  // detection, prefers a local `./kalahari.<triple>.node` (dev checkout), and
  // falls back to `require("@amlalabs/kalahari-<triple>")` resolved from
  // optionalDependencies (published install).
  try {
    binding = require(resolve(nativeDir, "index.js")) as NativeBinding;
  } catch (err) {
    throw improveLoaderError(err);
  }
  return binding;
}

// The napi-rs wrapper throws "Cannot find native binding. npm has a bug
// related to optional dependencies..." whenever it exhausts its candidate
// list. That hint points at npm issue #4828, which is irrelevant when the
// user deliberately stripped optionalDependencies (--omit=optional,
// --no-optional, or an .npmrc with `omit=optional`). Translate to a clearer
// message only when the host's expected per-arch package is genuinely
// absent; otherwise pass the original error through so libc/ABI mismatches
// remain debuggable.
function improveLoaderError(err: unknown): Error {
  const original = err instanceof Error ? err : new Error(String(err));
  const expected = expectedHostPackage();
  if (!expected) return original;

  try {
    require.resolve(`${expected}/package.json`);
    return original;
  } catch {
    // Fall through: package not installed.
  }

  const detail = original.message
    ? `\n\nUnderlying loader error: ${original.message}`
    : "";
  const improved = new Error(
    `@amlalabs/kalahari: per-arch binding package ${expected} is not installed.\n` +
      `This usually means your package manager skipped optionalDependencies ` +
      `(npm \`--omit=optional\` / \`--no-optional\`, pnpm \`--no-optional\`, ` +
      `yarn \`--ignore-optional\`, or an .npmrc with \`omit=optional\`). ` +
      `Reinstall without omitting optional dependencies, or install ` +
      `${expected} directly.${detail}`,
  );
  (improved as Error & { cause?: unknown }).cause = original;
  return improved;
}

function expectedHostPackage(): string | undefined {
  if (process.platform === "darwin" && process.arch === "arm64") {
    return "@amlalabs/kalahari-darwin-arm64";
  }
  if (process.platform === "linux") {
    // Only glibc builds are published. On musl, the napi-rs wrapper's
    // candidate list won't match this name anyway; let its original
    // diagnostic surface in that case.
    if (process.arch === "x64") return "@amlalabs/kalahari-linux-x64-gnu";
    if (process.arch === "arm64") return "@amlalabs/kalahari-linux-arm64-gnu";
  }
  return undefined;
}

export function resolveWorkerPath(explicit?: string): string | undefined {
  if (explicit) {
    return checkedHvfWorkerPath(explicit);
  }
  if (process.platform !== "darwin") {
    return undefined;
  }

  const localCandidate = join(nativeDir, "amla-hvf-worker");
  if (existsSync(localCandidate)) {
    return checkedHvfWorkerPath(localCandidate);
  }

  try {
    const subpkg =
      require.resolve("@amlalabs/kalahari-darwin-arm64/package.json");
    const candidate = join(dirname(subpkg), "amla-hvf-worker");
    if (existsSync(candidate)) {
      return checkedHvfWorkerPath(candidate);
    }
  } catch {
    // Per-arch package not installed (non-darwin host or missing optionalDep).
  }

  return undefined;
}

function checkedHvfWorkerPath(workerPath: string): string {
  if (process.platform !== "darwin" || checkedWorkerPaths.has(workerPath)) {
    return workerPath;
  }

  const checker = resolve(packageRoot, "scripts/check-hvf-worker.mjs");
  if (!existsSync(checker)) {
    return workerPath;
  }

  const result = spawnSync(process.execPath, [checker, workerPath], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr]
      .filter(Boolean)
      .join("\n")
      .trim();
    throw new Error(
      output ||
        `@amlalabs/kalahari: amla-hvf-worker failed macOS signature checks.`,
    );
  }

  checkedWorkerPaths.add(workerPath);
  return workerPath;
}

// Exported for tests that assert the candidate-name shape per platform.
// The loader itself delegates to the napi-rs wrapper; this helper just
// describes which `.node` filenames the wrapper would look for.
export function nativeBindingCandidateNames(
  platform = process.platform,
  arch = process.arch,
): string[] {
  const names = [`kalahari.${platform}-${arch}.node`];
  if (platform === "linux") {
    names.push(`kalahari.${platform}-${arch}-gnu.node`);
  }
  names.push("kalahari.node");
  return names;
}
