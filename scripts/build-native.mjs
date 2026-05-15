import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "..");
const nativeDir = resolve(packageRoot, "native");
const rustRoot = resolveRustRoot();
const bindingCrate = resolve(rustRoot, "crates/kalahari");

function resolveRustRoot() {
  // Nested package layout: packages/kalahari -> ../../../rust
  const nestedWorkspaceCandidate = resolve(packageRoot, "../../../rust");
  // Release-source layout: <package_root>/rust (Rust workspace directly under the npm
  // package root, e.g. when the package is extracted into its own repo).
  const packageRootCandidate = resolve(packageRoot, "rust");
  if (existsSync(resolve(nestedWorkspaceCandidate, "Cargo.toml"))) {
    return nestedWorkspaceCandidate;
  }
  if (existsSync(resolve(packageRootCandidate, "Cargo.toml"))) {
    return packageRootCandidate;
  }
  throw new Error(
    `kalahari: cannot find Rust workspace; tried ${resolve(nestedWorkspaceCandidate, "Cargo.toml")} and ${resolve(packageRootCandidate, "Cargo.toml")}`,
  );
}

const args = process.argv.slice(2);
const explicitTargets = parseExplicitTargets(args);
const buildAllLinux = args.includes("--all-linux");
const buildAll = args.includes("--all");

const targets = resolveTargets();
const willBuildHvfWorker =
  process.platform === "darwin" ||
  buildAll ||
  targets.includes("aarch64-apple-darwin");

mkdirSync(nativeDir, { recursive: true });
removeStaleNativeArtifacts();

for (const target of targets) {
  buildNapi(target);
}

// Linux Kalahari uses the integrated in-process KVM backend in the native
// addon, so the npm package never ships an amla-kvm-worker. The HVF worker
// is the only out-of-process worker we build.
if (willBuildHvfWorker) {
  buildHvfWorker();
} else if (process.platform !== "linux") {
  console.warn(
    `No AMLA VM worker binary is configured for ${process.platform}.`,
  );
}

function parseExplicitTargets(args) {
  const result = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--target=")) {
      result.push(arg.slice("--target=".length));
    } else if (arg === "--target" && i + 1 < args.length) {
      result.push(args[++i]);
    }
  }
  return result;
}

function resolveTargets() {
  if (explicitTargets.length > 0) {
    return explicitTargets;
  }
  if (buildAll) {
    requireLinuxHost("--all");
    return [
      "aarch64-unknown-linux-gnu",
      "x86_64-unknown-linux-gnu",
      "aarch64-apple-darwin",
    ];
  }
  if (buildAllLinux) {
    requireLinuxHost("--all-linux");
    return ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"];
  }
  return [null];
}

function requireLinuxHost(flag) {
  if (process.platform !== "linux") {
    console.error(
      `${flag} requires a Linux host with the cross toolchains configured ` +
        `in src/rust/.cargo/config.toml; you ran it on ${process.platform}.`,
    );
    process.exit(1);
  }
}

function buildNapi(target) {
  const napiArgs = [
    "build",
    "--release",
    "--platform",
    "--package-json-path",
    resolve(packageRoot, "package.json"),
    "--output-dir",
    nativeDir,
  ];
  const env = { ...process.env };
  if (target) {
    napiArgs.push("--target", target);
    // For darwin, the repo's .cargo/config.toml configures a linker wrapper
    // (tools/link-and-sign.sh) that uses zig + macos-stubs/Hypervisor.framework.
    // Using --cross-compile would route through cargo-zigbuild and bypass
    // that wrapper, breaking the framework link.
    const isDarwin = target.endsWith("-apple-darwin");
    const isHost = target === hostLinuxTriple();
    if (!isDarwin && !isHost) {
      napiArgs.push("--cross-compile");
      Object.assign(env, crossEnvFor(target));
    }
  }
  run("napi", napiArgs, { cwd: bindingCrate, env });
}

function hostLinuxTriple() {
  if (process.platform !== "linux") return null;
  if (process.arch === "x64") return "x86_64-unknown-linux-gnu";
  if (process.arch === "arm64") return "aarch64-unknown-linux-gnu";
  return null;
}

function buildHvfWorker() {
  const hvfTarget =
    process.platform === "darwin" ? null : "aarch64-apple-darwin";
  const cargoArgs = [
    "build",
    "--release",
    "-p",
    "amla-vm-hvf",
    "--bin",
    "amla-hvf-worker",
  ];
  if (hvfTarget) {
    cargoArgs.push("--target", hvfTarget);
  }
  run("cargo", cargoArgs, { cwd: rustRoot });
  const targetSubdir = hvfTarget ? `${hvfTarget}/release` : "release";
  copyIfExists(
    resolve(rustRoot, "target", targetSubdir, "amla-hvf-worker"),
    resolve(nativeDir, "amla-hvf-worker"),
  );
}

function crossEnvFor(target) {
  const presets = {
    "x86_64-unknown-linux-gnu": {
      CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER: "x86_64-linux-gnu-gcc",
      CC_x86_64_unknown_linux_gnu: "x86_64-linux-gnu-gcc",
      CXX_x86_64_unknown_linux_gnu: "x86_64-linux-gnu-g++",
    },
    "aarch64-unknown-linux-gnu": {
      CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER: "aarch64-linux-gnu-gcc",
      CC_aarch64_unknown_linux_gnu: "aarch64-linux-gnu-gcc",
      CXX_aarch64_unknown_linux_gnu: "aarch64-linux-gnu-g++",
    },
  };
  return presets[target] ?? {};
}

function removeStaleNativeArtifacts() {
  // Legacy: amla-kvm-worker is no longer produced; sweep any leftover.
  rmSync(resolve(nativeDir, "amla-kvm-worker"), { force: true });
  if (willBuildHvfWorker) {
    rmSync(resolve(nativeDir, "amla-hvf-worker"), { force: true });
  }
  // Sweep every .node file we might overwrite. For multi-arch builds this
  // covers all platform shapes; for a host-only build it just clears the
  // current platform's artifact. Globbing avoids enumerating every
  // supported triple here.
  if (existsSync(nativeDir)) {
    for (const entry of readdirSync(nativeDir)) {
      if (entry.endsWith(".node")) {
        rmSync(resolve(nativeDir, entry), { force: true });
      }
    }
  }
}

function copyIfExists(source, dest) {
  if (!existsSync(source)) {
    throw new Error(`Expected build artifact does not exist: ${source}`);
  }
  copyFileSync(source, dest);
}

function run(command, args, options) {
  const result = spawnSync(command, args, {
    ...options,
    stdio: "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
