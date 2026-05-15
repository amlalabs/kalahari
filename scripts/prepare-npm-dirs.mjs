import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "..");
const nativeDir = resolve(packageRoot, "native");
const npmDir = resolve(packageRoot, "npm");

const mainPkg = JSON.parse(
  readFileSync(resolve(packageRoot, "package.json"), "utf8"),
);

const requestedTargets = parseRequestedTargets(process.argv.slice(2));

const subpackages = [
  // os/cpu/libc filters teach npm which optionalDependency to install per host.
  // Triples must match the napi-rs build targets in scripts/build-native.mjs.
  {
    triple: "linux-x64-gnu",
    os: ["linux"],
    cpu: ["x64"],
    libc: ["glibc"],
    files: ["kalahari.linux-x64-gnu.node"],
  },
  {
    triple: "linux-arm64-gnu",
    os: ["linux"],
    cpu: ["arm64"],
    libc: ["glibc"],
    files: ["kalahari.linux-arm64-gnu.node"],
  },
  {
    triple: "darwin-arm64",
    os: ["darwin"],
    cpu: ["arm64"],
    files: ["kalahari.darwin-arm64.node", "amla-hvf-worker"],
  },
];

const selectedSubpackages =
  requestedTargets.length === 0
    ? subpackages
    : subpackages.filter((sub) => requestedTargets.includes(sub.triple));

const unknownTargets = requestedTargets.filter(
  (target) => !subpackages.some((sub) => sub.triple === target),
);
if (unknownTargets.length > 0) {
  throw new Error(
    `Unknown target(s): ${unknownTargets.join(", ")}. ` +
      `Supported targets: ${subpackages.map((sub) => sub.triple).join(", ")}.`,
  );
}

// Each per-arch sub-package is pinned at the main version via
// `optionalDependencies` (exact match required). If the main version bumps
// without updating those pins, installs partially fail at resolution time on
// users' machines. Fail loudly before staging so the publisher fixes it now.
const optionalDeps = mainPkg.optionalDependencies ?? {};
for (const sub of selectedSubpackages) {
  const subName = `${mainPkg.name}-${sub.triple}`;
  const pinned = optionalDeps[subName];
  if (pinned !== mainPkg.version) {
    throw new Error(
      `optionalDependencies["${subName}"] is ${JSON.stringify(pinned)}, ` +
        `but main version is ${JSON.stringify(mainPkg.version)}. ` +
        `Update package.json so they match before staging per-arch packages.`,
    );
  }
}

// Two layered guarantees:
//
//   1. Concurrency-safety: two pre-commit / build invocations racing on
//      this script must not interleave `rmSync(npmDir/<triple>)` with
//      another invocation's in-progress writes. Each per-arch subdir is
//      first written in full into a sibling staging directory, then
//      atomically swapped into place with a single `renameSync`. POSIX
//      `rename(2)` is atomic on the same filesystem; mkdtemp creates the
//      staging dir as a sibling of `npmDir` to guarantee that.
//
//   2. Partial-build safety: when invoked with `--target X` (filtered to
//      a subset of subpackages), only the requested subdirs are touched.
//      Per-subdir renames (rather than a single top-level npm/ swap)
//      preserve any other subdirs already present from a prior full
//      build. This matters for local dev workflows that rebuild one
//      arch at a time; CI calls this script with no flags and rebuilds
//      all three.
const stagingDir = mkdtempSync(`${npmDir}.staging-`);

try {
  const repoLicense = readFileSync(resolve(packageRoot, "LICENSE"), "utf8");
  const agplPath = resolve(packageRoot, "LICENSES/AGPL-3.0-or-later.txt");
  const buslPath = resolve(packageRoot, "LICENSES/BUSL-1.1.txt");

  for (const sub of selectedSubpackages) {
    const subDir = resolve(stagingDir, sub.triple);
    mkdirSync(resolve(subDir, "LICENSES"), { recursive: true });

    for (const file of sub.files) {
      const src = resolve(nativeDir, file);
      if (!existsSync(src)) {
        throw new Error(
          `Missing artifact ${file} in native/. Run \`npm run build:all\` first.`,
        );
      }
      copyFileSync(src, resolve(subDir, file));
    }

    const subPkg = {
      name: `${mainPkg.name}-${sub.triple}`,
      version: mainPkg.version,
      description: `Native binding for ${mainPkg.name} (${sub.triple})`,
      license: mainPkg.license,
      homepage: mainPkg.homepage,
      repository: mainPkg.repository,
      bugs: mainPkg.bugs,
      main: sub.files[0],
      files: [...sub.files, "LICENSE", "LICENSES", "README.md"],
      os: sub.os,
      cpu: sub.cpu,
      engines: { node: ">=20" },
      publishConfig: { access: "public" },
    };
    if (sub.libc) subPkg.libc = sub.libc;
    if (sub.triple === "darwin-arm64") {
      subPkg.files.push("check-hvf-worker.mjs");
      subPkg.scripts = {
        postinstall:
          "node check-hvf-worker.mjs amla-hvf-worker --warn-only --label=@amlalabs/kalahari-darwin-arm64",
      };
      copyFileSync(
        resolve(here, "check-hvf-worker.mjs"),
        resolve(subDir, "check-hvf-worker.mjs"),
      );
    }

    writeFileSync(
      resolve(subDir, "package.json"),
      JSON.stringify(subPkg, null, 2) + "\n",
    );
    writeFileSync(resolve(subDir, "LICENSE"), repoLicense);
    copyFileSync(agplPath, resolve(subDir, "LICENSES/AGPL-3.0-or-later.txt"));
    copyFileSync(buslPath, resolve(subDir, "LICENSES/BUSL-1.1.txt"));
    writeFileSync(
      resolve(subDir, "README.md"),
      `# ${subPkg.name}\n\nNative binding for [\`${mainPkg.name}\`](https://www.npmjs.com/package/${mainPkg.name}).\n\nDo not install directly. Install \`${mainPkg.name}\` and let npm resolve the matching native binding via \`optionalDependencies\`.\n`,
    );

    console.log(`Prepared ${subPkg.name}`);
  }

  // All requested subpackages are fully written into the staging dir. Move
  // each one into `npm/` with a per-subdir atomic rename so untouched
  // subdirs in npm/ (e.g. a prior `--target linux-x64-gnu` run left
  // darwin-arm64 and linux-arm64-gnu in place) are preserved.
  //
  // `renameSync` over an existing directory is not permitted on POSIX, so
  // we remove the old per-arch subdir first. The window between rm and
  // rename is tiny and only affects readers walking that specific subdir;
  // any reader reading a specific file inside the old subdir still holds
  // an open fd to the now-unlinked inode and reads safely to completion.
  mkdirSync(npmDir, { recursive: true });
  for (const sub of selectedSubpackages) {
    const finalDir = resolve(npmDir, sub.triple);
    const staged = resolve(stagingDir, sub.triple);
    rmSync(finalDir, { recursive: true, force: true });
    renameSync(staged, finalDir);
  }
  // stagingDir is empty after all renames; `force: true` keeps the cleanup
  // idempotent against a (theoretically impossible) leftover entry.
  rmSync(stagingDir, { recursive: true, force: true });
} catch (err) {
  // Best-effort cleanup; the throw below surfaces the original error.
  // Already-renamed subdirs are now permanently in npm/ — that's fine, each
  // was a full per-arch package. Only the *current* iteration's partial
  // staging content needs to go.
  rmSync(stagingDir, { recursive: true, force: true });
  throw err;
}

console.log(
  `\nDone. ${selectedSubpackages.length} per-arch packages in ${npmDir}.`,
);

function parseRequestedTargets(args) {
  const result = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--target") {
      const target = args[++i];
      if (!target || target.startsWith("--")) {
        throw new Error("--target requires a package target.");
      }
      result.push(target);
    } else if (arg.startsWith("--target=")) {
      const target = arg.slice("--target=".length);
      if (!target) {
        throw new Error("--target requires a package target.");
      }
      result.push(target);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return [...new Set(result)];
}
