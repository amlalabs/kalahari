// Verify each per-arch sibling declared in `optionalDependencies` is already
// on the npm registry at the target version.
//
// Publishing the main package first creates a silently broken install:
// npm's optionalDependency resolution logs a warning and continues, so
// `npm install @amlalabs/kalahari` appears to succeed but then fails on
// first import with "Cannot find native binding". This check makes that
// failure mode impossible by gating the main publish on the siblings.
//
// Expected release sequence:
//   1. npm run build:all              (cross-build all 3 native targets)
//   2. npm run prepare:npm-dirs       (stage per-arch packages in npm/)
//   3. cd npm/<triple> && npm publish (for each triple — siblings first)
//   4. npm publish                    (main; prepublishOnly runs this check)

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "..");
const mainPkg = JSON.parse(
  readFileSync(resolve(packageRoot, "package.json"), "utf8"),
);

const prefix = `${mainPkg.name}-`;
const siblings = Object.entries(mainPkg.optionalDependencies ?? {})
  .filter(([name]) => name.startsWith(prefix))
  .map(([name, version]) => ({
    name,
    version,
    triple: name.slice(prefix.length),
  }));

if (siblings.length === 0) {
  console.error(
    `No per-arch siblings (prefix ${prefix}) declared in optionalDependencies.`,
  );
  process.exit(1);
}

const missing = [];
const networkErrors = [];

for (const sib of siblings) {
  try {
    // Pass args as an array so no shell parsing happens on the spec string.
    execFileSync(
      "npm",
      ["view", `${sib.name}@${sib.version}`, "version", "--json"],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    console.log(`OK: ${sib.name}@${sib.version} present on registry.`);
  } catch (err) {
    // `--json` makes npm emit a structured error to stdout even on failure.
    // We prefer that over stderr because `npm run` suppresses child stderr
    // depending on log-level inheritance.
    const stdout = err.stdout?.toString() ?? "";
    const stderr = err.stderr?.toString() ?? "";
    let code = null;
    try {
      code = JSON.parse(stdout)?.error?.code ?? null;
    } catch {
      // not JSON, fall through to stderr-text matching
    }
    const isMissing = code === "E404" || /E404|404 Not Found/.test(stderr);
    if (isMissing) {
      missing.push(sib);
    } else {
      networkErrors.push({ ...sib, stderr: stderr || stdout });
    }
  }
}

if (networkErrors.length > 0) {
  console.error("\nFailed to query the npm registry for one or more siblings:");
  for (const e of networkErrors) {
    console.error(`  - ${e.name}@${e.version}`);
    const indented = e.stderr.trim().split("\n").join("\n    ");
    console.error(`    ${indented}`);
  }
  console.error(
    `\nThis check needs registry access. Verify connectivity and \`npm whoami\`.`,
  );
  process.exit(1);
}

if (missing.length > 0) {
  console.error(
    `\nCannot publish ${mainPkg.name}@${mainPkg.version}: per-arch sibling ` +
      `packages are not yet on the registry. Publish each missing one first, ` +
      `then re-run \`npm publish\` here:\n`,
  );
  for (const m of missing) {
    console.error(`  (cd npm/${m.triple} && npm publish)`);
  }
  console.error("");
  process.exit(1);
}

console.log(
  `\nAll ${siblings.length} per-arch siblings present at ${mainPkg.version}.`,
);
