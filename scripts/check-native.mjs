import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "..");

const required = [
  // Main package: napi-rs wrapper that loads the per-arch optionalDep.
  "native/index.js",
  "native/index.d.ts",
  // Per-arch packages staged in npm/, ready to publish individually.
  "npm/linux-x64-gnu/package.json",
  "npm/linux-x64-gnu/kalahari.linux-x64-gnu.node",
  "npm/linux-arm64-gnu/package.json",
  "npm/linux-arm64-gnu/kalahari.linux-arm64-gnu.node",
  "npm/darwin-arm64/package.json",
  "npm/darwin-arm64/kalahari.darwin-arm64.node",
  "npm/darwin-arm64/amla-hvf-worker",
  "npm/darwin-arm64/check-hvf-worker.mjs",
];

const missing = [];
const empty = [];
for (const rel of required) {
  const path = resolve(packageRoot, rel);
  if (!existsSync(path)) {
    missing.push(rel);
    continue;
  }
  if (statSync(path).size === 0) {
    empty.push(rel);
  }
}

if (missing.length > 0 || empty.length > 0) {
  if (missing.length > 0) {
    console.error(
      `Missing artifacts:\n${missing.map((m) => `  - ${m}`).join("\n")}`,
    );
  }
  if (empty.length > 0) {
    console.error(
      `Empty artifacts:\n${empty.map((m) => `  - ${m}`).join("\n")}`,
    );
  }
  console.error(
    `\nRun \`npm run build:all\` (Linux host) then \`npm run prepare:npm-dirs\` before publishing.`,
  );
  process.exit(1);
}

const darwinPkg = JSON.parse(
  readFileSync(resolve(packageRoot, "npm/darwin-arm64/package.json"), "utf8"),
);
const expectedPostinstall =
  "node check-hvf-worker.mjs amla-hvf-worker --warn-only --label=@amlalabs/kalahari-darwin-arm64";
if (darwinPkg.scripts?.postinstall !== expectedPostinstall) {
  console.error(
    `npm/darwin-arm64/package.json is missing the expected postinstall signature check.`,
  );
  process.exit(1);
}

console.log(`OK: ${required.length} artifacts present.`);
