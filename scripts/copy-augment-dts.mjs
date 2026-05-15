// Post-build step that ships the computesdk module augmentation in the
// published tarball.
//
// Two operations:
//
// 1. Copy source-only `.d.ts` files from `src/types/` into `dist/types/`.
//    `tsc` does not emit source `.d.ts` files into `outDir` (it treats them
//    as already-compiled declaration sources), so without an explicit copy
//    the augmentation file never reaches the tarball.
//
// 2. Prepend a triple-slash `<reference path="./types/computesdk-augment.d.ts" />`
//    directive to `dist/index.d.ts`. While `src/index.ts` already contains
//    the same directive, `tsc` emits triple-slash references into the `.js`
//    output but not into the corresponding `.d.ts` output (the directive is
//    not part of the declaration emit pipeline). Consumers reading the
//    package's types entry would otherwise never load the augmentation.
//
// Idempotent: re-running is safe (file copy overwrites; reference injection
// is a no-op if the directive is already present ANYWHERE in the file —
// `.includes` rather than `.startsWith` so a future tsc that prepends a
// BOM, banner comment, or other directive doesn't defeat the guard and
// cause double-prepending on each run).
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "..");
const srcTypesDir = join(packageRoot, "src", "types");
const distDir = join(packageRoot, "dist");
const distTypesDir = join(distDir, "types");

mkdirSync(distTypesDir, { recursive: true });

// 1. Copy `.d.ts` augmentation sources into dist/types/.
for (const entry of readdirSync(srcTypesDir)) {
  if (!entry.endsWith(".d.ts")) continue;
  const srcPath = join(srcTypesDir, entry);
  if (!statSync(srcPath).isFile()) continue;
  const destPath = join(distTypesDir, entry);
  copyFileSync(srcPath, destPath);
}

// 2. Inject triple-slash reference into dist/index.d.ts so consumers loading
//    `@amlalabs/kalahari`'s types automatically pull in the augmentation.
const indexDtsPath = join(distDir, "index.d.ts");
const referenceLine =
  '/// <reference path="./types/computesdk-augment.d.ts" />';
const existing = readFileSync(indexDtsPath, "utf8");
if (!existing.includes(referenceLine)) {
  writeFileSync(indexDtsPath, `${referenceLine}\n${existing}`);
}
