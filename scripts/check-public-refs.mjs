import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";

const forbidden = [
  "bW9ub3JlcG8=",
  "YW1sYWxhYnMvbW9ub3JlcG8=",
  "Z2l0aHViLmNvbS9hbWxhbGFicy9tb25vcmVwbw==",
  "c3JjL2phdmFzY3JpcHQvcGFja2FnZXMva2FsYWhhcmk=",
  "c3JjL3J1c3QvY3JhdGVzL2thbGFoYXJp",
].map((encoded) => Buffer.from(encoded, "base64").toString("utf8"));

const skipDirs = new Set([".git", ".kalahari", "node_modules", "target"]);
const roots = process.argv.slice(2);
const scanRoots = roots.length > 0 ? roots : ["."];
const matches = [];

for (const root of scanRoots) {
  scanPath(resolve(root));
}

if (matches.length > 0) {
  console.error(
    `Found internal repo references in public release files:\n${matches
      .map((match) => `  - ${match}`)
      .join("\n")}`,
  );
  process.exit(1);
}

console.log(
  `OK: scanned ${scanRoots.join(", ")} for internal repo references.`,
);

function scanPath(path) {
  const stat = statSync(path, { throwIfNoEntry: false });
  if (!stat) return;
  if (stat.isDirectory()) {
    if (skipDirs.has(basename(path))) return;
    for (const entry of readdirSync(path)) {
      scanPath(join(path, entry));
    }
    return;
  }
  if (!stat.isFile()) return;

  const bytes = readFileSync(path);
  if (bytes.includes(0)) return;
  const text = bytes.toString("utf8");
  for (const term of forbidden) {
    const offset = text.indexOf(term);
    if (offset === -1) continue;
    const line = text.slice(0, offset).split("\n").length;
    matches.push(`${relative(process.cwd(), path)}:${line}`);
  }
}
