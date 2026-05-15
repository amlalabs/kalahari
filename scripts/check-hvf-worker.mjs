import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HYPERVISOR_ENTITLEMENT = "com.apple.security.hypervisor";
const ENTITLEMENTS_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>${HYPERVISOR_ENTITLEMENT}</key>
  <true/>
</dict>
</plist>`;

export function checkHvfWorker(workerPath) {
  const absolutePath = resolve(workerPath);
  const issues = [];

  if (process.platform !== "darwin") {
    return { ok: true, workerPath: absolutePath, issues };
  }

  if (!existsSync(absolutePath)) {
    issues.push(`worker binary is missing at ${absolutePath}`);
    return { ok: false, workerPath: absolutePath, issues };
  }

  const stat = statSync(absolutePath);
  if ((stat.mode & 0o111) === 0) {
    issues.push("worker binary is not executable");
  }

  const verify = run("codesign", [
    "--verify",
    "--strict",
    "--verbose=2",
    absolutePath,
  ]);
  if (verify.error?.code === "ENOENT") {
    issues.push("macOS `codesign` tool is not available");
  } else if (verify.status !== 0) {
    issues.push(
      `codesign verification failed${formatCommandOutput(verify.output)}`,
    );
  }

  const entitlements = run("codesign", [
    "-d",
    "--xml",
    "--entitlements",
    "-",
    absolutePath,
  ]);
  if (entitlements.error?.code === "ENOENT") {
    issues.push("macOS `codesign` tool is not available");
  } else if (entitlements.status !== 0) {
    issues.push(
      `could not read worker entitlements${formatCommandOutput(
        entitlements.output,
      )}`,
    );
  } else if (!hasHypervisorEntitlement(entitlements.output)) {
    issues.push(`missing ${HYPERVISOR_ENTITLEMENT} entitlement`);
  }

  const quarantine = run("xattr", ["-p", "com.apple.quarantine", absolutePath]);
  if (quarantine.status === 0) {
    issues.push("worker binary has the com.apple.quarantine attribute");
  }

  return { ok: issues.length === 0, workerPath: absolutePath, issues };
}

export function reportHvfWorkerCheck(workerPath, options = {}) {
  const result = checkHvfWorker(workerPath);
  if (result.ok) {
    return true;
  }

  console.error(formatHvfWorkerIssue(result, options));
  return false;
}

function hasHypervisorEntitlement(output) {
  const compact = output.replace(/\s+/g, "");
  return (
    output.includes(HYPERVISOR_ENTITLEMENT) &&
    (compact.includes(`<key>${HYPERVISOR_ENTITLEMENT}</key><true/>`) ||
      output.includes("[Bool] true"))
  );
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  return {
    status: result.status ?? 1,
    error: result.error,
    output: [result.stdout, result.stderr].filter(Boolean).join("\n").trim(),
  };
}

function formatHvfWorkerIssue(result, options = {}) {
  const label = options.label ?? "@amlalabs/kalahari";
  const worker = shQuote(result.workerPath);
  const entitlementFile = "/tmp/kalahari-hvf-entitlements.plist";
  return (
    `${label}: amla-hvf-worker failed macOS signature checks.\n\n` +
    `Kalahari uses Hypervisor.framework on macOS. The worker binary must be ` +
    `executable, codesigned, and signed with the ${HYPERVISOR_ENTITLEMENT} ` +
    `entitlement.\n\n` +
    `Detected issue(s):\n${result.issues
      .map((issue) => `  - ${issue}`)
      .join("\n")}\n\n` +
    `To repair this install locally, run:\n\n` +
    `cat > ${entitlementFile} <<'PLIST'\n${ENTITLEMENTS_PLIST}\nPLIST\n` +
    `chmod +x ${worker}\n` +
    `codesign --force --sign - --entitlements ${entitlementFile} ${worker}\n` +
    `xattr -d com.apple.quarantine ${worker} 2>/dev/null || true\n\n` +
    `Then rerun your Kalahari command. If this came from a fresh npm install, ` +
    `please also report it at https://github.com/amlalabs/kalahari/issues.`
  );
}

function formatCommandOutput(output) {
  if (!output) return "";
  return `:\n${output
    .split("\n")
    .map((line) => `    ${line}`)
    .join("\n")}`;
}

function shQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

function parseCliArgs(args) {
  let workerPath;
  let warnOnly = false;
  let label;
  for (const arg of args) {
    if (arg === "--warn-only") {
      warnOnly = true;
    } else if (arg.startsWith("--label=")) {
      label = arg.slice("--label=".length);
    } else if (!workerPath) {
      workerPath = arg;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  if (!workerPath) {
    throw new Error(
      "Usage: node check-hvf-worker.mjs <worker-path> [--warn-only] [--label=<name>]",
    );
  }
  return { workerPath, warnOnly, label };
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const { workerPath, warnOnly, label } = parseCliArgs(process.argv.slice(2));
  const ok = reportHvfWorkerCheck(workerPath, { label });
  if (!ok && !warnOnly) {
    process.exit(1);
  }
}
