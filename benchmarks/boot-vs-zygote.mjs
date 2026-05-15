#!/usr/bin/env node
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";

import { KalahariClient, available } from "../dist/index.js";

const defaults = {
  clones: 8,
  command: "node",
  commandArgs: [
    "-e",
    [
      'const fs = require("node:fs");',
      'const state = fs.readFileSync("/tmp/kalahari-bench/state.txt", "utf8");',
      "process.stdout.write(`bench:${state}`);",
    ].join(""),
  ],
  fresh: 3,
  image: "node:22-alpine",
  memoryMb: 512,
  parallel: 4,
  prepare: true,
  verifyDefaultOutput: true,
  vcpus: 1,
};

const options = parseArgs(process.argv.slice(2));

assert.equal(
  available(),
  true,
  "Kalahari native VM must be available to run boot benchmarks",
);

const client = new KalahariClient({
  image: options.image,
  memoryMb: options.memoryMb,
  vcpus: options.vcpus,
});

const result = await runBenchmark(client, options);

if (options.json) {
  console.log(JSON.stringify(result, null, 2));
} else {
  printReport(result);
}

async function runBenchmark(client, options) {
  const startedAt = new Date();
  const prepareImageMs = options.prepare
    ? await time(async () => {
        await client.prepareImage();
      })
    : undefined;

  const freshRuns = [];
  for (let index = 0; index < options.fresh; index += 1) {
    freshRuns.push(await freshBootRun(client, options, index));
  }

  const zygoteSetup = await createBenchZygote(client, options);
  const sequentialClones = [];
  const parallelClones = [];

  try {
    for (let index = 0; index < options.clones; index += 1) {
      sequentialClones.push(
        await zygoteCloneRun(zygoteSetup.zygote, options, index),
      );
    }

    const parallelCount = Math.min(options.parallel, options.clones);
    if (parallelCount > 0) {
      parallelClones.push(
        ...(await Promise.all(
          Array.from({ length: parallelCount }, (_, index) =>
            zygoteCloneRun(zygoteSetup.zygote, options, index),
          ),
        )),
      );
    }
  } finally {
    await destroyIfRunning(zygoteSetup.zygote);
    await destroyIfRunning(zygoteSetup.base);
  }

  return {
    command: [options.command, ...options.commandArgs],
    config: {
      clones: options.clones,
      fresh: options.fresh,
      image: options.image,
      memoryMb: options.memoryMb,
      parallel: options.parallel,
      prepare: options.prepare,
      vcpus: options.vcpus,
    },
    fresh: {
      bootMs: summarize(freshRuns.map((run) => run.bootMs)),
      commandMs: summarize(freshRuns.map((run) => run.commandMs)),
      destroyMs: summarize(freshRuns.map((run) => run.destroyMs)),
      setupMs: summarize(freshRuns.map((run) => run.setupMs)),
      totalMs: summarize(freshRuns.map((run) => run.totalMs)),
      runs: freshRuns,
    },
    prepareImageMs,
    startedAt: startedAt.toISOString(),
    zygote: {
      baseBootMs: zygoteSetup.baseBootMs,
      baseSetupCommandMs: zygoteSetup.baseSetupCommandMs,
      conversionMs: zygoteSetup.conversionMs,
      parallelCloneCommandMs: summarize(
        parallelClones.map((run) => run.commandMs),
      ),
      parallelCloneMutationMs: summarize(
        parallelClones.map((run) => run.mutationMs),
      ),
      parallelCloneSpawnMs: summarize(parallelClones.map((run) => run.spawnMs)),
      parallelCloneTotalMs: summarize(parallelClones.map((run) => run.totalMs)),
      parallelClones,
      sequentialCloneCommandMs: summarize(
        sequentialClones.map((run) => run.commandMs),
      ),
      sequentialCloneMutationMs: summarize(
        sequentialClones.map((run) => run.mutationMs),
      ),
      sequentialCloneSpawnMs: summarize(
        sequentialClones.map((run) => run.spawnMs),
      ),
      sequentialCloneTotalMs: summarize(
        sequentialClones.map((run) => run.totalMs),
      ),
      sequentialClones,
    },
  };
}

async function freshBootRun(client, options, index) {
  const started = performance.now();
  let sandbox;
  try {
    const bootMs = await time(async () => {
      sandbox = await client.createSandbox();
    });
    const setupMs = await time(async () => {
      await setupBenchState(sandbox, `fresh-${index}\n`);
    });
    const commandMs = await time(async () => {
      const result = await runBenchCommand(sandbox, options);
      if (options.verifyDefaultOutput) {
        assert.equal(result.stdout, `bench:fresh-${index}\n`);
      }
    });
    const destroyMs = await time(async () => {
      await sandbox.destroy();
    });
    return {
      bootMs,
      commandMs,
      destroyMs,
      setupMs,
      totalMs: performance.now() - started,
    };
  } finally {
    await destroyIfRunning(sandbox);
  }
}

async function createBenchZygote(client, options) {
  let base;
  const baseBootMs = await time(async () => {
    base = await client.createSandbox();
  });
  try {
    const baseSetupCommandMs = await time(async () => {
      await setupBenchState(base, "zygote-base\n");
      const result = await runBenchCommand(base, options);
      if (options.verifyDefaultOutput) {
        assert.equal(result.stdout, "bench:zygote-base\n");
      }
    });
    let zygote;
    const conversionMs = await time(async () => {
      zygote = await base.zygote();
    });
    return {
      base,
      baseBootMs,
      baseSetupCommandMs,
      conversionMs,
      zygote,
    };
  } catch (error) {
    await destroyIfRunning(base);
    throw error;
  }
}

async function zygoteCloneRun(zygote, options, index) {
  const started = performance.now();
  let child;
  try {
    const spawnMs = await time(async () => {
      child = await zygote.spawn();
    });
    const commandMs = await time(async () => {
      const before = await runBenchCommand(child, options);
      if (options.verifyDefaultOutput) {
        assert.equal(before.stdout, "bench:zygote-base\n");
      }
    });
    const mutationMs = await time(async () => {
      await setupBenchState(child, `clone-${index}\n`);
      const after = await runBenchCommand(child, options);
      if (options.verifyDefaultOutput) {
        assert.equal(after.stdout, `bench:clone-${index}\n`);
      }
    });
    const destroyMs = await time(async () => {
      await child.destroy();
    });
    return {
      commandMs,
      destroyMs,
      mutationMs,
      spawnMs,
      totalMs: performance.now() - started,
    };
  } finally {
    await destroyIfRunning(child);
  }
}

async function setupBenchState(sandbox, value) {
  await sandbox.mkdir("/tmp/kalahari-bench");
  await sandbox.writeFile("/tmp/kalahari-bench/state.txt", value);
}

async function runBenchCommand(sandbox, options) {
  const result = await sandbox.run(options.command, {
    args: options.commandArgs,
    cwd: "/tmp/kalahari-bench",
  });
  assert.equal(result.exitCode, 0, result.stderr);
  return result;
}

async function destroyIfRunning(resource) {
  if (resource && !resource.isDestroyed()) {
    await resource.destroy();
  }
}

async function time(callback) {
  const started = performance.now();
  await callback();
  return performance.now() - started;
}

function summarize(values) {
  if (values.length === 0) {
    return null;
  }
  const sorted = [...values].sort((left, right) => left - right);
  return {
    avg: average(sorted),
    max: sorted.at(-1),
    min: sorted[0],
    p50: percentile(sorted, 0.5),
    p90: percentile(sorted, 0.9),
    samples: sorted.length,
  };
}

function average(values) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function percentile(sorted, rank) {
  if (sorted.length === 1) {
    return sorted[0];
  }
  const index = Math.ceil(rank * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(index, sorted.length - 1))];
}

function printReport(result) {
  console.log("Kalahari boot benchmark");
  console.log(`image: ${result.config.image}`);
  console.log(
    `shape: ${result.config.memoryMb} MiB, ${result.config.vcpus} vCPU`,
  );
  console.log(`command: ${result.command.map(shellQuote).join(" ")}`);
  if (result.prepareImageMs !== undefined) {
    console.log(`prepare image: ${formatMs(result.prepareImageMs)}`);
  }
  console.log("");

  console.log("fresh sandbox");
  printSummary("boot", result.fresh.bootMs);
  printSummary("setup", result.fresh.setupMs);
  printSummary("command", result.fresh.commandMs);
  printSummary("destroy", result.fresh.destroyMs);
  printSummary("total", result.fresh.totalMs);
  console.log("");

  console.log("zygote");
  console.log(`base boot: ${formatMs(result.zygote.baseBootMs)}`);
  console.log(
    `base setup command: ${formatMs(result.zygote.baseSetupCommandMs)}`,
  );
  console.log(
    `convert sandbox to zygote: ${formatMs(result.zygote.conversionMs)}`,
  );
  printSummary("sequential clone spawn", result.zygote.sequentialCloneSpawnMs);
  printSummary(
    "sequential clone command",
    result.zygote.sequentialCloneCommandMs,
  );
  printSummary(
    "sequential clone mutation",
    result.zygote.sequentialCloneMutationMs,
  );
  printSummary("sequential clone total", result.zygote.sequentialCloneTotalMs);
  printSummary("parallel clone spawn", result.zygote.parallelCloneSpawnMs);
  printSummary("parallel clone command", result.zygote.parallelCloneCommandMs);
  printSummary(
    "parallel clone mutation",
    result.zygote.parallelCloneMutationMs,
  );
  printSummary("parallel clone total", result.zygote.parallelCloneTotalMs);
}

function printSummary(label, summary) {
  if (!summary) {
    console.log(`${label}: no samples`);
    return;
  }
  console.log(
    `${label}: samples=${summary.samples} avg=${formatMs(summary.avg)} p50=${formatMs(summary.p50)} p90=${formatMs(summary.p90)} min=${formatMs(summary.min)} max=${formatMs(summary.max)}`,
  );
}

function formatMs(value) {
  return `${value.toFixed(1)} ms`;
}

function shellQuote(value) {
  if (/^[A-Za-z0-9_./:=@-]+$/.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}

function parseArgs(args) {
  const options = { ...defaults, commandArgs: [...defaults.commandArgs] };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--") {
      options.commandArgs = args.slice(index + 1);
      options.verifyDefaultOutput = false;
      break;
    }
    if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    }
    if (arg === "--json") {
      options.json = true;
      continue;
    }
    if (arg === "--no-prepare") {
      options.prepare = false;
      continue;
    }
    if (arg === "--clones") {
      options.clones = nonNegativeInteger(optionValue(args, index, arg), arg);
      index += 1;
      continue;
    }
    if (arg.startsWith("--clones=")) {
      options.clones = nonNegativeInteger(inlineOptionValue(arg), "--clones");
      continue;
    }
    if (arg === "--command") {
      options.command = optionValue(args, index, arg);
      options.commandArgs = [];
      options.verifyDefaultOutput = false;
      index += 1;
      continue;
    }
    if (arg.startsWith("--command=")) {
      options.command = inlineOptionValue(arg);
      options.commandArgs = [];
      options.verifyDefaultOutput = false;
      continue;
    }
    if (arg === "--fresh") {
      options.fresh = nonNegativeInteger(optionValue(args, index, arg), arg);
      index += 1;
      continue;
    }
    if (arg.startsWith("--fresh=")) {
      options.fresh = nonNegativeInteger(inlineOptionValue(arg), "--fresh");
      continue;
    }
    if (arg === "--image") {
      options.image = optionValue(args, index, arg);
      index += 1;
      continue;
    }
    if (arg.startsWith("--image=")) {
      options.image = inlineOptionValue(arg);
      continue;
    }
    if (arg === "--memory-mb") {
      options.memoryMb = positiveInteger(optionValue(args, index, arg), arg);
      index += 1;
      continue;
    }
    if (arg.startsWith("--memory-mb=")) {
      options.memoryMb = positiveInteger(inlineOptionValue(arg), "--memory-mb");
      continue;
    }
    if (arg === "--parallel") {
      options.parallel = nonNegativeInteger(optionValue(args, index, arg), arg);
      index += 1;
      continue;
    }
    if (arg.startsWith("--parallel=")) {
      options.parallel = nonNegativeInteger(
        inlineOptionValue(arg),
        "--parallel",
      );
      continue;
    }
    if (arg === "--vcpus") {
      options.vcpus = positiveInteger(optionValue(args, index, arg), arg);
      index += 1;
      continue;
    }
    if (arg.startsWith("--vcpus=")) {
      options.vcpus = positiveInteger(inlineOptionValue(arg), "--vcpus");
      continue;
    }
    throw new Error(`unknown benchmark option: ${arg}`);
  }
  return options;
}

function optionValue(args, index, name) {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function inlineOptionValue(arg) {
  const value = arg.slice(arg.indexOf("=") + 1);
  if (value.length === 0) {
    throw new Error(`${arg.slice(0, arg.indexOf("="))} requires a value`);
  }
  return value;
}

function positiveInteger(value, name) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function nonNegativeInteger(value, name) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }
  return parsed;
}

function usage() {
  console.log(`usage: npm run bench:boot -- [options] [-- command-args...]

Options:
  --image <ref>       OCI image to boot (default: ${defaults.image})
  --fresh <n>         Fresh sandbox samples (default: ${defaults.fresh})
  --clones <n>        Sequential zygote clone samples (default: ${defaults.clones})
  --parallel <n>      Extra parallel zygote clone samples (default: ${defaults.parallel})
  --memory-mb <n>     VM memory in MiB (default: ${defaults.memoryMb})
  --vcpus <n>         VM vCPU count (default: ${defaults.vcpus})
  --command <cmd>     Command executable inside the sandbox (default: ${defaults.command})
  --no-prepare        Skip explicit image preparation before timing
  --json              Print raw JSON instead of a text report

The default command expects node:22-alpine and reads /tmp/kalahari-bench/state.txt.
Use --command plus -- to benchmark another image-specific command.`);
}
