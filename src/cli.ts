#!/usr/bin/env node
import { createSandbox, prepareImage } from "./index.js";

class CliUsageError extends Error {}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);

  try {
    if (command === "--help" || command === "-h" || command === "help") {
      if (args[0] === "prepare") {
        prepareUsage(process.stdout);
      } else if (args[0] === "run") {
        runUsage(process.stdout);
      } else {
        usage(process.stdout);
      }
      return;
    }

    if (command === "prepare") {
      await prepare(args);
      return;
    }
    if (command === "run") {
      await run(args);
      return;
    }

    usage(process.stderr);
    process.exitCode = 1;
  } catch (error) {
    if (error instanceof CliUsageError) {
      console.error(`error: ${error.message}`);
      if (command === "prepare") {
        prepareUsage(process.stderr);
      } else if (command === "run") {
        runUsage(process.stderr);
      } else {
        usage(process.stderr);
      }
      process.exitCode = 1;
      return;
    }
    throw error;
  }
}

async function prepare(args: string[]): Promise<void> {
  const options = parsePrepareArgs(args);
  if (options.help) {
    prepareUsage(process.stdout);
    return;
  }
  if (!options.image) {
    throw new CliUsageError("kalahari prepare requires --image.");
  }

  const prepared = await prepareImage({ image: options.image });
  const status = prepared.alreadyPresent ? "already present" : "imported";
  console.error(
    `${status}: ${prepared.source} (${prepared.manifestDigest.slice(0, 12)}, ${prepared.layers} layers)`,
  );
}

async function run(args: string[]): Promise<void> {
  const options = parseRunArgs(args);
  if (options.help) {
    runUsage(process.stdout);
    return;
  }
  if (!options.image) {
    throw new CliUsageError("kalahari run requires --image.");
  }

  const commandArgs = options.commandArgs;
  if (commandArgs.length === 0) {
    throw new CliUsageError(
      "kalahari run requires a command. Use -- before commands that start with '-'.",
    );
  }

  const sandbox = await createSandbox({ image: options.image });
  try {
    const result = await sandbox.run(commandArgs[0] ?? "/bin/sh", {
      args: commandArgs.slice(1),
    });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    process.exitCode = result.exitCode;
  } finally {
    await sandbox.destroy();
  }
}

interface PrepareCliOptions {
  help: boolean;
  image?: string;
}

interface RunCliOptions extends PrepareCliOptions {
  commandArgs: string[];
}

function parsePrepareArgs(args: string[]): PrepareCliOptions {
  const options: PrepareCliOptions = { help: false };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (isHelpFlag(arg)) {
      options.help = true;
      continue;
    }
    if (arg === "--image") {
      options.image = optionValue(args, index, "--image");
      index += 1;
      continue;
    }
    if (arg.startsWith("--image=")) {
      options.image = inlineOptionValue(arg, "--image");
      continue;
    }
    if (arg.startsWith("-")) {
      throw new CliUsageError(`unknown option for kalahari prepare: ${arg}`);
    }
    throw new CliUsageError(`unexpected argument for kalahari prepare: ${arg}`);
  }
  return options;
}

function parseRunArgs(args: string[]): RunCliOptions {
  const options: RunCliOptions = { commandArgs: [], help: false };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--") {
      options.commandArgs = args.slice(index + 1);
      return options;
    }
    if (isHelpFlag(arg)) {
      options.help = true;
      return options;
    }
    if (arg === "--image") {
      options.image = optionValue(args, index, "--image");
      index += 1;
      continue;
    }
    if (arg.startsWith("--image=")) {
      options.image = inlineOptionValue(arg, "--image");
      continue;
    }
    if (arg.startsWith("-")) {
      throw new CliUsageError(
        `unknown option for kalahari run before command: ${arg}`,
      );
    }
    options.commandArgs = args.slice(index);
    return options;
  }
  return options;
}

function isHelpFlag(arg: string): boolean {
  return arg === "--help" || arg === "-h";
}

function optionValue(args: string[], index: number, name: string): string {
  const value = args[index + 1];
  if (value === undefined || value === "--" || isHelpFlag(value)) {
    throw new CliUsageError(`${name} requires a value.`);
  }
  return value;
}

function inlineOptionValue(arg: string, name: string): string {
  const value = arg.slice(name.length + 1);
  if (value.length === 0) {
    throw new CliUsageError(`${name} requires a value.`);
  }
  return value;
}

function usage(stream: NodeJS.WritableStream): void {
  stream.write("usage: kalahari <command> [options]\n");
  stream.write("\n");
  stream.write("commands:\n");
  stream.write(
    "  prepare   prepare an OCI image in the local Kalahari store\n",
  );
  stream.write("  run       create a sandbox and run one command\n");
  stream.write("\n");
  stream.write("run `kalahari help <command>` for command-specific help.\n");
}

function prepareUsage(stream: NodeJS.WritableStream): void {
  stream.write("usage: kalahari prepare --image <image>\n");
}

function runUsage(stream: NodeJS.WritableStream): void {
  stream.write(
    "usage: kalahari run --image <image> [--] <command> [args...]\n",
  );
}

await main();
