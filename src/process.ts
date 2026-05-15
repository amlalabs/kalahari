import type { KalahariPtySession, KalahariSandbox } from "./index.js";
import type { CommandEnv, CommandResult } from "./types.js";
import { envRecord } from "./compat.js";

export interface KalahariProcessCallbacks {
  onStderr?: ((data: string) => void | Promise<void>) | undefined;
  onStdout?: ((data: string) => void | Promise<void>) | undefined;
}

export interface KalahariProcessInfo {
  args: string[];
  command: string;
  cwd?: string;
  env: Record<string, string>;
  pid: number;
  shell: boolean;
}

export interface KalahariStartProcessOptions {
  args?: string[] | undefined;
  cols?: number | undefined;
  cwd?: string | undefined;
  env?: CommandEnv | undefined;
  onStderr?: ((data: string) => void | Promise<void>) | undefined;
  onStdout?: ((data: string) => void | Promise<void>) | undefined;
  rows?: number | undefined;
  shell?: boolean | undefined;
}

export interface KalahariProcessHandle {
  readonly pid: number;
  kill(): Promise<boolean>;
  resize(size: { cols: number; rows?: number }): Promise<void>;
  sendStdin(data: string | Uint8Array): Promise<void>;
  wait(): Promise<CommandResult>;
}

interface ProcessRecord {
  callbacks: KalahariProcessCallbacks;
  info: KalahariProcessInfo;
  session: KalahariPtySession;
  startedAtMs: number;
  terminationError?: Error;
  terminationPromise?: Promise<void>;
  waitPromise?: Promise<CommandResult>;
}

const registries = new Map<string, KalahariProcessRegistry>();

export function processRegistryForSandbox(
  sandboxId: string,
): KalahariProcessRegistry {
  let registry = registries.get(sandboxId);
  if (!registry) {
    registry = new KalahariProcessRegistry();
    registries.set(sandboxId, registry);
  }
  return registry;
}

export function existingProcessRegistryForSandbox(
  sandboxId: string,
): KalahariProcessRegistry | undefined {
  return registries.get(sandboxId);
}

export function clearProcessRegistryForSandbox(sandboxId: string): void {
  registries.get(sandboxId)?.discardAll();
  registries.delete(sandboxId);
}

export class KalahariProcessRegistry {
  private readonly processes = new Map<number, ProcessRecord>();

  list(): KalahariProcessInfo[] {
    return [...this.processes.values()].map((record) => ({
      ...record.info,
      args: [...record.info.args],
      env: { ...record.info.env },
    }));
  }

  discardAll(): void {
    this.processes.clear();
  }

  async start(
    sandbox: KalahariSandbox,
    command: string,
    options: KalahariStartProcessOptions = {},
  ): Promise<KalahariProcessHandle> {
    const shell = options.shell === true;
    const session = await createPtySession(sandbox, {
      args: options.args,
      command,
      cwd: options.cwd,
      env: options.env,
      shell,
    });
    const startedAtMs = Date.now();
    try {
      if (options.rows !== undefined || options.cols !== undefined) {
        await session.resize(options.rows ?? 24, options.cols ?? 80);
      }
    } catch (error) {
      await terminateAfterStartError(session, error);
      throw error;
    }
    const info: Omit<KalahariProcessInfo, "pid"> = {
      args: options.args ?? [],
      command,
      env: envRecord(options.env),
      shell,
    };
    if (options.cwd !== undefined) {
      info.cwd = options.cwd;
    }
    return this.register(session, {
      callbacks: {
        onStderr: options.onStderr,
        onStdout: options.onStdout,
      },
      info,
      startedAtMs,
    });
  }

  handle(pid: number, label = "Kalahari process"): KalahariProcessHandle {
    return this.handleFor(pid, this.record(pid, label));
  }

  async kill(pid: number): Promise<boolean> {
    const record = this.processes.get(pid);
    if (!record) {
      return false;
    }
    await this.terminate(pid, record);
    return true;
  }

  async closeAll(): Promise<void> {
    const results = await Promise.allSettled(
      [...this.processes.keys()].map((pid) => this.kill(pid)),
    );
    const errors = results
      .filter((result): result is PromiseRejectedResult => {
        return result.status === "rejected";
      })
      .map((result) => result.reason);
    if (errors.length === 1) {
      throw errors[0];
    }
    if (errors.length > 1) {
      throw new AggregateError(errors, "Failed to close Kalahari processes.");
    }
  }

  async resize(
    pid: number,
    size: { cols: number; rows?: number },
    label = "Kalahari process",
  ): Promise<void> {
    await this.record(pid, label).session.resize(size.rows ?? 24, size.cols);
  }

  async sendStdin(
    pid: number,
    data: string | Uint8Array,
    label = "Kalahari process",
  ): Promise<void> {
    await this.record(pid, label).session.write(data);
  }

  private register(
    session: KalahariPtySession,
    options: {
      callbacks: KalahariProcessCallbacks;
      info: Omit<KalahariProcessInfo, "pid">;
      startedAtMs: number;
    },
  ): KalahariProcessHandle {
    const pid = nextPid();
    const record: ProcessRecord = {
      callbacks: options.callbacks,
      info: { ...options.info, pid },
      session,
      startedAtMs: options.startedAtMs,
    };
    this.processes.set(pid, record);
    record.waitPromise = this.collect(pid, record);
    record.waitPromise.catch(() => undefined);
    return this.handleFor(pid, record);
  }

  private handleFor(pid: number, record: ProcessRecord): KalahariProcessHandle {
    return {
      pid,
      kill: () => this.kill(pid),
      resize: (size) => this.resize(pid, size),
      sendStdin: (data) => this.sendStdin(pid, data),
      wait: () => this.wait(pid, record),
    };
  }

  private async wait(
    pid: number,
    record: ProcessRecord,
  ): Promise<CommandResult> {
    if (!record.waitPromise) {
      throw new Error(`Kalahari process ${pid} has not started collecting.`);
    }
    return record.waitPromise;
  }

  private async collect(
    pid: number,
    record: ProcessRecord,
  ): Promise<CommandResult> {
    let stdout = "";
    let stderr = "";
    let exitCode = 0;
    try {
      for (;;) {
        const chunk = await record.session.read();
        if (!chunk) {
          if (record.terminationError) {
            throw record.terminationError;
          }
          break;
        }
        stdout += chunk.stdout ?? "";
        stderr += chunk.stderr ?? "";
        if (chunk.stdout) {
          await record.callbacks.onStdout?.(chunk.stdout);
        }
        if (chunk.stderr) {
          await record.callbacks.onStderr?.(chunk.stderr);
        }
        if (chunk.exitCode !== undefined) {
          exitCode = chunk.exitCode;
          break;
        }
      }
    } catch (error) {
      await this.terminateAfterWaitError(pid, record, error);
      throw error;
    }
    this.processes.delete(pid);
    return {
      stdout,
      stderr,
      exitCode,
      durationMs: Date.now() - record.startedAtMs,
    };
  }

  private record(pid: number, label: string): ProcessRecord {
    const record = this.processes.get(pid);
    if (!record) {
      throw new Error(`${label} ${pid} was not found.`);
    }
    return record;
  }

  private async terminate(
    pid: number,
    record: ProcessRecord,
    reason = new Error(`Kalahari process ${pid} was terminated.`),
  ): Promise<void> {
    record.terminationError ??= reason;
    record.terminationPromise ??= terminateSession(record.session).finally(
      () => {
        this.processes.delete(pid);
      },
    );
    await record.terminationPromise;
  }

  private async terminateAfterWaitError(
    pid: number,
    record: ProcessRecord,
    waitError: unknown,
  ): Promise<void> {
    try {
      await this.terminate(pid, record, errorFromUnknown(waitError));
    } catch (cleanupError) {
      throw new AggregateError(
        [waitError, cleanupError],
        "Kalahari process wait failed and cleanup also failed.",
      );
    }
  }
}

export async function runDetachedProcess(
  sandbox: KalahariSandbox,
  command: string,
  options: KalahariStartProcessOptions = {},
): Promise<void> {
  const session = await createPtySession(sandbox, {
    args: options.args,
    command,
    cwd: options.cwd,
    env: options.env,
    shell: options.shell === true,
  });
  void drainSession(session, {
    onStderr: options.onStderr,
    onStdout: options.onStdout,
  }).catch(() => undefined);
}

async function createPtySession(
  sandbox: KalahariSandbox,
  options: {
    args?: string[] | undefined;
    command: string;
    cwd?: string | undefined;
    env?: CommandEnv | undefined;
    shell: boolean;
  },
): Promise<KalahariPtySession> {
  return sandbox.createPty(
    options.shell
      ? {
          command: "/bin/sh",
          args: ["-lc", options.command],
          env: options.env,
          cwd: options.cwd,
        }
      : {
          command: options.command,
          args: options.args,
          env: options.env,
          cwd: options.cwd,
        },
  );
}

async function drainSession(
  session: KalahariPtySession,
  callbacks: KalahariProcessCallbacks = {},
): Promise<void> {
  try {
    for (;;) {
      const chunk = await readPtyForDrain(session);
      if (!chunk) {
        break;
      }
      if (chunk.stdout) {
        await callbacks.onStdout?.(chunk.stdout);
      }
      if (chunk.stderr) {
        await callbacks.onStderr?.(chunk.stderr);
      }
      if (chunk.exitCode !== undefined) {
        break;
      }
    }
  } catch (error) {
    await terminateDetachedDrainAfterError(session, error);
    throw error;
  }
}

async function readPtyForDrain(
  session: KalahariPtySession,
): Promise<Awaited<ReturnType<KalahariPtySession["read"]>>> {
  try {
    return await session.read();
  } catch (error) {
    if (isFinishedPtyError(error)) {
      return null;
    }
    throw error;
  }
}

async function ignoreFinishedPtyError(operation: Promise<void>): Promise<void> {
  try {
    await operation;
  } catch (error) {
    if (!isFinishedPtyError(error)) {
      throw error;
    }
  }
}

async function terminateSession(session: KalahariPtySession): Promise<void> {
  let writeError: unknown;
  try {
    await ignoreFinishedPtyError(session.write("\x03"));
  } catch (error) {
    writeError = error;
  }

  try {
    await ignoreFinishedPtyError(session.close());
  } catch (closeError) {
    if (writeError) {
      throw new AggregateError(
        [writeError, closeError],
        "Failed to interrupt and close PTY session.",
      );
    }
    throw closeError;
  }

  if (writeError) {
    throw writeError;
  }
}

async function terminateDetachedDrainAfterError(
  session: KalahariPtySession,
  drainError: unknown,
): Promise<void> {
  try {
    await terminateSession(session);
  } catch (cleanupError) {
    throw new AggregateError(
      [drainError, cleanupError],
      "Detached PTY drain failed and cleanup also failed.",
    );
  }
}

async function terminateAfterStartError(
  session: KalahariPtySession,
  startError: unknown,
): Promise<void> {
  try {
    await terminateSession(session);
  } catch (cleanupError) {
    throw new AggregateError(
      [startError, cleanupError],
      "Kalahari process startup failed and cleanup also failed.",
    );
  }
}

let nextProcessPid = 1;

function nextPid(): number {
  return nextProcessPid++;
}

function errorFromUnknown(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function isFinishedPtyError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (/Kalahari PTY session .* (is closed|was not found)|Kalahari PTY session is closed|PTY session .* is closed/.test(
      error.message,
    ) ||
      /Kalahari sandbox worker (has stopped|dropped pty .* reply)/.test(
        error.message,
      ))
  );
}
