import { KalahariClient, KalahariSandbox } from "./index.js";

import { dataToBytes, unsupported, unsupportedSync } from "./compat.js";
import type { KalahariProcessHandle, KalahariProcessInfo } from "./index.js";
import type {
  CommandEnv,
  CommandResult,
  KalahariClientOptions,
  KalahariFileInfo,
  RunCommandOptions,
} from "./types.js";

export interface E2BCommandOptions {
  args?: string[];
  background?: boolean;
  cwd?: string;
  envs?: CommandEnv;
  onStderr?: (data: string) => void | Promise<void>;
  onStdout?: (data: string) => void | Promise<void>;
  requestTimeoutMs?: number;
  stdin?: boolean;
  timeoutMs?: number;
  user?: string;
}

export interface E2BEntryInfo {
  name: string;
  path: string;
  type: "file" | "dir";
}

export interface E2BProcessInfo {
  args: string[];
  cmd: string;
  cwd?: string | undefined;
  envs: Record<string, string>;
  pid: number;
  tag?: string | undefined;
}

export interface E2BCommandHandle {
  pid: number;
  wait(): Promise<CommandResult>;
  kill(): Promise<boolean>;
  sendStdin(data: string): Promise<void>;
}

export interface E2BWatchHandle {
  stop(): Promise<void>;
}

export interface E2BFileSystem {
  exists(path: string): Promise<boolean>;
  list(path: string): Promise<E2BEntryInfo[]>;
  makeDir(path: string): Promise<boolean>;
  read(
    path: string,
    options?: { format?: "text" | "bytes" },
  ): Promise<string | Uint8Array>;
  remove(path: string): Promise<void>;
  rename(oldPath: string, newPath: string): Promise<E2BEntryInfo>;
  watchDir(
    path: string,
    onEvent: (event: unknown) => void | Promise<void>,
  ): Promise<E2BWatchHandle>;
  write(
    path: string,
    data: string | ArrayBuffer | ArrayBufferView | Blob | ReadableStream,
  ): Promise<E2BEntryInfo>;
}

export interface E2BPty {
  create(options?: {
    cmd?: string;
    cols?: number;
    rows?: number;
  }): Promise<E2BCommandHandle>;
  kill(pid: number): Promise<boolean>;
  resize(pid: number, size: { cols: number; rows?: number }): Promise<void>;
  sendInput(pid: number, data: Uint8Array): Promise<void>;
}

export class Sandbox extends KalahariSandbox {
  readonly files: E2BFileSystem = {
    exists: (path) => this.exists(path),
    list: async (path) => {
      return this.listFiles(path);
    },
    makeDir: async (path) => {
      const existed = await this.exists(path);
      await this.mkdir(path);
      return !existed;
    },
    read: async (path, options?: { format?: "text" | "bytes" }) => {
      if (options?.format === "bytes") {
        return this.readFileBytes(path);
      }
      return this.readFile(path);
    },
    remove: (path) => this.remove(path),
    rename: async (oldPath, newPath) => {
      await this.rename(oldPath, newPath);
      return e2bEntryFromKalahari(await this.statFile(newPath));
    },
    watchDir: () => unsupported("E2B files.watchDir"),
    write: async (path, data) => {
      if (typeof data === "string") {
        await this.writeFile(path, data);
      } else {
        await this.writeFileBytes(path, await dataToBytes(data));
      }
      return e2bEntryFromKalahari(await this.statFile(path));
    },
  };

  readonly commands = {
    connect: (pid: number) => this.connectE2BCommand(pid),
    kill: (pid: number) => this.killProcess(pid),
    list: async (): Promise<E2BProcessInfo[]> =>
      this.listProcesses().map(e2bProcessInfoFromKalahari),
    run: (command: string, options: E2BCommandOptions = {}) =>
      this.runE2BCommand(command, options),
    exec: (command: string, options: E2BCommandOptions = {}) =>
      this.runE2BCommand(command, options),
    sendStdin: (pid: number, data: string) =>
      this.sendStdinE2BCommand(pid, data),
  };

  readonly pty: E2BPty = {
    create: (options = {}) => this.createE2BPty(options),
    kill: (pid) => this.killProcess(pid),
    resize: (pid, size) => this.resizeE2BPty(pid, size),
    sendInput: (pid, data) => this.writeE2BPty(pid, data),
  };

  get sandboxId(): string {
    return this.id;
  }

  static create(options?: KalahariClientOptions): Promise<Sandbox>;
  static create(
    templateId: string,
    options?: KalahariClientOptions,
  ): Promise<never>;
  static async create(
    templateOrOptions: string | KalahariClientOptions = {},
    options: KalahariClientOptions = {},
  ): Promise<Sandbox> {
    if (typeof templateOrOptions === "string") {
      void options;
      return unsupported("E2B template sandbox creation");
    }
    const createOptions = templateOrOptions;
    const native = await new KalahariClient(createOptions).createSandbox();
    return new Sandbox(native.native);
  }

  static async connect(sandboxId: string): Promise<Sandbox> {
    const existing = new KalahariClient().getById(sandboxId);
    if (!existing) {
      throw new Error(
        "Kalahari can only reconnect to sandboxes in this process.",
      );
    }
    return new Sandbox(existing.native);
  }

  static async kill(sandboxId: string): Promise<boolean> {
    const client = new KalahariClient();
    const existing = client.getById(sandboxId);
    if (!existing) {
      return false;
    }
    await existing.destroy();
    return true;
  }

  static async list(): Promise<Array<{ sandboxId: string }>> {
    return new KalahariClient().list().map((sandbox) => ({
      sandboxId: sandbox.id,
    }));
  }

  static async setTimeout(
    sandboxId: string,
    timeoutMs: number,
  ): Promise<never> {
    void sandboxId;
    void timeoutMs;
    return unsupported("E2B sandbox setTimeout");
  }

  async isRunning(): Promise<boolean> {
    return !this.isDestroyed();
  }

  async setTimeout(timeoutMs: number): Promise<never> {
    void timeoutMs;
    return unsupported("E2B sandbox setTimeout");
  }

  async kill(): Promise<void> {
    await this.destroy();
  }

  override async destroy(): Promise<void> {
    await super.destroy();
  }

  getHost(port: number): string {
    void port;
    return unsupportedSync("E2B getHost");
  }

  uploadUrl(): string {
    throw new Error(
      "E2B uploadUrl is not supported by local Kalahari sandboxes yet.",
    );
  }

  downloadUrl(): string {
    throw new Error(
      "E2B downloadUrl is not supported by local Kalahari sandboxes yet.",
    );
  }

  async commandsRun(
    command: string,
    options: E2BCommandOptions = {},
  ): Promise<CommandResult | E2BCommandHandle> {
    return this.runE2BCommand(command, options);
  }

  private async runE2BCommand(
    command: string,
    options: E2BCommandOptions,
  ): Promise<CommandResult | E2BCommandHandle> {
    rejectUnsupportedE2BCommandOptions(options);
    if (options.background || options.stdin) {
      return this.startE2BCommandHandle(command, options);
    }
    const runOptions = toRunOptions(options);
    const result = Array.isArray(options.args)
      ? await this.run(command, runOptions)
      : await this.runShell(command, runOptions);
    await options.onStdout?.(result.stdout);
    await options.onStderr?.(result.stderr);
    return result;
  }

  private async startE2BCommandHandle(
    command: string,
    options: E2BCommandOptions,
  ): Promise<E2BCommandHandle> {
    const handle = await this.startProcess(command, {
      args: options.args,
      cwd: options.cwd,
      env: options.envs,
      onStderr: options.onStderr,
      onStdout: options.onStdout,
      shell: !Array.isArray(options.args),
    });
    return e2bHandle(handle);
  }

  private async createE2BPty(options: {
    cmd?: string;
    cols?: number;
    rows?: number;
  }): Promise<E2BCommandHandle> {
    const handle = await this.startProcess(options.cmd ?? "/bin/sh", {
      cols: options.cols,
      rows: options.rows,
      shell: options.cmd !== undefined,
    });
    return e2bHandle(handle);
  }

  private async connectE2BCommand(pid: number): Promise<E2BCommandHandle> {
    return e2bHandle(this.connectProcess(pid));
  }

  private async sendStdinE2BCommand(pid: number, data: string): Promise<void> {
    await this.connectProcess(pid).sendStdin(data);
  }

  private async resizeE2BPty(
    pid: number,
    size: { cols: number; rows?: number },
  ): Promise<void> {
    await this.connectProcess(pid).resize(size);
  }

  private async writeE2BPty(pid: number, data: Uint8Array): Promise<void> {
    await this.connectProcess(pid).sendStdin(data);
  }
}

export const E2B = { Sandbox };

function toRunOptions(options: E2BCommandOptions): RunCommandOptions {
  return {
    args: options.args,
    env: options.envs,
    cwd: options.cwd,
    timeoutMs: options.timeoutMs ?? options.requestTimeoutMs,
  };
}

function rejectUnsupportedE2BCommandOptions(options: E2BCommandOptions): void {
  const unsupportedFeatures = [];
  if (options.user !== undefined) {
    unsupportedFeatures.push("user");
  }
  if (options.background || options.stdin) {
    if (options.timeoutMs !== undefined) {
      unsupportedFeatures.push("background timeoutMs");
    }
    if (options.requestTimeoutMs !== undefined) {
      unsupportedFeatures.push("background requestTimeoutMs");
    }
  }
  if (unsupportedFeatures.length > 0) {
    throw new Error(
      `E2B command option is not supported by Kalahari yet: ${unsupportedFeatures.join(", ")}.`,
    );
  }
}

function e2bEntryFromKalahari(entry: KalahariFileInfo): E2BEntryInfo {
  return {
    name: entry.name,
    path: entry.path,
    type: entry.type,
  };
}

function e2bProcessInfoFromKalahari(info: KalahariProcessInfo): E2BProcessInfo {
  return {
    args: info.args,
    cmd: info.command,
    cwd: info.cwd,
    envs: info.env,
    pid: info.pid,
  };
}

function e2bHandle(handle: KalahariProcessHandle): E2BCommandHandle {
  return {
    pid: handle.pid,
    wait: () => handle.wait(),
    kill: () => handle.kill(),
    sendStdin: (data) => handle.sendStdin(data),
  };
}
