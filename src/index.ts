/// <reference path="./types/computesdk-augment.d.ts" />
import { envEntries } from "./compat.js";
import { loadNativeBinding, resolveWorkerPath } from "./native.js";
import {
  clearProcessRegistryForSandbox,
  existingProcessRegistryForSandbox,
  processRegistryForSandbox,
} from "./process.js";

import type {
  KalahariProcessHandle,
  KalahariProcessInfo,
  KalahariStartProcessOptions,
} from "./process.js";
import type {
  KalahariClientOptions,
  KalahariFileInfo,
  KalahariSandboxInfo,
  KalahariZygoteInfo,
  KalahariZygoteSpawnOptions,
  CommandResult,
  CreatePtyOptions,
  CreateSandboxOptions,
  NativeCommandResult,
  NativePreparedImage,
  NativeSandbox,
  NativeZygote,
  NativePtySession,
  PtyOutput,
  PrepareImageOptions,
  PreparedImage,
  RunCommandOptions,
  RunOneShotCommandOptions,
  RunShellOptions,
} from "./types.js";

export type {
  KalahariProcessHandle,
  KalahariProcessInfo,
  KalahariStartProcessOptions,
} from "./process.js";
export type {
  KalahariClientOptions,
  KalahariFileInfo,
  KalahariOptions,
  KalahariSandboxInfo,
  KalahariZygoteInfo,
  KalahariZygoteSpawnOptions,
  CommandEnv,
  CommandResult,
  CreatePtyOptions,
  CreateSandboxOptions,
  NativeSandbox,
  NativeZygote,
  NativePtySession,
  PrepareImageOptions,
  PreparedImage,
  PtyOutput,
  RunCommandOptions,
  RunOneShotCommandOptions,
  RunNativeCommandOptions,
  RunShellOptions,
  RunSandboxCommandOptions,
} from "./types.js";

const sandboxes = new Map<string, KalahariSandbox>();

export function available(): boolean {
  return loadNativeBinding().available();
}

export async function prepareImage(
  options: PrepareImageOptions,
): Promise<PreparedImage> {
  return normalizePreparedImage(
    await loadNativeBinding().prepareImage({
      image: requireImage(options.image),
    }),
  );
}

export async function createNativeSandbox(
  options: CreateSandboxOptions,
): Promise<NativeSandbox> {
  const createOptions = normalizeCreateSandboxOptions(options);
  return loadNativeBinding().createSandbox({
    ...createOptions,
    image: requireImage(createOptions.image),
    workerPath: resolveWorkerPath(createOptions.workerPath),
  });
}

function requireImage(image: string | undefined): string {
  if (!image) {
    throw new Error(
      'kalahari: image is required, for example "node:22-alpine".',
    );
  }
  return image;
}

export async function createSandbox(
  options: CreateSandboxOptions,
): Promise<KalahariSandbox> {
  return defaultClient.createSandbox(options);
}

export async function runCommand(
  options: RunOneShotCommandOptions,
): Promise<CommandResult> {
  const sandbox = await createSandbox(createSandboxOptionsFromOneShot(options));
  try {
    return await sandbox.run(options.command, runOptionsFromOneShot(options));
  } finally {
    await sandbox.destroy();
  }
}

export class KalahariClient {
  readonly options: KalahariClientOptions;

  constructor(options: KalahariClientOptions = {}) {
    this.options = normalizeCreateSandboxOptions(options);
  }

  async prepareImage(
    options: Partial<PrepareImageOptions> = {},
  ): Promise<PreparedImage> {
    return prepareImage({
      image: requireImage(options.image ?? this.options.image),
    });
  }

  async createSandbox(
    options: KalahariClientOptions = {},
  ): Promise<KalahariSandbox> {
    const merged = normalizeCreateSandboxOptions({
      ...this.options,
      ...options,
    });
    const native = await createNativeSandbox({
      ...merged,
      image: requireImage(merged.image),
    });
    const sandbox = new KalahariSandbox(native);
    sandboxes.set(sandbox.id, sandbox);
    return sandbox;
  }

  getById(sandboxId: string): KalahariSandbox | null {
    const sandbox = sandboxes.get(sandboxId);
    return sandbox && !sandbox.isDestroyed() ? sandbox : null;
  }

  list(): KalahariSandbox[] {
    return [...sandboxes.values()].filter((sandbox) => !sandbox.isDestroyed());
  }

  async destroy(sandboxId: string): Promise<void> {
    const sandbox = sandboxes.get(sandboxId);
    if (sandbox) {
      await sandbox.destroy();
    }
  }

  async runCommand(options: RunOneShotCommandOptions): Promise<CommandResult> {
    const sandbox = await this.createSandbox(
      createSandboxOptionsFromOneShot(options),
    );
    try {
      return await sandbox.run(options.command, runOptionsFromOneShot(options));
    } finally {
      await sandbox.destroy();
    }
  }
}

export class KalahariSandbox {
  readonly native: NativeSandbox;
  private zygoted = false;

  constructor(native: NativeSandbox) {
    this.native = native;
  }

  get id(): string {
    return this.native.id;
  }

  get image(): string {
    return this.native.image;
  }

  get requestedImage(): string {
    return (
      this.native.requestedImage ?? this.native.requested_image ?? this.image
    );
  }

  get storeDir(): string | undefined {
    return this.native.storeDir ?? this.native.store_dir;
  }

  get createdAt(): Date {
    return new Date(this.native.createdAtMs ?? this.native.created_at_ms ?? 0);
  }

  isDestroyed(): boolean {
    return this.native.isDestroyed();
  }

  info(): KalahariSandboxInfo {
    const info: KalahariSandboxInfo = {
      id: this.id,
      image: this.image,
      requestedImage: this.requestedImage,
      createdAt: this.createdAt,
      destroyed: this.isDestroyed(),
    };
    const storeDir = this.storeDir;
    if (storeDir !== undefined) {
      info.storeDir = storeDir;
    }
    return info;
  }

  async zygote(): Promise<KalahariZygote> {
    this.assertRunning();
    const registry = existingProcessRegistryForSandbox(this.id);
    if (registry && registry.list().length > 0) {
      throw new Error(
        `kalahari sandbox ${this.id} cannot become a zygote while processes are active.`,
      );
    }

    try {
      const native = await this.native.zygote();
      this.zygoted = true;
      registry?.discardAll();
      clearProcessRegistryForSandbox(this.id);
      sandboxes.delete(this.id);
      return new KalahariZygote(native);
    } catch (error) {
      if (this.isDestroyed()) {
        registry?.discardAll();
        clearProcessRegistryForSandbox(this.id);
        sandboxes.delete(this.id);
      }
      throw error;
    }
  }

  async run(
    command: string,
    options: RunCommandOptions = {},
  ): Promise<CommandResult> {
    this.assertRunning();
    return normalizeCommandResult(
      await this.native.runCommand({
        command,
        args: options.args,
        stdinBase64: stdinBase64(options.stdin),
        env: envEntries(options.env),
        cwd: options.cwd,
        timeoutMs: options.timeoutMs,
        outputLimitBytes: options.outputLimitBytes,
      }),
    );
  }

  async runShell(
    command: string,
    options: RunShellOptions = {},
  ): Promise<CommandResult> {
    return this.run("/bin/sh", {
      ...options,
      args: ["-lc", command],
    });
  }

  async createPty(options: CreatePtyOptions): Promise<KalahariPtySession> {
    this.assertRunning();
    const native = await this.native.createPty({
      command: options.command,
      args: options.args,
      env: envEntries(options.env),
      cwd: options.cwd,
    });
    return new KalahariPtySession(native);
  }

  async startProcess(
    command: string,
    options: KalahariStartProcessOptions = {},
  ): Promise<KalahariProcessHandle> {
    this.assertRunning();
    return processRegistryForSandbox(this.id).start(this, command, options);
  }

  async startShell(
    command: string,
    options: KalahariStartProcessOptions = {},
  ): Promise<KalahariProcessHandle> {
    return this.startProcess(command, { ...options, shell: true });
  }

  listProcesses(): KalahariProcessInfo[] {
    return existingProcessRegistryForSandbox(this.id)?.list() ?? [];
  }

  connectProcess(pid: number): KalahariProcessHandle {
    return processRegistryForSandbox(this.id).handle(pid);
  }

  async killProcess(pid: number): Promise<boolean> {
    return (
      (await existingProcessRegistryForSandbox(this.id)?.kill(pid)) ?? false
    );
  }

  async closeProcesses(): Promise<void> {
    await existingProcessRegistryForSandbox(this.id)?.closeAll();
  }

  async readFile(path: string): Promise<string> {
    const result = await this.run("@kalahari:fs-read", { args: [path] });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr || `Failed to read file: ${path}`);
    }
    return result.stdout;
  }

  async readFileBytes(path: string): Promise<Uint8Array> {
    const result = await this.run("@kalahari:fs-read-b64", { args: [path] });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr || `Failed to read file: ${path}`);
    }
    return Buffer.from(result.stdout.trim(), "base64");
  }

  async writeFile(path: string, content: string): Promise<void> {
    await this.writeFileBytes(path, Buffer.from(content));
  }

  async writeFileBytes(path: string, content: Uint8Array): Promise<void> {
    const result = await this.run("@kalahari:fs-write", {
      args: [path],
      stdin: content,
    });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr || `Failed to write file: ${path}`);
    }
  }

  async mkdir(path: string): Promise<void> {
    const result = await this.run("@kalahari:fs-mkdir", { args: [path] });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr || `Failed to create directory: ${path}`);
    }
  }

  async readdir(path: string): Promise<string[]> {
    return (await this.listFiles(path)).map((entry) => entry.name);
  }

  async listFiles(path: string): Promise<KalahariFileInfo[]> {
    const result = await this.run("@kalahari:fs-list", { args: [path] });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr || `Failed to read directory: ${path}`);
    }
    return parseKalahariFileInfo(result.stdout, path);
  }

  async statFile(path: string): Promise<KalahariFileInfo> {
    const result = await this.run("@kalahari:fs-stat", { args: [path] });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr || `Failed to stat file: ${path}`);
    }
    return parseKalahariFileStat(result.stdout, path);
  }

  async exists(path: string): Promise<boolean> {
    const result = await this.run("@kalahari:fs-exists", { args: [path] });
    return result.exitCode === 0;
  }

  async remove(path: string): Promise<void> {
    const result = await this.run("@kalahari:fs-remove", { args: [path] });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr || `Failed to remove: ${path}`);
    }
  }

  async rename(oldPath: string, newPath: string): Promise<void> {
    const result = await this.run("@kalahari:fs-rename", {
      args: [oldPath, newPath],
    });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr || `Failed to rename: ${oldPath}`);
    }
  }

  async destroy(): Promise<void> {
    const registry = existingProcessRegistryForSandbox(this.id);
    try {
      if (this.isDestroyed()) {
        registry?.discardAll();
        return;
      }
      try {
        await registry?.closeAll();
      } finally {
        await this.native.destroy();
      }
    } finally {
      clearProcessRegistryForSandbox(this.id);
      sandboxes.delete(this.id);
    }
  }

  private assertRunning(): void {
    if (this.zygoted) {
      throw new Error(`kalahari sandbox ${this.id} has become a zygote.`);
    }
    if (this.isDestroyed()) {
      throw new Error(`kalahari sandbox ${this.id} is not running.`);
    }
  }
}

export class KalahariZygote {
  readonly native: NativeZygote;

  constructor(native: NativeZygote) {
    this.native = native;
  }

  get id(): string {
    return this.native.id;
  }

  get image(): string {
    return this.native.image;
  }

  get requestedImage(): string {
    return (
      this.native.requestedImage ?? this.native.requested_image ?? this.image
    );
  }

  get storeDir(): string | undefined {
    return this.native.storeDir ?? this.native.store_dir;
  }

  get createdAt(): Date {
    return new Date(this.native.createdAtMs ?? this.native.created_at_ms ?? 0);
  }

  isDestroyed(): boolean {
    return this.native.isDestroyed();
  }

  info(): KalahariZygoteInfo {
    const info: KalahariZygoteInfo = {
      id: this.id,
      image: this.image,
      requestedImage: this.requestedImage,
      createdAt: this.createdAt,
      destroyed: this.isDestroyed(),
    };
    const storeDir = this.storeDir;
    if (storeDir !== undefined) {
      info.storeDir = storeDir;
    }
    return info;
  }

  async spawn(
    options: KalahariZygoteSpawnOptions = {},
  ): Promise<KalahariSandbox> {
    if (this.isDestroyed()) {
      throw new Error(`kalahari zygote ${this.id} is destroyed.`);
    }
    const native = await this.native.spawn({ ...options });
    const sandbox = new KalahariSandbox(native);
    sandboxes.set(sandbox.id, sandbox);
    return sandbox;
  }

  async destroy(): Promise<void> {
    await this.native.destroy();
  }
}

export class KalahariPtySession {
  readonly native: NativePtySession;

  constructor(native: NativePtySession) {
    this.native = native;
  }

  get id(): string {
    return this.native.id;
  }

  get sandboxId(): string | undefined {
    return this.native.sandboxId ?? this.native.sandbox_id;
  }

  async read(): Promise<PtyOutput | null> {
    return normalizePtyOutput(await this.native.read());
  }

  async write(data: string | Uint8Array): Promise<void> {
    if (typeof data === "string") {
      await this.native.write(data);
      return;
    }
    await this.native.writeBytes(Array.from(data));
  }

  async resize(rows: number, cols: number): Promise<void> {
    await this.native.resize(rows, cols);
  }

  async close(): Promise<void> {
    await this.native.close();
  }
}

export function normalizeCommandResult(
  result: NativeCommandResult,
): CommandResult {
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    exitCode: result.exitCode ?? result.exit_code ?? 1,
    durationMs: result.durationMs ?? result.duration_ms ?? 0,
  };
}

function normalizePreparedImage(result: NativePreparedImage): PreparedImage {
  return {
    image: result.image,
    source: result.source,
    storeDir: result.storeDir ?? result.store_dir ?? "",
    manifestDigest: result.manifestDigest ?? result.manifest_digest ?? "",
    layers: result.layers,
    alreadyPresent: result.alreadyPresent ?? result.already_present ?? false,
  };
}

function normalizePtyOutput(result: PtyOutput | null): PtyOutput | null {
  if (!result) {
    return null;
  }
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exitCode ?? result.exit_code,
  };
}

function stdinBase64(
  stdin: string | Uint8Array | ArrayBuffer | undefined,
): string | undefined {
  if (stdin === undefined) {
    return undefined;
  }
  if (typeof stdin === "string") {
    return Buffer.from(stdin).toString("base64");
  }
  if (stdin instanceof ArrayBuffer) {
    return Buffer.from(stdin).toString("base64");
  }
  return Buffer.from(stdin).toString("base64");
}

function parseKalahariFileInfo(
  stdout: string,
  path: string,
): KalahariFileInfo[] {
  const value: unknown = JSON.parse(stdout || "[]");
  if (!Array.isArray(value)) {
    throw new Error(`Failed to parse directory listing for ${path}`);
  }
  return value.map((entry) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Invalid directory entry for ${path}`);
    }
    const item = entry as Record<string, unknown>;
    const itemName = item["name"];
    const itemPath = item["path"];
    if (typeof itemName !== "string" || typeof itemPath !== "string") {
      throw new Error(`Invalid directory entry for ${path}`);
    }
    const result: KalahariFileInfo = {
      name: itemName,
      path: itemPath,
      type: item["type"] === "dir" ? ("dir" as const) : ("file" as const),
    };
    const itemSize = item["size"];
    if (typeof itemSize === "number") {
      result.size = itemSize;
    }
    const itemModTimeMs = item["modTimeMs"];
    if (typeof itemModTimeMs === "number") {
      result.modTimeMs = itemModTimeMs;
    }
    return result;
  });
}

function parseKalahariFileStat(stdout: string, path: string): KalahariFileInfo {
  const value: unknown = JSON.parse(stdout || "{}");
  if (!value || typeof value !== "object") {
    throw new Error(`Failed to parse file details for ${path}`);
  }
  const item = value as Record<string, unknown>;
  const itemName = item["name"];
  const itemPath = item["path"];
  if (typeof itemName !== "string" || typeof itemPath !== "string") {
    throw new Error(`Invalid file details for ${path}`);
  }
  const result: KalahariFileInfo = {
    name: itemName,
    path: itemPath,
    type: item["type"] === "dir" ? "dir" : "file",
  };
  const itemSize = item["size"];
  if (typeof itemSize === "number") {
    result.size = itemSize;
  }
  const itemModTimeMs = item["modTimeMs"];
  if (typeof itemModTimeMs === "number") {
    result.modTimeMs = itemModTimeMs;
  }
  return result;
}

const defaultClient = new KalahariClient();

function createSandboxOptionsFromOneShot(
  options: RunOneShotCommandOptions,
): CreateSandboxOptions {
  const {
    args: _args,
    command: _command,
    cwd: _cwd,
    env: _env,
    stdin: _stdin,
    ...sandboxOptions
  } = options;
  return sandboxOptions;
}

function normalizeCreateSandboxOptions(
  options: KalahariClientOptions = {},
): KalahariClientOptions {
  return {
    image: options.image,
    prepareImage: options.prepareImage,
    workerPath: options.workerPath,
    memoryMb: options.memoryMb,
    vcpus: options.vcpus,
    timeoutMs: options.timeoutMs,
    outputLimitBytes: options.outputLimitBytes,
    requestQueueSize: options.requestQueueSize,
    network: options.network
      ? {
          mode: options.network.mode,
          dns: options.network.dns,
          allowList: options.network.allowList
            ? [...options.network.allowList]
            : undefined,
          dnsMode: options.network.dnsMode,
        }
      : undefined,
  };
}

function runOptionsFromOneShot(
  options: RunOneShotCommandOptions,
): RunCommandOptions {
  return {
    args: options.args,
    cwd: options.cwd,
    env: options.env,
    outputLimitBytes: options.outputLimitBytes,
    stdin: options.stdin,
    timeoutMs: options.timeoutMs,
  };
}
