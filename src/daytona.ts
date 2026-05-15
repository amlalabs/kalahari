import {
  readFile as readHostFile,
  writeFile as writeHostFile,
} from "node:fs/promises";
import { Readable } from "node:stream";

import {
  assertOk,
  fileInfo,
  mergeEnv,
  permissionMode,
  secondsToMs,
  stripUndefined,
  unsupported,
  unsupportedSync,
} from "./compat.js";
import { KalahariClient, KalahariSandbox } from "./index.js";

import type {
  CommandEnv,
  CommandResult,
  KalahariClientOptions,
  NativeSandbox,
  NetworkOptions,
  RunCommandOptions,
} from "./types.js";

const DAYTONA_WORKDIR = "/workspace";

export interface DaytonaConfig extends KalahariClientOptions {
  apiKey?: string;
  apiUrl?: string;
  jwtToken?: string;
  organizationId?: string;
  target?: string;
}

export interface DaytonaCreateOptions extends KalahariClientOptions {
  autoArchiveInterval?: number;
  autoDeleteInterval?: number;
  autoStopInterval?: number;
  envVars?: Record<string, string>;
  ephemeral?: boolean;
  labels?: Record<string, string>;
  language?: string;
  name?: string;
  networkAllowList?: string;
  networkBlockAll?: boolean;
  public?: boolean;
  resources?: { cpu?: number; memory?: number; disk?: number };
  snapshot?: string;
  target?: string;
  user?: string;
  volumes?: Array<{ volumeId: string; mountPath: string }>;
}

export interface DaytonaExecuteOptions {
  args?: string[];
  env?: CommandEnv;
  cwd?: string;
  timeoutMs?: number;
}

export interface DaytonaSessionCommandRequest extends DaytonaExecuteOptions {
  command: string;
}

export interface DaytonaExecuteResponse {
  artifacts: { stdout: string; charts: unknown[] };
  exitCode: number;
  result: string;
  stderr: string;
  stdout: string;
}

export interface DaytonaFileInfo {
  modTime?: string;
  name: string;
  path: string;
  size: number;
  type: "file" | "dir";
}

export interface DaytonaReplaceResult {
  file: string;
  replacements: number;
  success: boolean;
}

interface DaytonaSandboxOptions {
  envVars?: Record<string, string> | undefined;
}

export class DaytonaSandbox extends KalahariSandbox {
  private readonly defaultEnv: Record<string, string>;

  constructor(native: NativeSandbox, options: DaytonaSandboxOptions = {}) {
    super(native);
    this.defaultEnv = { ...(options.envVars ?? {}) };
  }

  readonly process = {
    codeRun: (
      code: string,
      params?: { argv?: string[]; env?: Record<string, string> },
      timeout?: number,
    ) => this.codeRun(code, params, timeout),
    createSession: (): Promise<never> => unsupported("Daytona createSession"),
    deleteSession: (): Promise<never> => unsupported("Daytona deleteSession"),
    executeCommand: (command: string, options: DaytonaExecuteOptions = {}) =>
      this.processExecuteCommand(command, options),
    executeSessionCommand: (
      _sessionId: string,
      request: DaytonaSessionCommandRequest,
      timeout?: number,
    ): Promise<never> => {
      void _sessionId;
      void request;
      void timeout;
      return unsupported("Daytona executeSessionCommand");
    },
    getSession: (): Promise<never> => unsupported("Daytona getSession"),
    getSessionCommandLogs: (): Promise<never> =>
      unsupported("Daytona getSessionCommandLogs"),
    listSessions: (): Promise<never> => unsupported("Daytona listSessions"),
  };

  readonly fs = {
    createFolder: (path: string, mode?: string | number) =>
      this.createFolder(path, mode),
    deleteFile: (path: string) => this.remove(path),
    downloadFile: (
      source: string,
      destination?: string,
    ): Promise<Uint8Array | void> => this.downloadFile(source, destination),
    downloadFiles: (
      files: Array<{ source: string; destination: string }>,
    ): Promise<
      Array<{ destination: string; source: string; success: boolean }>
    > => this.downloadFiles(files),
    downloadFileStream: (path: string): Promise<Readable> =>
      this.downloadFileStream(path),
    findFiles: (path: string, pattern: string) => this.findFiles(path, pattern),
    getFileDetails: (path: string) => this.fileDetails(path),
    listFiles: (path: string): Promise<DaytonaFileInfo[]> =>
      this.listDaytonaFiles(path),
    moveFiles: (source: string, destination: string) =>
      this.rename(source, destination),
    replaceInFiles: (
      pathOrFiles: string | string[],
      pattern: string,
      replacement: string,
    ): Promise<DaytonaReplaceResult[]> =>
      this.replaceInFiles(pathOrFiles, pattern, replacement),
    searchFiles: (path: string, pattern: string) =>
      this.searchFiles(path, pattern),
    setFilePermissions: (
      path: string,
      params: { group?: string; mode?: string | number; owner?: string },
    ) => this.setFilePermissions(path, params),
    uploadFile: (source: string | Uint8Array, destination: string) =>
      this.uploadFile(source, destination),
    uploadFiles: (
      files: Array<{ source: string | Uint8Array; destination: string }>,
    ) =>
      Promise.all(
        files.map((file) => this.uploadFile(file.source, file.destination)),
      ).then(() => undefined),
    readFile: (path: string) => this.readFile(path),
    writeFile: (path: string, content: string) => this.writeFile(path, content),
  };

  readonly git = {
    add: (path: string, files: string[]) =>
      this.gitCommand(path, ["add", ...files]),
    clone: (url: string, path: string) =>
      this.run("git", {
        args: ["clone", url, path],
        env: mergeEnv(this.defaultEnv, undefined),
      }).then(assertOk),
    commit: (path: string, message: string) =>
      this.gitCommand(path, ["commit", "-m", message]),
    createBranch: (path: string, name: string) =>
      this.gitCommand(path, ["checkout", "-b", name]),
    deleteBranch: (path: string, name: string) =>
      this.gitCommand(path, ["branch", "-D", name]),
    pull: (path: string) => this.gitCommand(path, ["pull"]),
    push: (path: string) => this.gitCommand(path, ["push"]),
    status: async (path: string) => {
      const result = await this.run("git", {
        args: ["status", "--short", "--branch"],
        cwd: path,
        env: mergeEnv(this.defaultEnv, undefined),
      });
      return {
        currentBranch: parseBranch(result.stdout),
        output: result.stdout,
      };
    },
    switchBranch: (path: string, name: string) =>
      this.gitCommand(path, ["checkout", name]),
  };

  async processExecuteCommand(
    command: string,
    options: DaytonaExecuteOptions = {},
  ): Promise<DaytonaExecuteResponse> {
    const result = Array.isArray(options.args)
      ? await this.run(command, this.toRunOptions(options))
      : await this.runShell(command, this.toRunOptions(options));
    return executeResponse(result);
  }

  async codeRun(
    code: string,
    params?: { argv?: string[]; env?: Record<string, string> },
    timeout?: number,
  ): Promise<DaytonaExecuteResponse> {
    const language = this.requestedImage.includes("python") ? "python" : "node";
    const result = await this.run(language === "python" ? "python3" : "node", {
      args: ["-", ...(params?.argv ?? [])],
      stdin: code,
      env: mergeEnv(this.defaultEnv, params?.env),
      timeoutMs: secondsToMs(timeout),
    });
    return executeResponse(result);
  }

  async delete(): Promise<void> {
    await this.destroy();
  }

  async start(): Promise<void> {
    if (this.isDestroyed()) {
      await unsupported("Daytona start");
    }
  }

  stop(): Promise<never> {
    return unsupported("Daytona stop");
  }

  archive(): Promise<never> {
    return unsupported("Daytona archive");
  }

  recover(): Promise<never> {
    return unsupported("Daytona recover");
  }

  refreshActivity(): Promise<never> {
    return unsupported("Daytona refreshActivity");
  }

  refreshData(): Promise<never> {
    return unsupported("Daytona refreshData");
  }

  resize(): Promise<never> {
    return unsupported("Daytona resize");
  }

  waitForResizeComplete(): Promise<never> {
    return unsupported("Daytona waitForResizeComplete");
  }

  async waitUntilStarted(): Promise<void> {
    if (this.isDestroyed()) {
      await unsupported("Daytona waitUntilStarted");
    }
  }

  async waitUntilStopped(): Promise<void> {
    if (!this.isDestroyed()) {
      await unsupported("Daytona waitUntilStopped");
    }
  }

  async setLabels(labels: Record<string, string>): Promise<never> {
    void labels;
    return unsupported("Daytona setLabels");
  }

  async setAutoArchiveInterval(interval: number): Promise<never> {
    void interval;
    return unsupported("Daytona setAutoArchiveInterval");
  }

  async setAutoDeleteInterval(interval: number): Promise<never> {
    void interval;
    return unsupported("Daytona setAutoDeleteInterval");
  }

  async setAutostopInterval(interval: number): Promise<never> {
    void interval;
    return unsupported("Daytona setAutostopInterval");
  }

  getWorkDir(): string {
    return DAYTONA_WORKDIR;
  }

  getUserHomeDir(): string {
    return "/root";
  }

  getUserRootDir(): string {
    return "/";
  }

  get state(): "started" | "stopped" {
    return this.isDestroyed() ? "stopped" : "started";
  }

  createLspServer(): Promise<never> {
    return unsupported("Daytona createLspServer");
  }

  createSshAccess(): Promise<never> {
    return unsupported("Daytona createSshAccess");
  }

  revokeSshAccess(): Promise<never> {
    return unsupported("Daytona revokeSshAccess");
  }

  validateSshAccess(): Promise<never> {
    return unsupported("Daytona validateSshAccess");
  }

  getPreviewLink(port: number): string {
    void port;
    return unsupportedSync("Daytona getPreviewLink");
  }

  getSignedPreviewUrl(port: number): Promise<never> {
    void port;
    return unsupported("Daytona getSignedPreviewUrl");
  }

  expireSignedPreviewUrl(): Promise<never> {
    return unsupported("Daytona expireSignedPreviewUrl");
  }

  updateNetworkSettings(settings: {
    networkAllowList?: string;
    networkBlockAll?: boolean;
  }): Promise<void> {
    if (settings.networkAllowList?.trim()) {
      return unsupported("Daytona CIDR networkAllowList");
    }
    if (settings.networkBlockAll !== undefined) {
      return unsupported("Daytona runtime updateNetworkSettings");
    }
    return Promise.resolve();
  }

  _experimental_createSnapshot(): Promise<never> {
    return unsupported("Daytona _experimental_createSnapshot");
  }

  _experimental_fork(): Promise<never> {
    return unsupported("Daytona _experimental_fork");
  }

  private async createFolder(path: string, mode?: string | number) {
    await this.mkdir(path);
    if (mode !== undefined) {
      await this.setFilePermissions(path, { mode });
    }
  }

  private async downloadFile(
    source: string,
    destination?: string,
  ): Promise<Uint8Array | void> {
    const bytes = await this.readFileBytes(source);
    if (destination !== undefined) {
      await writeHostFile(destination, bytes);
      return;
    }
    return bytes;
  }

  private async downloadFiles(
    files: Array<{ source: string; destination: string }>,
  ): Promise<Array<{ destination: string; source: string; success: boolean }>> {
    return Promise.all(
      files.map(async (file) => {
        await this.downloadFile(file.source, file.destination);
        return { ...file, success: true };
      }),
    );
  }

  private async downloadFileStream(path: string): Promise<Readable> {
    return Readable.from(Buffer.from(await this.readFileBytes(path)));
  }

  private async findFiles(path: string, pattern: string) {
    const files = await this.collectTextFiles(path);
    const matches = await Promise.all(
      files.map((file) => this.findInFile(file, pattern)),
    );
    return matches.flat();
  }

  private async fileDetails(path: string): Promise<DaytonaFileInfo> {
    return fileInfo(await this.statFile(path));
  }

  private async listDaytonaFiles(path: string): Promise<DaytonaFileInfo[]> {
    const entries = await this.listFiles(path);
    return Promise.all(
      entries.map(async (entry) => fileInfo(await this.statFile(entry.path))),
    );
  }

  private async findInFile(path: string, pattern: string) {
    const content = await this.readFile(path);
    return findLiteralMatches(path, content, pattern);
  }

  private async setFilePermissions(
    path: string,
    params: { group?: string; mode?: string | number; owner?: string },
  ): Promise<void> {
    if (params.owner !== undefined || params.group !== undefined) {
      await unsupported("Daytona fs.setFilePermissions owner/group");
    }
    if (params.mode === undefined) {
      return;
    }
    const result = await this.run("@kalahari:fs-chmod", {
      args: [path, permissionMode(params.mode)],
    });
    assertOk(result);
  }

  private async replaceInFiles(
    pathOrFiles: string | string[],
    pattern: string,
    replacement: string,
  ): Promise<DaytonaReplaceResult[]> {
    if (pattern.length === 0) {
      throw new Error("Daytona fs.replaceInFiles pattern must not be empty.");
    }
    const files = Array.isArray(pathOrFiles)
      ? pathOrFiles
      : await this.collectTextFiles(pathOrFiles);
    return Promise.all(
      files.map((file) => this.replaceInFile(file, pattern, replacement)),
    );
  }

  private async uploadFile(source: string | Uint8Array, destination: string) {
    if (typeof source === "string") {
      await this.writeFileBytes(destination, await readHostFile(source));
      return;
    }
    await this.writeFileBytes(destination, source);
  }

  private async searchFiles(path: string, pattern: string) {
    const files = await this.collectAllFiles(path);
    return {
      files: files.filter((file) => matchesGlob(file, pattern)),
    };
  }

  private async collectTextFiles(path: string): Promise<string[]> {
    try {
      const entries = await this.listFiles(path);
      const files = await Promise.all(
        entries.map((entry) =>
          entry.type === "dir"
            ? this.collectTextFiles(entry.path)
            : Promise.resolve([entry.path]),
        ),
      );
      return files.flat();
    } catch {
      return [path];
    }
  }

  private async collectAllFiles(path: string): Promise<string[]> {
    try {
      const entries = await this.listFiles(path);
      const files = await Promise.all(
        entries.map((entry) =>
          entry.type === "dir"
            ? this.collectAllFiles(entry.path)
            : Promise.resolve([entry.path]),
        ),
      );
      return files.flat();
    } catch {
      return [path];
    }
  }

  private async replaceInFile(
    path: string,
    pattern: string,
    replacement: string,
  ): Promise<DaytonaReplaceResult> {
    const content = await this.readFile(path);
    if (!content.includes(pattern)) {
      return { file: path, replacements: 0, success: true };
    }
    const replacements = content.split(pattern).length - 1;
    await this.writeFile(path, content.split(pattern).join(replacement));
    return { file: path, replacements, success: true };
  }

  private async gitCommand(path: string, args: string[]): Promise<void> {
    const result = await this.run("git", {
      args,
      cwd: path,
      env: mergeEnv(this.defaultEnv, undefined),
    });
    assertOk(result);
  }

  private toRunOptions(options: DaytonaExecuteOptions): RunCommandOptions {
    return {
      args: options.args,
      env: mergeEnv(this.defaultEnv, options.env),
      cwd: options.cwd,
      timeoutMs: options.timeoutMs,
    };
  }
}

export class Daytona {
  private readonly client: KalahariClient;

  constructor(options: DaytonaConfig = {}) {
    rejectUnsupportedDaytonaConfig(options);
    this.client = new KalahariClient(options);
  }

  async create(
    options: DaytonaCreateOptions = {},
    createOptions: {
      timeout?: number;
      onSnapshotCreateLogs?: (chunk: string) => void;
    } = {},
  ): Promise<DaytonaSandbox> {
    rejectUnsupportedDaytonaCreateOptions(options);
    createOptions.onSnapshotCreateLogs?.(
      "Kalahari uses local OCI image preparation.\n",
    );
    const sandbox = await this.client.createSandbox(
      stripUndefined({
        image: options.image ?? imageForLanguage(options.language),
        memoryMb: options.memoryMb ?? gbToMb(options.resources?.memory),
        network: daytonaNetworkOptions(options),
        outputLimitBytes: options.outputLimitBytes,
        prepareImage: options.prepareImage,
        requestQueueSize: options.requestQueueSize,
        timeoutMs: secondsToMs(createOptions.timeout) ?? options.timeoutMs,
        vcpus: options.vcpus ?? options.resources?.cpu,
        workerPath: options.workerPath,
      }),
    );
    try {
      await sandbox.mkdir(DAYTONA_WORKDIR);
    } catch (error) {
      await sandbox.destroy().catch(() => undefined);
      throw error;
    }
    return new DaytonaSandbox(sandbox.native, {
      envVars: options.envVars,
    });
  }

  async delete(sandbox: DaytonaSandbox, _timeout = 60): Promise<void> {
    await sandbox.destroy();
  }

  async remove(sandbox: DaytonaSandbox | string): Promise<void> {
    if (typeof sandbox === "string") {
      await this.client.destroy(sandbox);
      return;
    }
    await sandbox.destroy();
  }

  async get(sandboxIdOrName: string): Promise<DaytonaSandbox> {
    const sandbox = this.client.getById(sandboxIdOrName);
    if (!sandbox) {
      throw new Error(`Kalahari sandbox ${sandboxIdOrName} was not found.`);
    }
    return new DaytonaSandbox(sandbox.native);
  }

  async list(): Promise<DaytonaSandbox[]> {
    return this.client
      .list()
      .map((sandbox) => new DaytonaSandbox(sandbox.native));
  }

  async start(sandbox: DaytonaSandbox): Promise<void> {
    await sandbox.start();
  }

  async stop(sandbox: DaytonaSandbox): Promise<void> {
    await sandbox.stop();
  }
}

function daytonaNetworkOptions(
  options: DaytonaCreateOptions,
): NetworkOptions | undefined {
  if (options.networkBlockAll) {
    return {
      mode: "denyAll",
      dnsMode: "denyAll",
    };
  }
  if (options.networkAllowList?.trim()) {
    return {
      allowList: parseDaytonaNetworkAllowList(options.networkAllowList),
      mode: "unrestricted",
      dnsMode: "denyAll",
    };
  }
  return options.network;
}

function rejectUnsupportedDaytonaConfig(options: DaytonaConfig): void {
  const unsupportedFeatures = [];
  if (options.apiKey !== undefined) {
    unsupportedFeatures.push("apiKey");
  }
  if (options.apiUrl !== undefined) {
    unsupportedFeatures.push("apiUrl");
  }
  if (options.jwtToken !== undefined) {
    unsupportedFeatures.push("jwtToken");
  }
  if (options.organizationId !== undefined) {
    unsupportedFeatures.push("organizationId");
  }
  if (options.target !== undefined && options.target !== "local") {
    unsupportedFeatures.push("target");
  }
  throwIfUnsupportedDaytonaOptions("Daytona config", unsupportedFeatures);
}

function rejectUnsupportedDaytonaCreateOptions(
  options: DaytonaCreateOptions,
): void {
  const unsupportedFeatures = [];
  if (options.autoArchiveInterval !== undefined) {
    unsupportedFeatures.push("autoArchiveInterval");
  }
  if (options.autoDeleteInterval !== undefined) {
    unsupportedFeatures.push("autoDeleteInterval");
  }
  if (options.autoStopInterval !== undefined) {
    unsupportedFeatures.push("autoStopInterval");
  }
  if (options.ephemeral !== undefined) {
    unsupportedFeatures.push("ephemeral");
  }
  if (options.labels !== undefined && Object.keys(options.labels).length > 0) {
    unsupportedFeatures.push("labels");
  }
  if (options.name !== undefined) {
    unsupportedFeatures.push("name");
  }
  if (options.public !== undefined) {
    unsupportedFeatures.push("public");
  }
  if (options.resources?.disk !== undefined) {
    unsupportedFeatures.push("resources.disk");
  }
  if (options.snapshot !== undefined) {
    unsupportedFeatures.push("snapshot");
  }
  if (options.target !== undefined && options.target !== "local") {
    unsupportedFeatures.push("target");
  }
  if (options.user !== undefined) {
    unsupportedFeatures.push("user");
  }
  if (options.volumes !== undefined && options.volumes.length > 0) {
    unsupportedFeatures.push("volumes");
  }
  throwIfUnsupportedDaytonaOptions(
    "Daytona create option",
    unsupportedFeatures,
  );
}

function throwIfUnsupportedDaytonaOptions(
  context: string,
  features: string[],
): void {
  if (features.length === 0) {
    return;
  }
  throw new Error(
    `${context} is not supported by Kalahari yet: ${features.join(", ")}.`,
  );
}

function parseDaytonaNetworkAllowList(value: string): string[] {
  const entries = value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (entries.length > 10) {
    throw new Error(
      "Daytona networkAllowList accepts at most 10 CIDR entries.",
    );
  }
  for (const entry of entries) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}\/(?:[0-9]|[12][0-9]|3[0-2])$/.test(entry)) {
      throw new Error(
        `Daytona networkAllowList entry must be IPv4 CIDR: ${entry}`,
      );
    }
  }
  return entries;
}

function imageForLanguage(language: string | undefined): string | undefined {
  if (language === "python") {
    return "python:3.12-alpine";
  }
  if (
    language === "node" ||
    language === "typescript" ||
    language === "javascript"
  ) {
    return "node:22-alpine";
  }
  return undefined;
}

function executeResponse(result: CommandResult): DaytonaExecuteResponse {
  return {
    artifacts: { charts: [], stdout: result.stdout },
    exitCode: result.exitCode,
    result: result.stdout,
    stderr: result.stderr,
    stdout: result.stdout,
  };
}

function parseBranch(output: string): string {
  return output.match(/^##\s+([^\s.]+)/)?.[1] ?? "";
}

function gbToMb(memoryGb: number | undefined): number | undefined {
  return memoryGb === undefined ? undefined : memoryGb * 1024;
}

function findLiteralMatches(file: string, content: string, pattern: string) {
  if (pattern.length === 0) {
    return [];
  }
  return content
    .split(/\r?\n/)
    .flatMap((line, index) =>
      line.includes(pattern) ? [{ content: line, file, line: index + 1 }] : [],
    );
}

function matchesGlob(path: string, pattern: string): boolean {
  const normalized = pattern.includes("/")
    ? path
    : (path.split("/").at(-1) ?? path);
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const source = `^${escaped.replace(/\*/g, ".*").replace(/\?/g, ".")}$`;
  return new RegExp(source).test(normalized);
}
