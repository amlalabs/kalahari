export interface PrepareImageOptions {
  /**
   * OCI image reference to prepare, for example "node:22-alpine".
   */
  image: string;
}

export interface PreparedImage {
  image: string;
  source: string;
  storeDir: string;
  manifestDigest: string;
  layers: number;
  alreadyPresent: boolean;
}

/**
 * Options for `KalahariClient` construction and registry-only consumers
 * (e2b/computesdk/harbor shims that just look up sandboxes). All fields are
 * optional; in particular `image` may be set later when calling
 * `client.createSandbox()`.
 *
 * Each optional property accepts `undefined` explicitly so that adapter
 * shims can forward `someOptions.x` (typed `T | undefined`) without having
 * to first strip undefined values; this is the intended ergonomic with
 * `exactOptionalPropertyTypes` enabled.
 */
export interface KalahariClientOptions {
  /**
   * OCI image reference to boot, for example "node:22-alpine" or
   * "python:3.12-alpine".
   */
  image?: string | undefined;
  prepareImage?: boolean | undefined;
  workerPath?: string | undefined;
  memoryMb?: number | undefined;
  vcpus?: number | undefined;
  timeoutMs?: number | undefined;
  outputLimitBytes?: number | undefined;
  requestQueueSize?: number | undefined;
  network?: NetworkOptions | undefined;
}

/**
 * Options for the standalone `createSandbox` / `runCommand` helpers and any
 * call that boots a sandbox without going through a preconfigured client.
 * `image` is required.
 */
export interface CreateSandboxOptions extends KalahariClientOptions {
  image: string;
}

export interface KalahariOptions extends KalahariClientOptions {}

export interface KalahariZygoteSpawnOptions {
  timeoutMs?: number | undefined;
  outputLimitBytes?: number | undefined;
  requestQueueSize?: number | undefined;
  network?: NetworkOptions | undefined;
}

export interface NetworkOptions {
  /**
   * Guest outbound egress policy.
   *
   * - "unrestricted": allow all guest outbound NAT
   * - "publicInternet": allow only globally routable destinations
   * - "denyAll": block outbound guest NAT
   */
  mode?: "unrestricted" | "publicInternet" | "denyAll" | undefined;
  /**
   * Guest-visible DNS server address.
   */
  dns?: string | undefined;
  /**
   * IPv4 CIDR allow list for guest outbound traffic. A `/32` entry allows one
   * address; port `0` wildcard semantics are applied in the VM packet policy.
   */
  allowList?: string[] | undefined;
  /**
   * Host DNS forwarding policy.
   */
  dnsMode?:
    | "unrestricted"
    | "publicInternet"
    | "useEgressPolicy"
    | "denyAll"
    | undefined;
}

export type CommandEnv = Record<string, string | number | boolean> | string[];

export interface RunCommandOptions {
  args?: string[] | undefined;
  stdin?: string | Uint8Array | ArrayBuffer | undefined;
  env?: CommandEnv | undefined;
  cwd?: string | undefined;
  timeoutMs?: number | undefined;
  outputLimitBytes?: number | undefined;
}

export interface RunShellOptions {
  env?: CommandEnv | undefined;
  cwd?: string | undefined;
  timeoutMs?: number | undefined;
  outputLimitBytes?: number | undefined;
}

export interface RunSandboxCommandOptions extends RunCommandOptions {
  command: string;
}

export interface RunOneShotCommandOptions
  extends CreateSandboxOptions, RunSandboxCommandOptions {}

export interface RunNativeCommandOptions {
  command: string;
  args?: string[] | undefined;
  stdinBase64?: string | undefined;
  env?: string[] | undefined;
  cwd?: string | undefined;
  timeoutMs?: number | undefined;
  outputLimitBytes?: number | undefined;
}

export interface CreatePtyOptions {
  command: string;
  args?: string[] | undefined;
  env?: CommandEnv | undefined;
  cwd?: string | undefined;
}

export interface NativeCreatePtyOptions {
  command: string;
  args?: string[] | undefined;
  env?: string[] | undefined;
  cwd?: string | undefined;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
}

export interface KalahariFileInfo {
  name: string;
  path: string;
  type: "file" | "dir";
  size?: number;
  modTimeMs?: number;
}

export interface PtyOutput {
  stdout?: string | undefined;
  stderr?: string | undefined;
  exitCode?: number | undefined;
  exit_code?: number | undefined;
}

export interface NativePtySession {
  readonly id: string;
  readonly sandboxId?: string;
  readonly sandbox_id?: string;
  read(): Promise<PtyOutput | null>;
  write(data: string): Promise<void>;
  writeBytes(data: number[]): Promise<void>;
  resize(rows: number, cols: number): Promise<void>;
  close(): Promise<void>;
}

export interface KalahariSandboxInfo {
  id: string;
  image: string;
  requestedImage: string;
  storeDir?: string;
  createdAt: Date;
  destroyed: boolean;
}

export interface KalahariZygoteInfo {
  id: string;
  image: string;
  requestedImage: string;
  storeDir?: string;
  createdAt: Date;
  destroyed: boolean;
}

export interface NativeCommandResult {
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  exit_code?: number;
  durationMs?: number;
  duration_ms?: number;
}

export interface NativePreparedImage {
  image: string;
  source: string;
  storeDir?: string;
  store_dir?: string;
  manifestDigest?: string;
  manifest_digest?: string;
  layers: number;
  alreadyPresent?: boolean;
  already_present?: boolean;
}

export interface NativeSandbox {
  readonly id: string;
  readonly image: string;
  readonly storeDir?: string;
  readonly store_dir?: string;
  readonly requestedImage?: string;
  readonly requested_image?: string;
  readonly createdAtMs?: number;
  readonly created_at_ms?: number;
  isDestroyed(): boolean;
  runCommand(options: RunNativeCommandOptions): Promise<NativeCommandResult>;
  createPty(options: NativeCreatePtyOptions): Promise<NativePtySession>;
  zygote(): Promise<NativeZygote>;
  destroy(): Promise<void>;
}

export interface NativeZygote {
  readonly id: string;
  readonly image: string;
  readonly storeDir?: string;
  readonly store_dir?: string;
  readonly requestedImage?: string;
  readonly requested_image?: string;
  readonly createdAtMs?: number;
  readonly created_at_ms?: number;
  isDestroyed(): boolean;
  spawn(options: KalahariZygoteSpawnOptions): Promise<NativeSandbox>;
  destroy(): Promise<void>;
}

export interface NativeBinding {
  available(): boolean;
  prepareImage(options: {
    image?: string;
    storeDir?: string;
  }): Promise<NativePreparedImage>;
  createSandbox(options: CreateSandboxOptions): Promise<NativeSandbox>;
}
