import type { CommandEnv, CommandResult, KalahariFileInfo } from "./types.js";

export interface CommonFileInfo {
  modTime?: string;
  name: string;
  path: string;
  size: number;
  type: "file" | "dir";
}

export function assertOk(result: CommandResult): void {
  if (result.exitCode !== 0) {
    throw new Error(
      result.stderr || `Command failed with exit code ${result.exitCode}`,
    );
  }
}

export async function dataToBytes(
  data: string | ArrayBuffer | ArrayBufferView | Blob | ReadableStream,
): Promise<Uint8Array> {
  if (typeof data === "string") {
    return new TextEncoder().encode(data);
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }
  if (isReadableStream(data)) {
    return readableStreamToBytes(data);
  }
  throw new Error("Unsupported binary data source.");
}

export function envEntries(env: CommandEnv | undefined): string[] | undefined {
  if (!env) {
    return undefined;
  }
  if (Array.isArray(env)) {
    return env;
  }
  return Object.entries(env).map(([key, value]) => `${key}=${value}`);
}

export function envRecord(env: CommandEnv | undefined): Record<string, string> {
  if (!env) {
    return {};
  }
  if (Array.isArray(env)) {
    return Object.fromEntries(
      env.map((entry) => {
        const separator = entry.indexOf("=");
        return separator < 0
          ? [entry, ""]
          : [entry.slice(0, separator), entry.slice(separator + 1)];
      }),
    );
  }
  return Object.fromEntries(
    Object.entries(env).map(([key, value]) => [key, String(value)]),
  );
}

export function mergeEnv(
  defaults: Record<string, string> | undefined,
  env: CommandEnv | undefined,
): CommandEnv | undefined {
  if (!defaults || Object.keys(defaults).length === 0) {
    return env;
  }
  if (!env) {
    return defaults;
  }
  if (Array.isArray(env)) {
    return [
      ...Object.entries(defaults).map(([key, value]) => `${key}=${value}`),
      ...env,
    ];
  }
  return { ...defaults, ...env };
}

export function emptyCommandResult(): CommandResult {
  return {
    durationMs: 0,
    exitCode: 0,
    stderr: "",
    stdout: "",
  };
}

export function fileInfo(details: KalahariFileInfo): CommonFileInfo {
  return {
    modTime: new Date(details.modTimeMs ?? 0).toISOString(),
    name: details.name,
    path: details.path,
    size: details.size ?? 0,
    type: details.type,
  };
}

export function permissionMode(mode: string | number): string {
  if (typeof mode === "number") {
    if (!Number.isInteger(mode) || mode < 0) {
      throw new Error("File permission mode must be a non-negative integer.");
    }
    return mode.toString(8);
  }
  return mode;
}

export function secondsToMs(timeout: number | undefined): number | undefined {
  return timeout === undefined ? undefined : timeout * 1000;
}

export function stripUndefined<T extends Record<string, unknown>>(
  options: T,
): Partial<T> {
  return Object.fromEntries(
    Object.entries(options).filter(([, value]) => value !== undefined),
  ) as Partial<T>;
}

export function unsupported<T>(feature: string): Promise<T> {
  return Promise.reject(unsupportedError(feature));
}

export function unsupportedSync(feature: string): never {
  throw unsupportedError(feature);
}

function unsupportedError(feature: string): Error {
  return new Error(`${feature} is not supported by Kalahari yet.`);
}

function isReadableStream(value: unknown): value is ReadableStream {
  return (
    typeof ReadableStream !== "undefined" && value instanceof ReadableStream
  );
}

async function readableStreamToBytes(
  stream: ReadableStream,
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    const bytes = await dataToBytes(value);
    chunks.push(bytes);
    total += bytes.byteLength;
  }

  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}
