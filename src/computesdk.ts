import { defineProvider } from "@computesdk/provider";

import {
  emptyCommandResult,
  envEntries,
  mergeEnv,
  unsupported,
} from "./compat.js";
import { KalahariClient, KalahariSandbox } from "./index.js";
import { runDetachedProcess } from "./process.js";

import type { KalahariOptions, CommandResult } from "./types.js";
import type {
  CreateSandboxOptions,
  FileEntry,
  RunCommandOptions,
  SandboxInfo,
} from "@computesdk/provider";

export const kalahari = defineProvider({
  name: "kalahari",
  methods: {
    sandbox: {
      create: async (
        config: KalahariOptions,
        options?: CreateSandboxOptions,
      ) => {
        const client = new KalahariClient(config);
        // `options` comes through ComputeSDK's `[key: string]: any` index
        // signature, so `sandboxId` is typed `any`. Accept only non-empty
        // strings as a reconnect request; empty string is treated as "no id
        // supplied" (same as omitting the field), matching the pre-strict
        // behaviour of `if (options?.sandboxId)`.
        const existingSandboxId = options?.["sandboxId"];
        if (
          typeof existingSandboxId === "string" &&
          existingSandboxId.length > 0
        ) {
          const existing = client.getById(existingSandboxId);
          if (existing) {
            return { sandbox: existing, sandboxId: existing.id };
          }
          throw new Error(
            "kalahari cannot reconnect to sandboxes from another Node process yet.",
          );
        }

        const sandbox = await client.createSandbox({
          ...config,
          timeoutMs: options?.timeout ?? config.timeoutMs,
        });
        if (options?.envs) {
          sandboxCreateEnv.set(sandbox.id, options.envs);
        }
        return { sandbox, sandboxId: sandbox.id };
      },

      getById: async (config: KalahariOptions, sandboxId: string) => {
        const sandbox = new KalahariClient(config).getById(sandboxId);
        return sandbox ? { sandbox, sandboxId } : null;
      },

      list: async (config: KalahariOptions) => {
        return new KalahariClient(config)
          .list()
          .map((sandbox) => ({ sandbox, sandboxId: sandbox.id }));
      },

      destroy: async (config: KalahariOptions, sandboxId: string) => {
        try {
          await new KalahariClient(config).destroy(sandboxId);
        } finally {
          sandboxCreateEnv.delete(sandboxId);
        }
      },

      runCommand: async (
        sandbox: KalahariSandbox,
        command: string,
        options?: RunCommandOptions,
      ): Promise<CommandResult> => {
        assertRunning(sandbox);

        const env = mergeEnv(sandboxCreateEnv.get(sandbox.id), options?.env);
        if (options?.background) {
          if (options.timeout !== undefined) {
            return unsupported("ComputeSDK background command timeout");
          }
          await runDetachedProcess(sandbox, command, {
            cwd: options.cwd,
            env,
            shell: true,
          });
          return emptyCommandResult();
        }

        return runShell(sandbox, command, {
          env: envEntries(env),
          cwd: options?.cwd,
          timeoutMs: options?.timeout,
        });
      },

      getInfo: async (sandbox: KalahariSandbox): Promise<SandboxInfo> => {
        return {
          id: sandbox.id,
          provider: "kalahari",
          status: sandbox.isDestroyed() ? "stopped" : "running",
          createdAt: sandbox.createdAt,
          timeout: 0,
          metadata: {
            image: sandbox.requestedImage,
            manifestDigest: sandbox.image,
            storeDir: sandbox.storeDir,
          },
        };
      },

      getUrl: async () => {
        throw new Error(
          "kalahari does not expose guest ports through ComputeSDK getUrl yet.",
        );
      },

      filesystem: {
        readFile: async (
          sandbox: KalahariSandbox,
          path: string,
        ): Promise<string> => {
          return sandbox.readFile(path);
        },

        writeFile: async (
          sandbox: KalahariSandbox,
          path: string,
          content: string,
        ): Promise<void> => {
          await sandbox.writeFile(path, content);
        },

        mkdir: async (
          sandbox: KalahariSandbox,
          path: string,
        ): Promise<void> => {
          await sandbox.mkdir(path);
        },

        readdir: async (
          sandbox: KalahariSandbox,
          path: string,
        ): Promise<FileEntry[]> => {
          const entries = await sandbox.listFiles(path);
          return Promise.all(
            entries.map(async (entry): Promise<FileEntry> => {
              const details = await sandbox.statFile(entry.path);
              const fileEntry: FileEntry = {
                name: entry.name,
                type: details.type === "dir" ? "directory" : "file",
              };
              if (details.size !== undefined) {
                fileEntry.size = details.size;
              }
              if (details.modTimeMs !== undefined) {
                fileEntry.modified = new Date(details.modTimeMs);
              }
              return fileEntry;
            }),
          );
        },

        exists: async (
          sandbox: KalahariSandbox,
          path: string,
        ): Promise<boolean> => {
          return sandbox.exists(path);
        },

        remove: async (
          sandbox: KalahariSandbox,
          path: string,
        ): Promise<void> => {
          await sandbox.remove(path);
        },
      },

      getInstance: (sandbox: KalahariSandbox): KalahariSandbox => sandbox,
    },
  },
});

const sandboxCreateEnv = new Map<string, Record<string, string>>();

async function runShell(
  sandbox: KalahariSandbox,
  command: string,
  options: {
    env?: string[] | undefined;
    cwd?: string | undefined;
    timeoutMs?: number | undefined;
  } = {},
): Promise<CommandResult> {
  return sandbox.runShell(command, options);
}

function assertRunning(sandbox: KalahariSandbox): void {
  if (sandbox.isDestroyed()) {
    throw new Error(`kalahari sandbox ${sandbox.id} is destroyed.`);
  }
}
