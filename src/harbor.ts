import { KalahariClient, KalahariSandbox } from "./index.js";
import { unsupported } from "./compat.js";

import type { CommandResult, KalahariClientOptions } from "./types.js";

export interface HarborEnvironmentConfig extends KalahariClientOptions {
  name?: string;
  nConcurrent?: number;
}

export interface HarborTaskMount {
  source: string;
  target: string;
}

export interface HarborRunOptions {
  command: string;
  cwd?: string;
  timeoutMs?: number;
  env?: Record<string, string | number | boolean>;
  mounts?: HarborTaskMount[];
}

export interface HarborEnvironment {
  name: string;
  create(): Promise<KalahariSandbox>;
  run(options: HarborRunOptions): Promise<CommandResult>;
  destroy(sandboxId: string): Promise<void>;
}

export function createHarborEnvironment(
  config: HarborEnvironmentConfig = {},
): HarborEnvironment {
  rejectUnsupportedHarborConfig(config);
  const client = new KalahariClient(config);
  const name = config.name ?? "kalahari";

  return {
    name,

    create: () => client.createSandbox(),

    run: async (options) => {
      await rejectMounts(options.mounts ?? []);
      const sandbox = await client.createSandbox();
      try {
        return await sandbox.runShell(options.command, {
          cwd: options.cwd,
          timeoutMs: options.timeoutMs,
          env: options.env,
        });
      } finally {
        await sandbox.destroy();
      }
    },

    destroy: (sandboxId) => client.destroy(sandboxId),
  };
}

export const harbor = createHarborEnvironment;

async function rejectMounts(mounts: HarborTaskMount[]): Promise<void> {
  if (mounts.length > 0) {
    await unsupported("Harbor task mounts");
  }
}

function rejectUnsupportedHarborConfig(config: HarborEnvironmentConfig): void {
  if (config.nConcurrent !== undefined) {
    throw new Error("Harbor nConcurrent is not supported by Kalahari yet.");
  }
}
