import assert from "node:assert/strict";
import test from "node:test";

const kalahariCore = await import("../dist/index.js");
const { Sandbox: E2BSandbox } = await import("../dist/e2b.js");

assert.equal(
  kalahariCore.available(),
  true,
  "Kalahari native VM must be available",
);

/**
 * Process options accepted by every adapter's `start*` method. Mirrors the
 * subset of `KalahariStartProcessOptions` / `E2BCommandOptions` actually used
 * in these conformance tests.
 *
 * @typedef {{
 *   cols?: number,
 *   rows?: number,
 *   onStdout?: (chunk: string) => void | Promise<void>,
 *   onStderr?: (chunk: string) => void | Promise<void>,
 * }} ProcessStartOptions
 */

/**
 * A handle that exposes the lifecycle subset shared by Kalahari core process
 * handles and E2B command handles.
 *
 * @typedef {{
 *   pid: number,
 *   wait(): Promise<{ stdout: string; stderr: string; exitCode: number; durationMs: number }>,
 *   kill(): Promise<boolean>,
 *   sendStdin(data: string): Promise<void>,
 *   resize?(size: { cols: number; rows?: number }): Promise<void>,
 * }} ProcessHandleLike
 */

/**
 * Sandbox-like adapter under test. Both Kalahari core sandboxes and E2B
 * compatibility sandboxes implement this shape via their own concrete types;
 * we keep the typedef loose to span both.
 *
 * @typedef {object} ConformanceSandbox
 */

/**
 * @typedef {{
 *   name: string,
 *   create: () => Promise<ConformanceSandbox>,
 *   destroy: (sandbox: ConformanceSandbox) => Promise<void>,
 *   kill: (sandbox: ConformanceSandbox, pid: number) => Promise<boolean>,
 *   list: (sandbox: ConformanceSandbox) => Promise<Array<{ pid: number }>> | Array<{ pid: number }>,
 *   start: (sandbox: ConformanceSandbox, command: string, options?: ProcessStartOptions) => Promise<ProcessHandleLike>,
 *   startWithResize: (sandbox: ConformanceSandbox, command: string, options?: ProcessStartOptions) => Promise<ProcessHandleLike>,
 * }} ConformanceAdapter
 */

/** @type {ConformanceAdapter[]} */
const adapters = [
  {
    name: "Kalahari core",
    create: () =>
      new kalahariCore.KalahariClient({
        image: "node:22-alpine",
      }).createSandbox(),
    destroy: (sandbox) =>
      /** @type {import("../dist/index.js").KalahariSandbox} */ (
        sandbox
      ).destroy(),
    kill: (sandbox, pid) =>
      /** @type {import("../dist/index.js").KalahariSandbox} */ (
        sandbox
      ).killProcess(pid),
    list: (sandbox) =>
      /** @type {import("../dist/index.js").KalahariSandbox} */ (
        sandbox
      ).listProcesses(),
    start: (sandbox, command, options = {}) =>
      /** @type {import("../dist/index.js").KalahariSandbox} */ (
        sandbox
      ).startShell(command, options),
    startWithResize: (sandbox, command, options = {}) =>
      /** @type {import("../dist/index.js").KalahariSandbox} */ (
        sandbox
      ).startProcess(command, options),
  },
  {
    name: "E2B compatibility",
    create: () => E2BSandbox.create({ image: "node:22-alpine" }),
    destroy: (sandbox) =>
      /** @type {import("../dist/e2b.js").Sandbox} */ (sandbox).destroy(),
    kill: (sandbox, pid) =>
      /** @type {import("../dist/e2b.js").Sandbox} */ (sandbox).commands.kill(
        pid,
      ),
    list: (sandbox) =>
      /** @type {import("../dist/e2b.js").Sandbox} */ (sandbox).commands.list(),
    start: async (sandbox, command, options = {}) => {
      const result = await /** @type {import("../dist/e2b.js").Sandbox} */ (
        sandbox
      ).commands.run(command, { ...options, background: true });
      return /** @type {ProcessHandleLike} */ (/** @type {unknown} */ (result));
    },
    startWithResize: (sandbox, command, options = {}) =>
      /** @type {import("../dist/e2b.js").Sandbox} */ (sandbox).pty.create({
        cmd: command,
        ...options,
      }),
  },
];

for (const adapter of adapters) {
  test(`${adapter.name} process handles share core lifecycle semantics`, async () => {
    const sandbox = await adapter.create();
    try {
      const handle = await adapter.start(sandbox, "printf repeat");

      const [first, second] = await Promise.all([handle.wait(), handle.wait()]);

      assert.deepEqual(second, first);
      assert.equal(first.stdout, "repeat");
      assert.deepEqual(await adapter.list(sandbox), []);
      await assert.rejects(() => handle.sendStdin("late input"), /not found/);
      const resize = handle.resize;
      if (typeof resize === "function") {
        await assert.rejects(
          () => resize.call(handle, { cols: 80, rows: 24 }),
          /not found/,
        );
      }
      assert.equal(await adapter.kill(sandbox, handle.pid), false);
    } finally {
      await adapter.destroy(sandbox);
    }
  });

  test(`${adapter.name} process callback failures terminate handles`, async () => {
    const sandbox = await adapter.create();
    try {
      const handle = await adapter.start(sandbox, "printf callback", {
        onStdout: () => {
          throw new Error("stdout callback failed");
        },
      });

      await assert.rejects(() => handle.wait(), /stdout callback failed/);
      assert.deepEqual(await adapter.list(sandbox), []);
      assert.equal(await adapter.kill(sandbox, handle.pid), false);
    } finally {
      await adapter.destroy(sandbox);
    }
  });

  test(`${adapter.name} process callbacks are delivered without wait`, async () => {
    const sandbox = await adapter.create();
    try {
      /** @type {string[]} */
      const stdout = [];
      const handle = await adapter.start(sandbox, "cat", {
        onStdout: (chunk) => {
          stdout.push(chunk);
        },
      });

      await handle.sendStdin("streamed\n");
      await waitUntil(() =>
        normalizePtyText(stdout.join("")).includes("streamed\n"),
      );

      assert.equal(
        (await adapter.list(sandbox)).some(
          /** @param {{ pid: number }} process */
          (process) => {
            return process.pid === handle.pid;
          },
        ),
        true,
      );
      assert.equal(await adapter.kill(sandbox, handle.pid), true);
      await assert.rejects(() => handle.wait(), /terminated/);
    } finally {
      await adapter.destroy(sandbox);
    }
  });

  test(`${adapter.name} process duration starts at launch`, async () => {
    const sandbox = await adapter.create();
    try {
      const handle = await adapter.start(
        sandbox,
        "sh -c 'sleep 0.05; printf done'",
      );

      const result = await handle.wait();

      assert.equal(result.stdout, "done");
      assert.equal(result.exitCode, 0);
      assert.ok(
        result.durationMs >= 30,
        `expected duration from launch, got ${result.durationMs}ms`,
      );
    } finally {
      await adapter.destroy(sandbox);
    }
  });

  test(`${adapter.name} process startup cleans up when initial resize fails`, async () => {
    const sandbox = await adapter.create();
    try {
      await assert.rejects(
        () =>
          adapter.startWithResize(sandbox, "cat", {
            cols: 70_000,
            rows: 24,
          }),
        /out of range|too large|invalid|failed/i,
      );
      assert.deepEqual(await adapter.list(sandbox), []);
    } finally {
      await adapter.destroy(sandbox);
    }
  });

  test(`${adapter.name} sandbox destroy cancels in-flight process waits`, async () => {
    const sandbox = await adapter.create();
    const handle = await adapter.start(sandbox, "sleep 60");
    const wait = assert.rejects(
      () => handle.wait(),
      /terminated|stopped|destroyed|cancelled|worker has stopped/i,
    );

    await adapter.destroy(sandbox);

    await wait;
    assert.deepEqual(await adapter.list(sandbox), []);
  });
}

/**
 * @param {() => boolean} predicate
 * @param {number} [timeoutMs]
 */
async function waitUntil(predicate, timeoutMs = 5_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("timed out waiting for condition");
}

/** @param {string} value */
function normalizePtyText(value) {
  return value.replace(/\r\n/g, "\n");
}
