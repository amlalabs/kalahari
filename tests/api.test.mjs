import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:net";
import { existsSync } from "node:fs";
import {
  mkdtemp,
  readFile as readHostFile,
  rm,
  writeFile as writeHostFile,
} from "node:fs/promises";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const websiteKalahariPage = resolve(
  root,
  "../../apps/website/src/pages/kalahari.astro",
);

const kalahariCore = await import("../dist/index.js");
const { compute } = await import("computesdk");
const computeSdkModule = await import("../dist/computesdk.js");
const { kalahari } = computeSdkModule;
const { Daytona } = await import("../dist/daytona.js");
const { Sandbox: E2BSandbox } = await import("../dist/e2b.js");
const { createHarborEnvironment, harbor } = await import("../dist/harbor.js");
const nativeModule = await import("../dist/native.js");

assert.equal(
  kalahariCore.available(),
  true,
  "Kalahari native VM must be available",
);

test("Kalahari public API does not expose legacy amla-vm aliases", () => {
  assert.equal(Object.hasOwn(kalahariCore, "AmlaVmClient"), false);
  assert.equal(Object.hasOwn(kalahariCore, "AmlaVmSandbox"), false);
  assert.equal(Object.hasOwn(computeSdkModule, "amlaVm"), false);
});

test("Kalahari native loader only targets the current platform shape", () => {
  assert.deepEqual(
    nativeModule.nativeBindingCandidateNames("darwin", "arm64"),
    ["kalahari.darwin-arm64.node", "kalahari.node"],
  );
  assert.deepEqual(nativeModule.nativeBindingCandidateNames("linux", "x64"), [
    "kalahari.linux-x64.node",
    "kalahari.linux-x64-gnu.node",
    "kalahari.node",
  ]);
  assert.equal(
    nativeModule
      .nativeBindingCandidateNames("darwin", "arm64")
      .includes("kalahari.linux-x64-gnu.node"),
    false,
  );
});

test("Kalahari one-shot command helpers wait before sandbox cleanup", async () => {
  const moduleResult = await kalahariCore.runCommand({
    image: "node:22-alpine",
    command: "node",
    args: ["-e", "console.log('module oneshot')"],
  });
  assert.equal(moduleResult.exitCode, 0);
  assert.equal(moduleResult.stdout, "module oneshot\n");

  const clientResult = await new kalahariCore.KalahariClient({
    image: "node:22-alpine",
  }).runCommand({
    image: "node:22-alpine",
    command: "node",
    args: ["-e", "console.log('client oneshot')"],
  });
  assert.equal(clientResult.exitCode, 0);
  assert.equal(clientResult.stdout, "client oneshot\n");
});

test("Kalahari core API runs real commands and filesystem operations", async () => {
  const client = new kalahariCore.KalahariClient({
    image: "node:22-alpine",
    memoryMb: 1024,
    vcpus: 1,
  });
  const sandbox = await client.createSandbox();
  try {
    assert.equal(sandbox.requestedImage, "node:22-alpine");

    await sandbox.mkdir("/tmp/kalahari-api");
    await sandbox.writeFile("/tmp/kalahari-api/message.txt", "hello\n");
    assert.equal(
      await sandbox.readFile("/tmp/kalahari-api/message.txt"),
      "hello\n",
    );

    const result = await sandbox.run("node", {
      args: ["-e", "console.log('hello from kalahari')"],
      cwd: "/tmp/kalahari-api",
    });
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout.trim(), "hello from kalahari");

    await sandbox.writeFileBytes(
      "/tmp/kalahari-api/binary.bin",
      new Uint8Array([0, 255, 65, 128]),
    );
    assert.deepEqual(
      Array.from(await sandbox.readFileBytes("/tmp/kalahari-api/binary.bin")),
      [0, 255, 65, 128],
    );
    assert.equal(await sandbox.exists("/tmp/kalahari-api/message.txt"), true);
    await sandbox.rename(
      "/tmp/kalahari-api/message.txt",
      "/tmp/kalahari-api/renamed.txt",
    );
    assert.equal(await sandbox.exists("/tmp/kalahari-api/message.txt"), false);
    assert.equal(
      await sandbox.readFile("/tmp/kalahari-api/renamed.txt"),
      "hello\n",
    );
    await sandbox.writeFile("/tmp/kalahari-api/no-newline.txt", "no-newline");
    assert.equal(
      await sandbox.readFile("/tmp/kalahari-api/no-newline.txt"),
      "no-newline",
    );
  } finally {
    await sandbox.destroy();
  }
  assert.equal(sandbox.isDestroyed(), true);
});

test("Kalahari zygotes spawn isolated N-way children and consume the parent", async () => {
  const sandbox = await new kalahariCore.KalahariClient({
    image: "node:22-alpine",
  }).createSandbox();

  await sandbox.writeFile("/tmp/zygote-state.txt", "base\n");

  const zygote = await sandbox.zygote();
  assert.equal(sandbox.isDestroyed(), true);
  await assert.rejects(
    () => sandbox.readFile("/tmp/zygote-state.txt"),
    /zygote/,
  );

  const first = await zygote.spawn();
  const second = await zygote.spawn();
  try {
    assert.equal(await first.readFile("/tmp/zygote-state.txt"), "base\n");
    assert.equal(await second.readFile("/tmp/zygote-state.txt"), "base\n");

    await first.writeFile("/tmp/zygote-state.txt", "first child\n");
    assert.equal(
      await first.readFile("/tmp/zygote-state.txt"),
      "first child\n",
    );
    assert.equal(await second.readFile("/tmp/zygote-state.txt"), "base\n");

    const secondGeneration = await first.zygote();
    await assert.rejects(
      () => first.readFile("/tmp/zygote-state.txt"),
      /zygote/,
    );
    const grandchild = await secondGeneration.spawn();
    try {
      assert.equal(
        await grandchild.readFile("/tmp/zygote-state.txt"),
        "first child\n",
      );
    } finally {
      await grandchild.destroy();
      await secondGeneration.destroy();
    }
  } finally {
    await second.destroy();
    await zygote.destroy();
  }
});

test("Kalahari zygote rejects active process handles before freezing", async () => {
  const sandbox = await new kalahariCore.KalahariClient({
    image: "node:22-alpine",
  }).createSandbox();
  try {
    const process = await sandbox.startShell("cat");

    await assert.rejects(() => sandbox.zygote(), /processes are active/);
    assert.equal(sandbox.isDestroyed(), false);

    assert.equal(await process.kill(), true);
    await assert.rejects(() => process.wait(), /terminated/);
  } finally {
    await sandbox.destroy();
  }
});

test("Kalahari zygote rejects after an abandoned foreground command", async () => {
  const sandbox = await new kalahariCore.KalahariClient({
    image: "node:22-alpine",
  }).createSandbox();
  try {
    await assert.rejects(
      () =>
        sandbox.run("node", {
          args: ["-e", "setTimeout(() => {}, 2_000)"],
          timeoutMs: 100,
        }),
      /timed out after 100ms/,
    );

    await assert.rejects(() => sandbox.zygote(), /abandoned|timeout|output/i);
    assert.equal(sandbox.isDestroyed(), false);
  } finally {
    await sandbox.destroy();
  }
});

test("Kalahari core stress handles mixed filesystem, command, and process pressure", async () => {
  const client = new kalahariCore.KalahariClient({
    image: "node:22-alpine",
    memoryMb: 1024,
    requestQueueSize: 128,
    outputLimitBytes: 2 * 1024 * 1024,
    vcpus: 1,
  });
  const sandbox = await client.createSandbox();
  const root = "/tmp/kalahari-stress";

  try {
    await sandbox.mkdir(root);

    const payload = deterministicBytes(64 * 1024);
    const payloadPath = `${root}/payload.bin`;
    await sandbox.writeFileBytes(payloadPath, payload);

    const [roundTrip, guestDigest, payloadStat] = await Promise.all([
      sandbox.readFileBytes(payloadPath),
      guestSha256(sandbox, payloadPath),
      sandbox.statFile(payloadPath),
    ]);
    assert.deepEqual(Array.from(roundTrip), Array.from(payload));
    assert.equal(guestDigest, sha256(payload));
    assert.equal(payloadStat.type, "file");
    assert.equal(payloadStat.size, payload.length);

    const fileIds = Array.from({ length: 16 }, (_, index) => index);
    await Promise.all(
      fileIds.map(async (index) => {
        const path = `${root}/item-${index}.txt`;
        const content = `item=${index}\n${"x".repeat(index * 11)}\n`;
        await sandbox.writeFile(path, content);
        assert.equal(await sandbox.readFile(path), content);
        const stat = await sandbox.statFile(path);
        assert.equal(stat.name, `item-${index}.txt`);
        assert.equal(stat.size, Buffer.byteLength(content));
      }),
    );

    const itemNames = fileIds.map((index) => `item-${index}.txt`).sort();
    assert.deepEqual(
      (await sandbox.readdir(root))
        .filter((name) => name.startsWith("item-"))
        .sort(),
      itemNames,
    );

    await Promise.all(
      fileIds
        .filter((index) => index % 2 === 0)
        .map((index) =>
          sandbox.rename(
            `${root}/item-${index}.txt`,
            `${root}/renamed-${index}.txt`,
          ),
        ),
    );
    await Promise.all(
      fileIds
        .filter((index) => index % 4 === 0)
        .map((index) => sandbox.remove(`${root}/renamed-${index}.txt`)),
    );

    for (const index of fileIds) {
      const expectedExists = index % 2 === 1 || index % 4 !== 0;
      const path =
        index % 2 === 0
          ? `${root}/renamed-${index}.txt`
          : `${root}/item-${index}.txt`;
      assert.equal(await sandbox.exists(path), expectedExists, path);
    }

    const commandResults = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        sandbox.run("node", {
          args: ["-e", commandPressureScript(), String(index)],
          cwd: root,
          env: {
            KALAHARI_BOOL: true,
            KALAHARI_STRESS_INDEX: index,
          },
          stdin: `stdin-${index}`,
        }),
      ),
    );

    for (const [index, result] of commandResults.entries()) {
      assert.equal(result.exitCode, 0);
      assert.equal(result.stderr, "");
      assert.ok(result.durationMs >= 0);
      assert.deepEqual(JSON.parse(result.stdout), {
        argv: String(index),
        bool: "true",
        cwd: root,
        env: String(index),
        stdin: `stdin-${index}`,
      });
    }

    const splitStreams = await sandbox.run("node", {
      args: [
        "-e",
        "process.stdout.write('stdout-split\\n'); process.stderr.write('stderr-split\\n');",
      ],
    });
    assert.equal(splitStreams.exitCode, 0);
    assert.equal(splitStreams.stdout, "stdout-split\n");
    assert.equal(splitStreams.stderr, "stderr-split\n");

    await assert.rejects(
      () =>
        sandbox.run("node", {
          args: ["-e", "setTimeout(() => {}, 2_000)"],
          timeoutMs: 100,
        }),
      /timed out after 100ms/,
    );
    await assert.rejects(
      () =>
        sandbox.run("node", {
          args: ["-e", "process.stdout.write('x'.repeat(8192))"],
          outputLimitBytes: 1024,
        }),
      /output limit|limit exceeded/i,
    );

    /** @type {string[]} */
    const callbackStdout = [];
    /** @type {string[]} */
    const callbackStderr = [];
    const handle = await sandbox.startProcess("node", {
      args: ["-e", processPressureScript()],
      cols: 100,
      onStderr: (chunk) => {
        callbackStderr.push(chunk);
      },
      onStdout: (chunk) => {
        callbackStdout.push(chunk);
      },
      rows: 32,
    });
    assert.equal(sandbox.listProcesses().length, 1);
    const connected = sandbox.connectProcess(handle.pid);
    await connected.resize({ cols: 120, rows: 40 });

    for (const line of ["alpha", "beta", "gamma", "delta"]) {
      await connected.sendStdin(`${line}\n`);
    }

    const processResult = await handle.wait();
    assert.equal(processResult.exitCode, 0);
    assert.deepEqual(sandbox.listProcesses(), []);

    const output = normalizePtyText(
      processResult.stdout + processResult.stderr,
    );
    const callbackOutput = normalizePtyText(
      callbackStdout.join("") + callbackStderr.join(""),
    );
    for (const line of ["alpha", "beta", "gamma", "delta"]) {
      assert.match(output, new RegExp(`stdout:${line}`));
      assert.match(output, new RegExp(`stderr:${line}`));
      assert.match(callbackOutput, new RegExp(`stdout:${line}`));
      assert.match(callbackOutput, new RegExp(`stderr:${line}`));
    }

    await assert.rejects(() => connected.sendStdin("late\n"), /not found/);
    await assert.rejects(
      () => connected.resize({ cols: 80, rows: 24 }),
      /not found/,
    );
  } finally {
    await sandbox.destroy();
  }
});

test("Kalahari zygote stress fans out isolated children and nested generations", async () => {
  const client = new kalahariCore.KalahariClient({
    image: "node:22-alpine",
    memoryMb: 512,
    requestQueueSize: 128,
    vcpus: 1,
  });
  const parent = await client.createSandbox();
  /** @type {import("../dist/index.js").KalahariSandbox[]} */
  const children = [];
  /** @type {import("../dist/index.js").KalahariSandbox[]} */
  const grandchildren = [];
  /** @type {import("../dist/index.js").KalahariSandbox | undefined} */
  let observer;
  /** @type {import("../dist/index.js").KalahariZygote | undefined} */
  let zygote;
  /** @type {import("../dist/index.js").KalahariZygote | undefined} */
  let nestedZygote;

  try {
    const root = "/tmp/zygote-stress";
    const shared = `${root}/shared.txt`;
    const blobPath = `${root}/blob.bin`;
    const blob = deterministicBytes(16 * 1024);
    const blobDigest = sha256(blob);

    await parent.mkdir(root);
    await parent.writeFile(shared, "base\n");
    await parent.writeFileBytes(blobPath, blob);

    zygote = await parent.zygote();
    assert.equal(parent.isDestroyed(), true);
    assert.equal(client.getById(parent.id), null);

    const activeZygote = zygote;
    children.push(
      ...(await Promise.all(
        Array.from({ length: 3 }, () =>
          activeZygote.spawn({ requestQueueSize: 96 }),
        ),
      )),
    );

    await Promise.all(
      children.map(async (child, index) => {
        assert.equal(await child.readFile(shared), "base\n");
        assert.equal(await guestSha256(child, blobPath), blobDigest);
        await child.writeFile(shared, `child-${index}\n`);
        await child.writeFile(
          `${root}/child-${index}.txt`,
          `unique-${index}\n`,
        );
        assert.equal(
          (
            await child.run("node", {
              args: [
                "-e",
                "process.stdout.write(require('node:fs').readFileSync('/tmp/zygote-stress/shared.txt', 'utf8'))",
              ],
            })
          ).stdout,
          `child-${index}\n`,
        );
      }),
    );

    for (const [index, child] of children.entries()) {
      assert.equal(await child.readFile(shared), `child-${index}\n`);
      assert.equal(await child.exists(`${root}/child-${index}.txt`), true);
      for (const other of children.keys()) {
        if (other !== index) {
          assert.equal(await child.exists(`${root}/child-${other}.txt`), false);
        }
      }
    }

    observer = await zygote.spawn({ requestQueueSize: 96 });
    assert.equal(await observer.readFile(shared), "base\n");
    assert.equal(await guestSha256(observer, blobPath), blobDigest);
    for (const index of children.keys()) {
      assert.equal(await observer.exists(`${root}/child-${index}.txt`), false);
    }
    await observer.destroy();
    observer = undefined;

    await Promise.all(children.slice(1).map((child) => child.destroy()));
    const firstChild = children[0];
    assert.ok(firstChild, "expected at least one child sandbox");
    nestedZygote = await firstChild.zygote();
    assert.equal(firstChild.isDestroyed(), true);

    grandchildren.push(
      ...(await Promise.all([
        nestedZygote.spawn({ requestQueueSize: 64 }),
        nestedZygote.spawn({ requestQueueSize: 64 }),
      ])),
    );

    await Promise.all(
      grandchildren.map(async (grandchild, index) => {
        assert.equal(await grandchild.readFile(shared), "child-0\n");
        assert.equal(
          await grandchild.readFile(`${root}/child-0.txt`),
          "unique-0\n",
        );
        await grandchild.writeFile(shared, `grandchild-${index}\n`);
        await grandchild.writeFile(
          `${root}/grandchild-${index}.txt`,
          `nested-${index}\n`,
        );
      }),
    );

    for (const [index, grandchild] of grandchildren.entries()) {
      assert.equal(await grandchild.readFile(shared), `grandchild-${index}\n`);
      assert.equal(
        await grandchild.exists(`${root}/grandchild-${1 - index}.txt`),
        false,
      );
      assert.equal(await guestSha256(grandchild, blobPath), blobDigest);
    }
  } finally {
    await Promise.all(grandchildren.map(destroyIfRunning));
    await destroyIfRunning(nestedZygote);
    await destroyIfRunning(observer);
    await Promise.all(children.map(destroyIfRunning));
    await destroyIfRunning(zygote);
    await destroyIfRunning(parent);
  }
});

test("Kalahari network policies are enforced through the npm API", async () => {
  const host = hostReachableIPv4();
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.end("kalahari-network-ok\n", () => socket.destroy());
  });
  await listen(server);
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("expected AddressInfo from server.address()");
  }
  const port = address.port;

  try {
    await withSandbox(
      {
        network: {
          mode: "unrestricted",
          dnsMode: "denyAll",
          allowList: [`${host}/32`],
        },
      },
      /** @param {import("../dist/index.js").KalahariSandbox} sandbox */
      async (sandbox) => {
        const result = await runNetworkProbe(sandbox, host, port);
        assert.equal(result.exitCode, 0, result.stderr);
        assert.equal(result.stdout.trim(), "kalahari-network-ok");
      },
    );

    await withSandbox(
      {
        network: {
          mode: "unrestricted",
          dnsMode: "denyAll",
          allowList: ["192.0.2.0/24"],
        },
      },
      /** @param {import("../dist/index.js").KalahariSandbox} sandbox */
      async (sandbox) => {
        const result = await runNetworkProbe(sandbox, host, port);
        assert.notEqual(result.exitCode, 0);
        assert.doesNotMatch(result.stdout, /kalahari-network-ok/);
      },
    );

    await withSandbox(
      {
        network: {
          mode: "denyAll",
          dnsMode: "denyAll",
        },
      },
      /** @param {import("../dist/index.js").KalahariSandbox} sandbox */
      async (sandbox) => {
        const result = await runNetworkProbe(sandbox, host, port);
        assert.notEqual(result.exitCode, 0);
        assert.doesNotMatch(result.stdout, /kalahari-network-ok/);
      },
    );
  } finally {
    await closeServer(server, sockets);
  }
});

test("Kalahari Astro page examples execute against the built package", async (t) => {
  if (!existsSync(websiteKalahariPage)) {
    t.skip("skipped: integration test requires website example source");
    return;
  }
  const page = await readHostFile(websiteKalahariPage, "utf8");
  const examples = [
    {
      name: "Quickstart",
      code: extractTemplateConst(page, "quickstartCode"),
    },
    {
      name: "Zygote",
      code: extractTemplateConst(page, "zygoteCode"),
    },
    ...extractShimExamples(page),
  ];

  for (const example of examples) {
    await t.test(example.name, async () => {
      await runExampleModule(example.name, example.code);
    });
  }
});

test("ComputeSDK public compute entrypoint uses the Kalahari provider", async () => {
  const sdk = compute({
    provider: kalahari({ image: "node:22-alpine" }),
  });
  const sandbox = await sdk.sandbox.create({
    envs: { PROJECT: "kalahari-compute" },
  });
  try {
    await sandbox.filesystem.writeFile("/tmp/compute-entrypoint.txt", "ok\n");
    const result = await sandbox.runCommand(
      'printf "$PROJECT:" && cat /tmp/compute-entrypoint.txt',
    );
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, "kalahari-compute:ok\n");
    assert.equal((await sandbox.getInfo()).provider, "kalahari");
  } finally {
    await sandbox.destroy();
  }
});

test("ComputeSDK adapter uses the real Kalahari sandbox", async () => {
  const provider = kalahari({ image: "node:22-alpine" });
  const sandbox = await provider.sandbox.create({
    envs: { PROJECT: "kalahari" },
  });
  try {
    await sandbox.filesystem.writeFile("/tmp/computesdk.txt", "compute\n");
    const result = await sandbox.runCommand("cat /tmp/computesdk.txt");
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, "compute\n");

    const env = await sandbox.runCommand('printf "$PROJECT"');
    assert.equal(env.stdout, "kalahari");

    await assert.rejects(
      () => sandbox.runCommand("sleep 60", { background: true, timeout: 100 }),
      /background command timeout is not supported/,
    );

    assert.equal((await sandbox.getInfo()).provider, "kalahari");
    assert.equal(sandbox.getInstance().id, sandbox.sandboxId);
  } finally {
    await sandbox.destroy();
  }
});

test("ComputeSDK compatibility covers manager lifecycle, filesystem, and background commands", async () => {
  const sdk = compute({
    provider: kalahari({ image: "node:22-alpine" }),
  });
  const sandbox = await sdk.sandbox.create({
    envs: { PROJECT: "kalahari-compute-prod" },
  });
  try {
    assert.equal(sandbox.provider, "kalahari");
    assert.equal(sandbox.getProvider().name, "kalahari");

    const sameSandbox = await sdk.sandbox.getById(sandbox.sandboxId);
    assert.equal(sameSandbox?.sandboxId, sandbox.sandboxId);
    assert.equal(
      (await sdk.sandbox.list()).some(
        (entry) => entry.sandboxId === sandbox.sandboxId,
      ),
      true,
    );

    await sandbox.filesystem.mkdir("/tmp/computesdk-prod");
    await sandbox.filesystem.writeFile(
      "/tmp/computesdk-prod/message.txt",
      "compute fs\n",
    );
    assert.equal(
      await sandbox.filesystem.readFile("/tmp/computesdk-prod/message.txt"),
      "compute fs\n",
    );
    assert.equal(
      await sandbox.filesystem.exists("/tmp/computesdk-prod/message.txt"),
      true,
    );

    const entries = await sandbox.filesystem.readdir("/tmp/computesdk-prod");
    assert.deepEqual(
      entries.map((entry) => ({ name: entry.name, type: entry.type })),
      [{ name: "message.txt", type: "file" }],
    );
    const firstEntry = entries[0];
    assert.ok(firstEntry, "expected readdir to return at least one entry");
    assert.equal(typeof firstEntry.size, "number");
    assert.equal(firstEntry.modified instanceof Date, true);

    const env = await sandbox.runCommand('printf "$PROJECT"');
    assert.equal(env.stdout, "kalahari-compute-prod");

    const detached = await sandbox.runCommand(
      "sleep 0.05; printf background > /tmp/computesdk-prod/background.txt",
      { background: true },
    );
    assert.deepEqual(detached, {
      durationMs: 0,
      exitCode: 0,
      stderr: "",
      stdout: "",
    });
    await waitUntil(async () => {
      try {
        return (
          (await sandbox.filesystem.readFile(
            "/tmp/computesdk-prod/background.txt",
          )) === "background"
        );
      } catch {
        return false;
      }
    });
    assert.equal(
      await sandbox.filesystem.readFile("/tmp/computesdk-prod/background.txt"),
      "background",
    );

    await sandbox.filesystem.remove("/tmp/computesdk-prod/message.txt");
    assert.equal(
      await sandbox.filesystem.exists("/tmp/computesdk-prod/message.txt"),
      false,
    );
    await assert.rejects(
      () => sandbox.getUrl({ port: 3000 }),
      /does not expose guest ports/,
    );

    await sdk.sandbox.destroy(sandbox.sandboxId);
    assert.equal((await sandbox.getInfo()).status, "stopped");
    assert.equal(await sdk.sandbox.getById(sandbox.sandboxId), null);
  } finally {
    await sandbox.destroy().catch(() => undefined);
  }
});

test("E2B compatibility adapter runs on the real Kalahari sandbox", async () => {
  await assert.rejects(
    () => E2BSandbox.create("base", { image: "node:22-alpine" }),
    /template sandbox creation is not supported/,
  );

  const sandbox = await E2BSandbox.create({ image: "node:22-alpine" });
  try {
    assert.equal(await sandbox.isRunning(), true);
    assert.throws(() => sandbox.getHost(3000), /not supported/);
    await assert.rejects(() => sandbox.setTimeout(1_000), /not supported/);
    await assert.rejects(
      () => E2BSandbox.setTimeout(sandbox.id, 1_000),
      /not supported/,
    );
    await assert.rejects(
      () => sandbox.commands.run("whoami", { user: "node" }),
      /E2B command option is not supported/,
    );
    await assert.rejects(
      () =>
        sandbox.commands.run("sleep 60", {
          background: true,
          timeoutMs: 100,
        }),
      /background timeoutMs/,
    );
    await sandbox.files.write("/tmp/e2b.txt", "e2b\n");
    assert.equal(await sandbox.files.read("/tmp/e2b.txt"), "e2b\n");

    const result = await sandbox.commands.run("cat", {
      args: ["/tmp/e2b.txt"],
    });
    if (!("exitCode" in result)) {
      throw new Error("expected CommandResult, got E2BCommandHandle");
    }
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, "e2b\n");

    const pty = await sandbox.pty.create({ cmd: "printf pty-e2b" });
    assert.equal((await pty.wait()).stdout, "pty-e2b");
  } finally {
    await sandbox.destroy();
  }
});

test("E2B compatibility covers lifecycle, file data sources, commands, and PTYs", async () => {
  const sandbox = await E2BSandbox.create({ image: "node:22-alpine" });
  try {
    assert.equal(
      (await E2BSandbox.list()).some((entry) => entry.sandboxId === sandbox.id),
      true,
    );
    const connected = await E2BSandbox.connect(sandbox.id);

    assert.equal(await sandbox.files.makeDir("/tmp/e2b-prod"), true);
    assert.equal(await connected.files.exists("/tmp/e2b-prod"), true);

    await sandbox.files.write("/tmp/e2b-prod/text.txt", "text\n");
    await sandbox.files.write(
      "/tmp/e2b-prod/arraybuffer.bin",
      new Uint8Array([1, 2, 255]).buffer,
    );
    await sandbox.files.write(
      "/tmp/e2b-prod/view.bin",
      new Uint8Array([3, 4, 254]),
    );
    await sandbox.files.write("/tmp/e2b-prod/blob.txt", new Blob(["blob\n"]));
    await sandbox.files.write(
      "/tmp/e2b-prod/stream.txt",
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("stream\n"));
          controller.close();
        },
      }),
    );

    assert.equal(
      await connected.files.read("/tmp/e2b-prod/text.txt"),
      "text\n",
    );
    const viewBytes = await connected.files.read("/tmp/e2b-prod/view.bin", {
      format: "bytes",
    });
    if (typeof viewBytes === "string") {
      throw new Error("expected Uint8Array from bytes-format read");
    }
    assert.deepEqual(Array.from(viewBytes), [3, 4, 254]);
    assert.deepEqual(
      (await sandbox.files.list("/tmp/e2b-prod"))
        .map((entry) => entry.name)
        .sort(),
      ["arraybuffer.bin", "blob.txt", "stream.txt", "text.txt", "view.bin"],
    );

    const renamed = await connected.files.rename(
      "/tmp/e2b-prod/text.txt",
      "/tmp/e2b-prod/renamed.txt",
    );
    assert.deepEqual(renamed, {
      name: "renamed.txt",
      path: "/tmp/e2b-prod/renamed.txt",
      type: "file",
    });
    await sandbox.files.remove("/tmp/e2b-prod/blob.txt");
    assert.equal(await sandbox.files.exists("/tmp/e2b-prod/blob.txt"), false);

    /** @type {string[]} */
    const shellStdout = [];
    /** @type {string[]} */
    const shellStderr = [];
    const shell = await sandbox.commands.exec(
      'printf "$MODE:$PWD"; printf err >&2',
      {
        cwd: "/tmp/e2b-prod",
        envs: { MODE: "shell" },
        onStderr: (chunk) => {
          shellStderr.push(chunk);
        },
        onStdout: (chunk) => {
          shellStdout.push(chunk);
        },
      },
    );
    if (!("exitCode" in shell)) {
      throw new Error("expected CommandResult from shell command");
    }
    assert.equal(shell.exitCode, 0);
    assert.equal(shell.stdout, "shell:/tmp/e2b-prod");
    assert.equal(shell.stderr, "err");
    assert.deepEqual(shellStdout, [shell.stdout]);
    assert.deepEqual(shellStderr, [shell.stderr]);

    const argv = await connected.commands.run("node", {
      args: [
        "-e",
        "process.stdout.write(JSON.stringify({argv:process.argv.at(-1), env:process.env.E2B_ENV, cwd:process.cwd()}))",
        "arg-value",
      ],
      cwd: "/tmp/e2b-prod",
      envs: { E2B_ENV: "from-env" },
    });
    if (!("exitCode" in argv)) {
      throw new Error("expected CommandResult from argv command");
    }
    assert.deepEqual(JSON.parse(argv.stdout), {
      argv: "arg-value",
      cwd: "/tmp/e2b-prod",
      env: "from-env",
    });

    /** @type {string[]} */
    const stdinOutput = [];
    const stdinHandle = await sandbox.commands.run("cat", {
      stdin: true,
      onStdout: (chunk) => {
        stdinOutput.push(chunk);
      },
    });
    if (!("pid" in stdinHandle)) {
      throw new Error("expected E2BCommandHandle from stdin command");
    }
    await connected.commands.sendStdin(stdinHandle.pid, "via command\n");
    const connectedHandle = await connected.commands.connect(stdinHandle.pid);
    await connectedHandle.sendStdin("via handle\n");
    await waitUntil(() =>
      normalizePtyText(stdinOutput.join("")).includes("via handle\n"),
    );
    assert.equal(
      (await sandbox.commands.list()).some(
        (entry) => entry.pid === stdinHandle.pid,
      ),
      true,
    );
    assert.equal(await connectedHandle.kill(), true);
    await assert.rejects(() => stdinHandle.wait(), /terminated/);

    const pty = await sandbox.pty.create({
      cmd: 'read line; printf "pty:$line"',
      cols: 80,
      rows: 24,
    });
    await connected.pty.resize(pty.pid, { cols: 100, rows: 32 });
    await connected.pty.sendInput(pty.pid, new TextEncoder().encode("input\n"));
    assert.match(normalizePtyText((await pty.wait()).stdout), /pty:input$/);

    assert.throws(() => sandbox.uploadUrl(), /not supported/);
    assert.throws(() => sandbox.downloadUrl(), /not supported/);
    await assert.rejects(
      () => sandbox.files.watchDir("/tmp/e2b-prod", () => undefined),
      /not supported/,
    );

    assert.equal(await E2BSandbox.kill(sandbox.id), true);
    assert.equal(await E2BSandbox.kill(sandbox.id), false);
    await assert.rejects(() => E2BSandbox.connect(sandbox.id), /reconnect/);
  } finally {
    await sandbox.destroy().catch(() => undefined);
  }
});

test("Daytona compatibility adapter runs on the real Kalahari sandbox", async () => {
  const daytona = new Daytona({ image: "node:22-alpine", target: "local" });
  assert.throws(
    () => new Daytona({ image: "node:22-alpine", target: "remote" }),
    /Daytona config is not supported/,
  );
  await assert.rejects(
    () => daytona.create({ labels: { project: "kalahari" } }),
    /Daytona create option is not supported/,
  );

  const sandbox = await daytona.create({
    envVars: { NODE_ENV: "test" },
    language: "typescript",
  });
  try {
    await sandbox.fs.uploadFile(
      new TextEncoder().encode("daytona\n"),
      "/tmp/daytona.txt",
    );
    assert.equal(await sandbox.fs.readFile("/tmp/daytona.txt"), "daytona\n");

    const command = await sandbox.process.executeCommand("cat", {
      args: ["/tmp/daytona.txt"],
    });
    assert.equal(command.exitCode, 0);
    assert.equal(command.stdout, "daytona\n");

    const env = await sandbox.process.executeCommand("sh", {
      args: ["-lc", 'printf "$NODE_ENV"'],
    });
    assert.equal(env.stdout, "test");
    assert.equal(sandbox.getWorkDir(), "/workspace");
    assert.equal(
      (
        await sandbox.process.executeCommand("pwd", {
          cwd: sandbox.getWorkDir(),
        })
      ).stdout,
      "/workspace\n",
    );

    assert.equal(sandbox.state, "started");
    await assert.rejects(() => sandbox.stop(), /not supported/);
    await assert.rejects(() => sandbox.archive(), /not supported/);
    await assert.rejects(() => sandbox.refreshActivity(), /not supported/);
    await assert.rejects(() => sandbox.refreshData(), /not supported/);
    await assert.rejects(
      () => sandbox.setLabels({ project: "kalahari" }),
      /not supported/,
    );
    await assert.rejects(
      () => sandbox.setAutoArchiveInterval(60),
      /not supported/,
    );
    await assert.rejects(
      () => sandbox.setAutoDeleteInterval(60),
      /not supported/,
    );
    await assert.rejects(
      () => sandbox.setAutostopInterval(60),
      /not supported/,
    );
    await assert.rejects(
      () => sandbox.process.createSession(),
      /not supported/,
    );
    await assert.rejects(
      () =>
        sandbox.process.executeSessionCommand("session", {
          command: "echo fake-session",
        }),
      /not supported/,
    );
    assert.throws(() => sandbox.getPreviewLink(3000), /not supported/);
    await assert.rejects(
      () => sandbox.getSignedPreviewUrl(3000),
      /not supported/,
    );
  } finally {
    await daytona.delete(sandbox);
  }
});

test("Daytona compatibility covers filesystem helpers, git translations, and lifecycle", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "kalahari-daytona-prod-"));
  /** @type {string[]} */
  const logs = [];
  const daytona = new Daytona({ image: "node:22-alpine", target: "local" });
  const sandbox = await daytona.create(
    {
      envVars: {
        PATH: "/tmp/daytona-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      },
      language: "javascript",
      resources: { cpu: 1, memory: 1 },
    },
    {
      onSnapshotCreateLogs: (chunk) => logs.push(chunk),
      timeout: 10,
    },
  );

  try {
    assert.deepEqual(logs, ["Kalahari uses local OCI image preparation.\n"]);
    assert.equal((await daytona.get(sandbox.id)).id, sandbox.id);
    assert.equal(
      (await daytona.list()).some((entry) => entry.id === sandbox.id),
      true,
    );
    await daytona.start(sandbox);
    await sandbox.waitUntilStarted();
    assert.equal(sandbox.getUserHomeDir(), "/root");
    assert.equal(sandbox.getUserRootDir(), "/");

    await sandbox.fs.createFolder("/tmp/daytona-prod", "755");
    await sandbox.fs.writeFile("/tmp/daytona-prod/a.txt", "alpha beta\nbeta\n");
    await sandbox.fs.uploadFiles([
      {
        source: new TextEncoder().encode("bytes\n"),
        destination: "/tmp/daytona-prod/b.bin",
      },
      {
        source: new TextEncoder().encode("nested\n"),
        destination: "/tmp/daytona-prod/c.txt",
      },
    ]);

    const listed = await sandbox.fs.listFiles("/tmp/daytona-prod");
    assert.deepEqual(
      listed
        .map((entry) => ({ name: entry.name, type: entry.type }))
        .sort((left, right) => left.name.localeCompare(right.name)),
      [
        { name: "a.txt", type: "file" },
        { name: "b.bin", type: "file" },
        { name: "c.txt", type: "file" },
      ],
    );
    assert.equal(
      (await sandbox.fs.getFileDetails("/tmp/daytona-prod/a.txt")).size,
      "alpha beta\nbeta\n".length,
    );
    assert.deepEqual(await sandbox.fs.findFiles("/tmp/daytona-prod", "beta"), [
      { content: "alpha beta", file: "/tmp/daytona-prod/a.txt", line: 1 },
      { content: "beta", file: "/tmp/daytona-prod/a.txt", line: 2 },
    ]);
    assert.deepEqual(
      (await sandbox.fs.searchFiles("/tmp/daytona-prod", "*.txt")).files.sort(),
      ["/tmp/daytona-prod/a.txt", "/tmp/daytona-prod/c.txt"],
    );

    assert.deepEqual(
      await sandbox.fs.replaceInFiles(
        "/tmp/daytona-prod/a.txt",
        "beta",
        "gamma",
      ),
      [
        {
          file: "/tmp/daytona-prod/a.txt",
          replacements: 2,
          success: true,
        },
      ],
    );
    assert.equal(
      await sandbox.fs.readFile("/tmp/daytona-prod/a.txt"),
      "alpha gamma\ngamma\n",
    );
    await assert.rejects(
      () => sandbox.fs.replaceInFiles("/tmp/daytona-prod/a.txt", "", "x"),
      /pattern must not be empty/,
    );

    const bytes = await sandbox.fs.downloadFile("/tmp/daytona-prod/b.bin");
    if (!bytes) {
      throw new Error(
        "expected Uint8Array from downloadFile without destination",
      );
    }
    assert.deepEqual(
      Array.from(bytes),
      Array.from(new TextEncoder().encode("bytes\n")),
    );
    const downloadPath = join(tempDir, "downloaded.txt");
    await sandbox.fs.downloadFile("/tmp/daytona-prod/c.txt", downloadPath);
    assert.equal(await readHostFile(downloadPath, "utf8"), "nested\n");
    const batchDownloads = await sandbox.fs.downloadFiles([
      {
        source: "/tmp/daytona-prod/a.txt",
        destination: join(tempDir, "a.txt"),
      },
      {
        source: "/tmp/daytona-prod/c.txt",
        destination: join(tempDir, "c.txt"),
      },
    ]);
    assert.deepEqual(
      batchDownloads.map(({ success }) => success),
      [true, true],
    );
    assert.equal(
      await streamToString(
        await sandbox.fs.downloadFileStream("/tmp/daytona-prod/c.txt"),
      ),
      "nested\n",
    );

    await sandbox.fs.moveFiles(
      "/tmp/daytona-prod/c.txt",
      "/tmp/daytona-prod/moved.txt",
    );
    assert.equal(await sandbox.exists("/tmp/daytona-prod/c.txt"), false);
    assert.equal(
      await sandbox.fs.readFile("/tmp/daytona-prod/moved.txt"),
      "nested\n",
    );
    await sandbox.fs.deleteFile("/tmp/daytona-prod/moved.txt");
    assert.equal(await sandbox.exists("/tmp/daytona-prod/moved.txt"), false);
    await sandbox.fs.setFilePermissions("/tmp/daytona-prod/a.txt", {
      mode: 0o600,
    });
    assert.equal(
      (
        await sandbox.process.executeCommand("stat", {
          args: ["-c", "%a", "/tmp/daytona-prod/a.txt"],
        })
      ).stdout,
      "600\n",
    );
    await assert.rejects(
      () =>
        sandbox.fs.setFilePermissions("/tmp/daytona-prod/a.txt", {
          owner: "node",
        }),
      /owner\/group/,
    );

    await sandbox.fs.createFolder("/tmp/daytona-bin", "755");
    await sandbox.fs.writeFile(
      "/tmp/daytona-bin/git",
      [
        "#!/bin/sh",
        "printf '%s\\n' \"$@\" >> /tmp/daytona-git-calls.txt",
        "if [ \"$1\" = status ]; then printf '## main\\n M file.txt\\n'; fi",
        "",
      ].join("\n"),
    );
    await sandbox.fs.setFilePermissions("/tmp/daytona-bin/git", {
      mode: "755",
    });
    const status = await sandbox.git.status(sandbox.getWorkDir());
    assert.equal(status.currentBranch, "main");
    assert.match(status.output, /M file\.txt/);
    await sandbox.git.add(sandbox.getWorkDir(), ["file.txt"]);
    await sandbox.git.commit(sandbox.getWorkDir(), "message");
    await sandbox.git.createBranch(sandbox.getWorkDir(), "feature");
    await sandbox.git.switchBranch(sandbox.getWorkDir(), "main");
    await sandbox.git.deleteBranch(sandbox.getWorkDir(), "feature");
    await sandbox.git.pull(sandbox.getWorkDir());
    await sandbox.git.push(sandbox.getWorkDir());
    await sandbox.git.clone("https://example.invalid/repo.git", "/tmp/clone");
    assert.deepEqual(
      (await sandbox.fs.readFile("/tmp/daytona-git-calls.txt"))
        .trim()
        .split("\n"),
      [
        "status",
        "--short",
        "--branch",
        "add",
        "file.txt",
        "commit",
        "-m",
        "message",
        "checkout",
        "-b",
        "feature",
        "checkout",
        "main",
        "branch",
        "-D",
        "feature",
        "pull",
        "push",
        "clone",
        "https://example.invalid/repo.git",
        "/tmp/clone",
      ],
    );

    await sandbox.updateNetworkSettings({});
    await assert.rejects(
      () => sandbox.updateNetworkSettings({ networkAllowList: "127.0.0.1/32" }),
      /networkAllowList/,
    );
    await assert.rejects(
      () => sandbox.updateNetworkSettings({ networkBlockAll: true }),
      /updateNetworkSettings/,
    );
    await assert.rejects(() => sandbox.waitUntilStopped(), /not supported/);
    await assert.rejects(() => sandbox.resize(), /not supported/);
    await assert.rejects(
      () => sandbox.waitForResizeComplete(),
      /not supported/,
    );
    await assert.rejects(() => sandbox.recover(), /not supported/);
    await assert.rejects(() => sandbox.createLspServer(), /not supported/);
    await assert.rejects(() => sandbox.createSshAccess(), /not supported/);
    await assert.rejects(() => sandbox.revokeSshAccess(), /not supported/);
    await assert.rejects(() => sandbox.validateSshAccess(), /not supported/);
    await assert.rejects(
      () => sandbox.expireSignedPreviewUrl(),
      /not supported/,
    );
    await assert.rejects(
      () => sandbox._experimental_createSnapshot(),
      /not supported/,
    );
    await assert.rejects(() => sandbox._experimental_fork(), /not supported/);

    await daytona.remove(sandbox.id);
    assert.equal(sandbox.state, "stopped");
    await sandbox.waitUntilStopped();
    await assert.rejects(() => daytona.get(sandbox.id), /not found/);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
    await sandbox.destroy().catch(() => undefined);
  }
});

test("Harbor compatibility runs real one-shot tasks and lifecycle operations", async () => {
  const environment = harbor({ image: "node:22-alpine", name: "prod" });
  assert.equal(environment.name, "prod");

  const result = await environment.run({
    command: 'printf "$PROJECT:$PWD" > harbor.txt && cat harbor.txt',
    cwd: "/tmp",
    env: { PROJECT: "kalahari-harbor" },
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "kalahari-harbor:/tmp");
  await assert.rejects(
    () => environment.run({ command: "sleep 60", timeoutMs: 100 }),
    /timed out after 100ms/,
  );

  const sandbox = await environment.create();
  try {
    assert.equal(sandbox.isDestroyed(), false);
    await environment.destroy(sandbox.id);
    assert.equal(sandbox.isDestroyed(), true);
  } finally {
    await sandbox.destroy();
  }
});

test("Harbor compatibility rejects mounts instead of faking host volume support", async () => {
  assert.throws(
    () => createHarborEnvironment({ image: "node:22-alpine", nConcurrent: 2 }),
    /Harbor nConcurrent is not supported/,
  );

  const environment = createHarborEnvironment({ image: "node:22-alpine" });
  await assert.rejects(
    () =>
      environment.run({
        command: "true",
        mounts: [{ source: "/host/path", target: "/workspace" }],
      }),
    /Harbor task mounts is not supported/,
  );
});

test("Daytona host file upload and download preserve binary bytes", async () => {
  const sandbox = await new Daytona({
    image: "node:22-alpine",
    target: "local",
  }).create();
  const tempDir = await mkdtemp(join(tmpdir(), "kalahari-daytona-"));
  try {
    const localUpload = join(tempDir, "upload.bin");
    const localDownload = join(tempDir, "download.bin");
    await writeHostFile(localUpload, Buffer.from([1, 2, 3, 254]));
    await sandbox.fs.uploadFile(localUpload, "/tmp/from-host.bin");
    await sandbox.fs.downloadFile("/tmp/from-host.bin", localDownload);
    assert.deepEqual(
      Array.from(await readHostFile(localDownload)),
      [1, 2, 3, 254],
    );
  } finally {
    await rm(tempDir, { recursive: true, force: true });
    await sandbox.delete();
  }
});

test("Kalahari CLI supports help and argument validation", () => {
  const help = runKalahariCli(["--help"]);
  assert.equal(help.status, 0);
  assert.match(help.stdout, /usage: kalahari <command>/);
  assert.equal(help.stderr, "");

  const prepareHelp = runKalahariCli(["prepare", "--help"]);
  assert.equal(prepareHelp.status, 0);
  assert.match(prepareHelp.stdout, /usage: kalahari prepare/);
  assert.equal(prepareHelp.stderr, "");

  const missingImage = runKalahariCli(["prepare", "--image"]);
  assert.equal(missingImage.status, 1);
  assert.match(missingImage.stderr, /--image requires a value/);
});

/** @param {string[]} args */
function runKalahariCli(args) {
  return spawnSync(process.execPath, [resolve(root, "dist/cli.js"), ...args], {
    encoding: "utf8",
    env: process.env,
  });
}

/**
 * @param {string} name
 * @param {string} source
 */
async function runExampleModule(name, source) {
  const tempDir = await mkdtemp(join(root, ".tmp-kalahari-example-"));
  try {
    const modulePath = join(tempDir, `${slug(name)}.mjs`);
    await writeHostFile(modulePath, silenceExampleConsole(source));
    await import(pathToFileURL(modulePath).href);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

/** @param {string} source */
function silenceExampleConsole(source) {
  const lines = source.split("\n");
  let insertIndex = 0;
  while (/^\s*import\s/.test(lines[insertIndex] ?? "")) {
    insertIndex += 1;
  }

  return [
    ...lines.slice(0, insertIndex),
    "const __kalahariExampleLog = console.log;",
    "console.log = () => undefined;",
    "try {",
    ...lines.slice(insertIndex),
    "} finally {",
    "  console.log = __kalahariExampleLog;",
    "}",
  ].join("\n");
}

/**
 * @param {string} source
 * @param {string} name
 */
function extractTemplateConst(source, name) {
  const match = source.match(
    new RegExp(`const\\s+${name}\\s*=\\s*\`([\\s\\S]*?)\`;`),
  );
  const captured = match?.[1];
  if (captured === undefined) {
    throw new Error(`Could not find ${name} in ${websiteKalahariPage}`);
  }
  return captured;
}

/** @param {string} source */
function extractShimExamples(source) {
  const match = source.match(/const\s+shimExamples\s*=\s*\[([\s\S]*?)\];/);
  const body = match?.[1];
  if (body === undefined) {
    throw new Error(`Could not find shimExamples in ${websiteKalahariPage}`);
  }
  /** @type {Array<{ name: string; code: string }>} */
  const examples = [];
  for (const entry of body.matchAll(
    /name:\s*'([^']+)'[\s\S]*?code:\s*`([\s\S]*?)`/g,
  )) {
    const name = entry[1];
    const code = entry[2];
    if (name === undefined || code === undefined) {
      throw new Error(`Invalid shimExamples entry in ${websiteKalahariPage}`);
    }
    examples.push({ name, code });
  }
  return examples;
}

/** @param {string} value */
function slug(value) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

/** @param {number} size */
function deterministicBytes(size) {
  const bytes = new Uint8Array(size);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = (index * 31 + 17) % 256;
  }
  return bytes;
}

/** @param {Uint8Array} bytes */
function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * @param {import("../dist/index.js").KalahariSandbox} sandbox
 * @param {string} path
 */
async function guestSha256(sandbox, path) {
  const result = await sandbox.run("node", {
    args: [
      "-e",
      [
        'const { createHash } = require("node:crypto");',
        'const { readFileSync } = require("node:fs");',
        "process.stdout.write(createHash('sha256')",
        `.update(readFileSync(${JSON.stringify(path)}))`,
        ".digest('hex'));",
      ].join(""),
    ],
  });
  assert.equal(result.exitCode, 0, result.stderr);
  return result.stdout.trim();
}

function commandPressureScript() {
  return [
    "const chunks = [];",
    'process.stdin.on("data", (chunk) => chunks.push(chunk));',
    'process.stdin.on("end", () => {',
    "const value = {",
    "argv: process.argv.at(-1),",
    "bool: process.env.KALAHARI_BOOL,",
    "cwd: process.cwd(),",
    "env: process.env.KALAHARI_STRESS_INDEX,",
    "stdin: Buffer.concat(chunks).toString(),",
    "};",
    "process.stdout.write(JSON.stringify(value));",
    "});",
  ].join("");
}

function processPressureScript() {
  return [
    'const readline = require("node:readline");',
    "const rl = readline.createInterface({ input: process.stdin, terminal: false });",
    "let count = 0;",
    'rl.on("line", (line) => {',
    "count += 1;",
    "console.log(`stdout:${line}`);",
    "console.error(`stderr:${line}`);",
    "if (count === 4) {",
    "rl.close();",
    "setImmediate(() => process.exit(0));",
    "}",
    "});",
  ].join("");
}

/** @param {string} value */
function normalizePtyText(value) {
  return value.replace(/\r\n/g, "\n");
}

/**
 * @param {() => boolean | Promise<boolean>} predicate
 * @param {number} [timeoutMs]
 */
async function waitUntil(predicate, timeoutMs = 5_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("timed out waiting for condition");
}

/** @param {AsyncIterable<string | Uint8Array>} stream */
async function streamToString(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** @param {{ isDestroyed(): boolean; destroy(): Promise<void> } | null | undefined} resource */
async function destroyIfRunning(resource) {
  if (resource && !resource.isDestroyed()) {
    await resource.destroy();
  }
}

/**
 * @param {import("../dist/index.js").KalahariClientOptions} options
 * @param {(sandbox: import("../dist/index.js").KalahariSandbox) => void | Promise<void>} callback
 */
async function withSandbox(options, callback) {
  const sandbox = await new kalahariCore.KalahariClient({
    image: "node:22-alpine",
    ...options,
  }).createSandbox();
  try {
    await callback(sandbox);
  } finally {
    await sandbox.destroy();
  }
}

/**
 * @param {import("../dist/index.js").KalahariSandbox} sandbox
 * @param {string} host
 * @param {number} port
 */
async function runNetworkProbe(sandbox, host, port) {
  // Use busybox `nc` instead of `node` — spinning up node in node:22-alpine
  // takes 10+ seconds in nested-virt environments.
  //
  // Discard one warmup connection first. The first TCP exchange in a fresh
  // sandbox can take 10+ seconds for the inbound SYN-ACK / data to reach
  // the guest under nested KVM (first-packet delivery latency on the guest
  // virtio-net RX path). Subsequent connections in the same sandbox are
  // fast, so a throwaway warmup makes the timed probe deterministic.
  // Whether the warmup succeeds or fails doesn't matter — for negative-case
  // sandboxes the warmup fails (correct) and the probe also fails; for
  // positive cases the warmup succeeds and the probe is fast.
  await sandbox
    .run("sh", {
      args: ["-c", `nc -w 15 ${host} ${port} </dev/null || true`],
      timeoutMs: 30_000,
    })
    .catch(() => {});
  return sandbox.run("sh", {
    args: ["-c", `nc -w 3 ${host} ${port} </dev/null`],
    timeoutMs: 15_000,
  });
}

function hostReachableIPv4() {
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) {
        return entry.address;
      }
    }
  }
  throw new Error("could not find non-loopback host IPv4 address");
}

/** @param {import("node:net").Server} server */
function listen(server) {
  return /** @type {Promise<void>} */ (
    new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "0.0.0.0", () => {
        server.off("error", reject);
        resolve();
      });
    })
  );
}

/**
 * @param {import("node:net").Server} server
 * @param {Set<import("node:net").Socket>} [sockets]
 */
function closeServer(server, sockets = new Set()) {
  for (const socket of sockets) {
    socket.destroy();
  }
  return /** @type {Promise<void>} */ (
    new Promise((resolve, reject) => {
      server.close((/** @type {Error | undefined} */ error) => {
        if (error) reject(error);
        else resolve();
      });
    })
  );
}
