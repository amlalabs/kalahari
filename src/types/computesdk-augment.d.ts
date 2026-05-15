/**
 * Module augmentation for the upstream `computesdk` package.
 *
 * Upstream typing gap: the public `Sandbox` interface from `computesdk` (also
 * re-exported as `SandboxInterface`) declares only the universal subset shared
 * across providers: sandboxId, provider, runCommand, getInfo, getUrl, destroy,
 * filesystem. At runtime, however, `compute().sandbox.create()` returns
 * instances of `GeneratedSandbox` from `@computesdk/provider`, which
 * additionally expose `getProvider()` and `getInstance()` (see the
 * `ProviderSandbox` interface in
 * `node_modules/@computesdk/provider/dist/index.d.ts`).
 *
 * We augment via `SandboxInterface` because that is the name `computesdk`
 * actually exports (the internal name is `Sandbox`, but it is only re-exported
 * as `SandboxInterface`, so module augmentation must target the exported
 * alias). The augmentation flows through to every use of the underlying
 * interface, including the `Promise<Sandbox>` return types on
 * `compute().sandbox.create/getById/list`.
 *
 * When `computesdk` upstream tightens its public `Sandbox` type (likely by
 * folding in `ProviderSandbox`'s members), this file can be removed.
 *
 * Note: a compile-time guard that detects when this augmentation silently
 * no-ops (e.g. if upstream switches the export from interface to type alias)
 * lives in `./computesdk-augment-guard.ts`, not here, because the project's
 * `skipLibCheck: true` setting suppresses diagnostics emitted from `.d.ts`
 * files. The guard has to live in a real `.ts` source to fire.
 */
import type { Provider } from "@computesdk/provider";

declare module "computesdk" {
  interface SandboxInterface {
    /** Get the provider that created this sandbox. */
    getProvider(): Provider;
    /** Get the native provider-specific sandbox instance. */
    getInstance(): unknown;
  }
}
