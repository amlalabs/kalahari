/**
 * Compile-time guard for the `computesdk` module augmentation declared in
 * `./computesdk-augment.d.ts`.
 *
 * TypeScript module augmentation merges into exported `interface`
 * declarations but silently no-ops on exported `type` aliases. The upstream
 * `computesdk` package today re-exports its internal `interface Sandbox` as
 * `SandboxInterface`, so the augmentation works; but if a future upstream
 * version flips the public re-export to a true `type` alias (e.g. a union or
 * a mapped type), the `declare module` block in the sibling `.d.ts` would
 * compile cleanly yet contribute nothing to the type surface — leaving
 * `getProvider()` / `getInstance()` callers without typings while the
 * runtime behavior is unaffected.
 *
 * This file lives in `.ts` (not `.d.ts`) on purpose: the project's
 * `tsconfig` sets `skipLibCheck: true`, which suppresses diagnostics emitted
 * from `.d.ts` files. The guard has to be in a checked source for tsc to
 * actually fail.
 *
 * Mechanism: each conditional type below evaluates to `true` when the
 * augmented method is visible on `SandboxInterface`, and to `never` when it
 * is not. `_NotNeverBrand` swaps `never` for a marker string literal, and
 * `_AssertTrue<_T extends true>` rejects any non-`true` argument — so the
 * marker triggers a `TS2344` typecheck error directly here. (A plain
 * `... ? true : never` would not fail on its own, since `never` is
 * assignable to every type, including `true`.)
 *
 * If you see "Type 'ERROR-computesdk-augmentation-noop' does not satisfy
 * the constraint 'true'" pointing at one of the `_Guard*` aliases below,
 * the upstream `computesdk` type surface has changed in a way that defeats
 * the augmentation. Re-read the upstream `Sandbox` declaration and either
 * pick a new augmentation target or delete this file plus the augment .d.ts
 * if the upstream type already includes the methods.
 */
import type { SandboxInterface } from "computesdk";

type _NotNeverBrand<T> = [T] extends [never]
  ? "ERROR-computesdk-augmentation-noop"
  : T;
type _AssertTrue<_T extends true> = true;

type _GuardGetProvider = _AssertTrue<
  _NotNeverBrand<
    SandboxInterface extends { getProvider(): unknown } ? true : never
  >
>;
type _GuardGetInstance = _AssertTrue<
  _NotNeverBrand<
    SandboxInterface extends { getInstance(): unknown } ? true : never
  >
>;

// Reference the guards once so tools that report "unused locals" don't strip
// them. Using `Pick` ensures the alias bodies are evaluated for their
// constraint side-effects without producing any runtime value.
export type ComputeSdkAugmentationGuard = {
  getProvider: _GuardGetProvider;
  getInstance: _GuardGetInstance;
};
