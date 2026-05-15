# Secrets: kalahari mirror release workflow

This document covers GitHub Actions secrets consumed by
[`.github/workflows/release.yml`](./.github/workflows/release.yml) in
`amlalabs/kalahari`.

The workflow builds 3 native napi-rs binaries (Linux x64, Linux arm64, macOS
arm64), packs 4 npm tarballs (1 main + 3 per-arch), publishes them to npm with
provenance, and attaches them to a GitHub Release.

## Overview

| Name           | Type                     | Purpose                                                  |
| -------------- | ------------------------ | -------------------------------------------------------- |
| `NPM_TOKEN`    | npm automation token     | Publish 4 npm packages to the `@amlalabs` scope.         |
| `GITHUB_TOKEN` | Auto-provided by Actions | Create the GitHub Release (`create-release` job).        |
| (no secret)    | OIDC `id-token: write`   | Sign npm provenance attestations against npm's registry. |

## `NPM_TOKEN`

The workflow logs in to <https://registry.npmjs.org> via the standard
`NODE_AUTH_TOKEN` env contract set by `actions/setup-node@v4` when the secret
`NPM_TOKEN` is provided.

### Scope of access

The token must have publish rights to all four packages, all under the
`@amlalabs` org on npm:

- `@amlalabs/kalahari` (main package)
- `@amlalabs/kalahari-linux-x64-gnu`
- `@amlalabs/kalahari-linux-arm64-gnu`
- `@amlalabs/kalahari-darwin-arm64`

It **cannot** publish to any other npm scope or unscoped package, **cannot**
manage org members, and **cannot** rotate other tokens. It is a publishing
credential, nothing more.

### How to create

Prerequisite: be a member of the `amlalabs` npm org with publish rights on the
four packages above (or be granted them via a team membership before issuing
the token).

```bash
# Log in as the publish-account.
npm login

# Create an automation token (CI-friendly; bypasses 2FA on publish).
npm token create --type=automation
```

Copy the printed `npm_*` value and store it in the mirror's Actions secrets:

```bash
gh secret set NPM_TOKEN --repo amlalabs/kalahari
```

Reference docs:
<https://docs.npmjs.com/creating-and-viewing-access-tokens#creating-granular-access-tokens-on-the-website>
<https://docs.npmjs.com/about-access-tokens>

#### Why "automation" specifically

- "Read-only" cannot publish.
- "Publish" requires interactive 2FA at every `npm publish`, which breaks CI.
- "Automation" can publish without 2FA prompts, intended for CI.

If your org has 2FA-on-publish enforced and you don't want to weaken it,
prefer **granular access tokens** scoped to just these 4 packages with the
"Read and write" permission. Same usage, finer blast radius. The
`--type=automation` flag above is the simpler default.

### Rotation

Tokens are read at job-start; rotation is zero-downtime:

1. `npm token create --type=automation` -> new token value.
2. `gh secret set NPM_TOKEN --repo amlalabs/kalahari` -> overwrite in place.
3. Trigger a release (or `workflow_dispatch` re-run an existing tag) and
   confirm publish succeeds.
4. `npm token list` to find the old token's id, then `npm token revoke <id>`.

### Compromise detection

- `npm token list` shows last-used timestamps.
- The npm web UI at <https://www.npmjs.com/settings/~/tokens> shows token age
  and last-used. Unexpected last-used dates between releases indicate misuse.
- Each `npm publish --provenance` writes a signed attestation. If you ever
  see a version of one of these packages on the registry without a
  provenance badge, that publish bypassed CI and should be investigated.

### Failure modes

| Symptom in `publish` job                                                                                                    | Cause                                                                                                                                                                                                                                                                                                   |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm error code ENEEDAUTH`                                                                                                  | Secret missing/empty.                                                                                                                                                                                                                                                                                   |
| `npm error code E401` "Unable to authenticate"                                                                              | Token revoked or expired.                                                                                                                                                                                                                                                                               |
| `npm error code E403` "You do not have permission to publish"                                                               | Token type wrong (e.g. read-only) or no team rights on the scope.                                                                                                                                                                                                                                       |
| `npm error 404 Not Found - PUT https://registry.npmjs.org/@amlalabs%2fkalahari`                                             | Token scoped to wrong account; cannot see the org.                                                                                                                                                                                                                                                      |
| `Verify per-arch siblings are published` step fails after sub-package publish (runs `scripts/check-siblings-published.mjs`) | Not a token issue. See workflow comments; check that all 3 per-arch tarballs uploaded successfully in the previous step. The sibling check runs as an explicit workflow step rather than via `prepublishOnly` because `npm publish <tarball>` skips `prepack`/`prepublishOnly` for pre-packed archives. |

## `GITHUB_TOKEN`

Auto-provided by Actions. Read at `${{ secrets.GITHUB_TOKEN }}` in the
`create-release` job. The job sets `permissions: contents: write` at the job
level (already in the workflow) so the token can create/update releases and
upload assets.

You don't manage this yourself, but the repo must allow it:

- **Settings -> Actions -> General -> Workflow permissions**: choose either
  - "Read and write permissions" (simple, broad), or
  - "Read repository contents and packages permissions" + rely on the
    per-job `permissions:` block (what this workflow uses). Recommended.

If the create-release job fails with `HTTP 403: Resource not accessible by
integration`, the workflow permissions are too restrictive at the repo
default. Open the linked setting and flip it.

## OIDC `id-token: write` (npm provenance)

The `publish` job declares:

```yaml
permissions:
  id-token: write
  contents: read
```

There is no value to set. When `npm publish --provenance` runs, it requests an
OIDC token from the Actions identity provider, signs the provenance statement,
and submits it to npm. npm verifies the signer's `repo:amlalabs/kalahari`
claim against the package's publisher and publishes the attestation.

Repo prerequisite: **Settings -> Actions -> General -> Workflow permissions**
must allow `id-token: write` to be requested at the job level (this is the
default; the only way it's blocked is if an org admin disabled OIDC
explicitly).

Reference docs:
<https://docs.npmjs.com/generating-provenance-statements>
<https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect>

### Failure modes for OIDC

| Symptom                                                                | Cause                                                               |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `npm error code EUSAGE` / `--provenance flag requires id-token: write` | `id-token: write` missing from job permissions.                     |
| `npm error 422 Unprocessable Entity` on publish with `--provenance`    | Workflow not running on a tag from this repo, or org disabled OIDC. |

## Branch protection setup

External release automation pushes new `main` commits and `vX.Y.Z` tags into
`amlalabs/kalahari` on every release. The push may bypass code review by design
because this repository is generated release output.

If branch protection is enabled on `main` (or tag protection on `v*`), the
PAT identity must be allowed to bypass the relevant checks or the
orchestrator push will fail.

Two equivalent ways to make this work:

1. **Recommended for a true release mirror**: leave `main` and `v*` with
   no branch protection. No human ever pushes to this repo directly, so
   protection adds no value, only operational friction.

2. **If branch protection is required by org policy**: in
   **Settings -> Branches -> Branch protection rules -> `main`**, add the
   bot user that owns `MIRROR_PUSH_TOKEN_KALAHARI` to
   **"Allow specified actors to bypass required pull requests"**. If you
   also use **Settings -> Tags -> Tag protection rules** with a `v*`
   pattern, add the same bot user there too.

Symptom of misconfiguration: orchestrator logs show

```
remote: error: GH006: Protected branch update failed for refs/heads/main.
```

or, for tag-protection,

```
remote: error: GH013: Tag protection rule violated for v1.2.3.
```

Fix by adding the PAT identity to the bypass list, or by removing the
protection rule entirely.
