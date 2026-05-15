# Contributing

Thanks for your interest in contributing to Kalahari.

## This is a release mirror

This repository is the public release source for the
[@amlalabs/kalahari](https://www.npmjs.com/package/@amlalabs/kalahari) npm
package. Release automation may regenerate package source, the pruned Rust
workspace under `rust/`, and these release docs.

That means:

- Pull requests opened against this repository may conflict with generated
  release output. For nontrivial changes, open an issue first so maintainers
  can coordinate the best path.
- Issues are welcome here. Bug reports, feature requests, packaging problems,
  and platform-support requests for the npm artifact all belong here.
- Code changes are welcome when they are scoped to the npm package, native
  bindings, release workflow, or included Rust sources.

## Reporting issues

Please include the npm package version, your operating system and
architecture, your Node.js version, and a minimal reproducer if possible.

## Development checks

Install dependencies and run the package checks before opening a pull request:

```bash
npm install
npm run build
npm test
```

For release workflow changes, also run `npx actionlint` if it is available in
your environment.

## License

By contributing you agree your contribution will be licensed under
AGPL-3.0-or-later OR BUSL-1.1, matching the rest of the project.
