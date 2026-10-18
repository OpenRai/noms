# NOMS reference implementations

This repository contains reference implementations of Nano Off-chain Message Signing (NOMS), specified by [ORIS-001](https://github.com/OpenRai/Standards/blob/main/rfcs/ORIS-001.md).

ORIS-001 is the normative contract. This repository provides executable examples and conformance evidence; it does not add normative protocol rules.

## Packages and tools

- `@openrai/noms`: TypeScript library and `noms` CLI.
- `noms`: Rust library crate.
- `noms-cli`: native Rust `noms` executable.
- `site/`: browser-only signing and verification playground, published with GitHub Pages.
- `conformance/suite.json`: hash-pinned copy of the canonical Standards corpus, including known answers and adversarial verification cases. `vectors.json` and CLI self-test constants are generated views of that corpus.

The libraries implement ORIS-001 only. They do not derive wallet keys, manage sessions, provide wallet transport, or implement SIWN. The playground includes a small Nano seed derivation helper for demonstration; it is not exported by the NOMS library.

## Development

Use Node.js 24+ and the pinned pnpm version for development. The npm library supports Node.js 20.19+. Rust requires the stable toolchain; security checks also require Python 3, a C compiler, and `tar`.

```sh
pnpm install
pnpm exec playwright install chromium firefox webkit
pnpm conformance
```

Run the TypeScript CLI with `pnpm --filter @openrai/noms exec noms self-test`.
Run the Rust CLI with `cargo run -p noms-cli -- self-test`.
Run `pnpm run noms-site` to rebuild and preview the playground at `http://127.0.0.1:4173/noms/`.

### Reproduce CI and release artifacts locally

`pnpm conformance` builds and tests the libraries, CLIs, installed npm/Cargo
artifacts, production browser bundle in three engines, independent Nano C
oracle, and targeted security mutations. The oracle downloads its pinned source
on first use, verifies Git blob hashes, and caches it under `artifacts/`.
`pnpm conformance:core` runs the offline library/CLI checks without browsers or
artifact installation. On Linux, install browser system dependencies with
`pnpm exec playwright install --with-deps chromium firefox webkit`.

Run the release/nightly campaign locally:

```sh
pnpm conformance:extended
```

The extended campaign adds 10,000 generated key/message cases, 10,000 targeted
mutations, and 120-second parser/verification fuzz campaigns in each language.
`NOMS_TEST_SEED` selects a reproducible seed; `NOMS_FUZZ_SECONDS` changes the fuzz
duration for diagnosis. Reports, executed case IDs, seeds, and failure inputs
are written to `artifacts/conformance/`.

The TypeScript build is in `packages/typescript/dist/`, the production site is
in `site-dist/`, and Cargo package archives are in `target/package/`. Artifact
checks install npm tarballs and Cargo archives into temporary consumer projects
and remove those projects afterward. Local Cargo packaging permits uncommitted
changes; CI validates the exact checkout. Publishing is a separate workflow.

### Updating the protocol corpus

Edit ORIS-001 and its independent Python model in the adjacent Standards
repository. Run `make noms-vectors` there, then synchronize from this repository:

```sh
node scripts/check-fixtures.mjs --sync --source ../Standards
```

This regenerates the vendored suite, packaged Rust test data, compatibility
vectors, and both CLIs' self-tests. The manifest records content hashes and
marks uncommitted Standards work explicitly. After committing Standards, repeat
the synchronization to pin that commit. Releases verify the pinned files
against GitHub and fail if the source is uncommitted or its hashes differ.

ORIS-001 defines strict verification: noncanonical scalars/points, identity
points, and points outside the prime-order subgroup are invalid. This is
intentionally stricter than Nano V28.2's verifier. The original deterministic
signatures remain unchanged. CI reports deliberate Nano acceptance differences
separately from unexplained interoperability failures.

After publishing, use `npx --yes --package @openrai/noms noms self-test` or install the native Rust binary with `cargo install noms-cli` and run `noms self-test`.

Both CLIs accept explicit `--message TEXT` or exact UTF-8 `--message-stdin` input. Signing keys come from a permission-restricted file, a hidden prompt, or stdin; keys are never accepted as command-line arguments. `--signature-stdin` lets a verifier consume a piped signature.

See [publishing setup](docs/publishing.md) for registry names, release tags, and OIDC trusted-publisher configuration.

## Security

Signing accepts a raw 32-byte Nano account private key, not a wallet seed. Do not paste a funded wallet seed into the hosted playground. NOMS does not provide replay protection or application consent.
