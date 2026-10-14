# NOMS reference implementations

This repository contains reference implementations of Nano Off-chain Message Signing (NOMS), specified by [ORIS-001](https://github.com/OpenRai/Standards/blob/main/rfcs/ORIS-001.md).

ORIS-001 is the normative contract. This repository provides executable examples and conformance evidence; it does not add normative protocol rules.

## Packages

- `@openrai/noms`: TypeScript library and `noms` CLI.
- `noms`: Rust library crate.
- `conformance/vectors.json`: canonical vectors copied from ORIS-001 and checked by both implementations.
- The fixture records the exact Standards commit from which its published values were transcribed.

## Development

Use Node.js 24+ and pnpm for the TypeScript package. Rust requires the stable toolchain.

```sh
pnpm install
pnpm test
pnpm build
cargo test --workspace
```

Run the CLI with `pnpm --filter @openrai/noms exec noms self-test`.

## Security

Signing accepts a raw 32-byte Nano account private key, not a wallet seed. The CLI reads keys from a restricted-permission file, stdin, or a hidden prompt; do not put private keys in command arguments. NOMS does not provide replay protection or application consent.
