# noms CLI

The `noms` binary provides signing, verification, inspection, and offline conformance checks for ORIS-001.

This crate uses the Rust 2024 edition and requires Rust 1.88 or newer.

```sh
cargo run -p noms-cli -- self-test
cargo run -p noms-cli -- inspect --message 'Hello Nano'
```

After the crate is published, install the native binary with `cargo install noms-cli`; it exposes the executable as `noms`.

Signing accepts a raw account private key from a restricted-permission key file, a hidden prompt, or standard input. It never accepts private keys as command-line arguments. Use a zero-balance test key when trying the tool.

```sh
cargo run -p noms-cli -- sign --key-file ./account-key.hex --message 'Hello Nano'
```

For shell pipelines, read the signing key from a file or prompt and send the signature to the verifier:

```sh
npx --yes --package @openrai/noms noms sign --key-file ./account-key.hex --message 'Hello Nano' |
  cargo run -p noms-cli -- verify --account nano_... --message 'Hello Nano' --signature-stdin
```

Messages supplied through `--message-stdin` are read byte-for-byte as UTF-8; a trailing newline is significant.
