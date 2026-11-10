# noms-cli

The TypeScript command-line reference implementation for NOMS. It uses
`@openrai/noms` for the protocol implementation and exposes both `noms-cli` and
`noms` commands.

```sh
npx noms-cli self-test
npx noms-cli sign --key-file ./account-key.hex --message "Hello world"
npx noms-cli verify --account nano_… --signature "$SIGNATURE" --message "Hello world"
npx --package noms-cli noms inspect --message "Hello world"
```

The unscoped npm package name `noms` belongs to an unrelated package. The
`noms` executable is available through the `noms-cli` package.

Signing keys are read from a restricted-permission file, a hidden prompt, or
standard input. Never pass private keys as command-line arguments. Use a
zero-balance test account when trying the tool.

For exact multiline messages use `--message-stdin`. Verification can read a
signature from stdin with `--signature-stdin`. Key files must exclude group and
other access on POSIX systems; on Windows, restrict the file ACL to your user.
Running a package through `npx` is a software supply-chain decision.
