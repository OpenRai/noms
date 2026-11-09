# noms-cli

The npm command-line entrypoint for the NOMS reference implementation. It
forwards to the CLI shipped by `@openrai/noms` so the protocol implementation
has one source of truth.

```sh
npx noms-cli self-test
npx noms-cli sign --key-file ./account-key.hex --message "Hello world"
npx noms-cli verify --account nano_… --signature "$SIGNATURE" --message "Hello world"
```

The package exposes the `noms-cli` executable. The unscoped npm package name
`noms` belongs to an unrelated package; use `npx noms-cli` or `npx @openrai/noms`.

Signing keys are read from a restricted-permission file, a hidden prompt, or
standard input. Never pass private keys as command-line arguments. Use a
zero-balance test account when trying the tool.
