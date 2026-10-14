# @openrai/noms

TypeScript reference implementation of Nano Off-chain Message Signing (ORIS-001). The package exports a library API and a `noms` executable.

```ts
import { signMessage, verifyMessage } from '@openrai/noms';

const signature = signMessage(message, privateKeyHex);
const valid = verifyMessage(message, signature, 'nano_…');
```

`privateKeyHex` is a raw 32-byte Nano account private key, not a wallet seed. Signatures are returned as 128 lowercase hexadecimal characters. Verification accepts lowercase `nano_` and `xrb_` addresses and checks their checksum.

## CLI

```sh
noms sign --key-file ./account-key.hex "Hello world"
printf %s "$KEY" | noms sign --key-stdin "Hello world"
noms verify --account nano_… --signature "$SIGNATURE" "Hello world"
noms inspect "Hello world"
noms self-test
```

The CLI rejects key files readable by group or other users on POSIX systems. Do not pass private keys as command-line arguments. Running a package through `npx` or an equivalent command is a software supply-chain decision.

## Input behavior

Messages are encoded as their exact UTF-8 representation. The library does not normalize text, change line endings, or trim whitespace. JavaScript strings with unpaired UTF-16 surrogates are rejected. The reference implementation limits messages to 16 MiB before building the payload.

Malformed key, signature, and account encodings throw `NomsInputError`. Well-formed signatures that do not match return `false`.
