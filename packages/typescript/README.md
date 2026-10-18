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
noms sign --key-file ./account-key.hex --message "Hello world"
printf %s "$KEY" | noms sign --key-stdin --message "Hello world"
noms verify --account nano_… --signature "$SIGNATURE" --message "Hello world"
noms inspect --message "Hello world"
noms self-test
```

For exact multiline messages, use `--message-stdin`. Verification can read a signature from stdin with `--signature-stdin`. The CLI rejects key files readable by group or other users on POSIX systems. On Windows, restrict the file ACL to your user. Do not pass private keys as command-line arguments. Running a package through `npx` or an equivalent command is a software supply-chain decision.

Use `--key-file` when the message comes from stdin. Hidden key prompting and
`--key-stdin` both reserve stdin for key input and cannot be combined with
`--message-stdin`.

Both CLIs allow only ASCII spaces, tabs, CR, and LF around key input and piped
signatures. Other surrounding Unicode characters are rejected. Message input
is never trimmed, including a leading UTF-8 BOM.

## Input behavior

Messages are encoded as their exact UTF-8 representation. The library does not normalize text, change line endings, or trim whitespace. JavaScript strings with unpaired UTF-16 surrogates are rejected. The reference implementation limits messages to 16 MiB before building the payload.

Malformed key, signature, and account encodings throw `NomsInputError`. Well-formed signatures that do not match return `false`.

Verification follows ORIS-001's strict profile: it rejects noncanonical scalars
and point encodings, identity points, and points outside the prime-order
subgroup. Some signatures accepted by Nano's permissive verifier are therefore
invalid NOMS signatures. Public API signatures and the published deterministic
signing vectors are unchanged.
