# @openrai/noms

TypeScript library implementation of Nano Off-chain Message Signing (ORIS-001).

```ts
import { signMessage, verifyMessage } from '@openrai/noms';

const signature = signMessage(message, privateKeyHex);
const valid = verifyMessage(message, signature, 'nano_…');
```

`privateKeyHex` is a raw 32-byte Nano account private key, not a wallet seed. Signatures are returned as 128 lowercase hexadecimal characters. Verification accepts lowercase `nano_` and `xrb_` addresses and checks their checksum.

## Input behavior

Messages are encoded as their exact UTF-8 representation. The library does not normalize text, change line endings, or trim whitespace. JavaScript strings with unpaired UTF-16 surrogates are rejected. The reference implementation limits messages to 16 MiB before building the payload.

Malformed key, signature, and account encodings throw `NomsInputError`. Well-formed signatures that do not match return `false`.

Verification follows ORIS-001's strict profile: it rejects noncanonical scalars
and point encodings, identity points, and points outside the prime-order
subgroup. Some signatures accepted by Nano's permissive verifier are therefore
invalid NOMS signatures. Public API signatures and the published deterministic
signing vectors are unchanged.
