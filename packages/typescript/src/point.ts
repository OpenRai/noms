import { ed25519 } from '@noble/curves/ed25519.js';

/** Internal canonical decoder; subgroup policy is applied by the verifier. */
export function decodeCanonicalPoint(bytes: Uint8Array) {
  return ed25519.Point.fromBytes(bytes, false);
}
