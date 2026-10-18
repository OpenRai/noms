import { blake2b } from '@noble/hashes/blake2.js';

function bytesFromHex(value: string): Uint8Array {
  if (value.length !== 64 || !/^(?:[0-9a-fA-F]{2}){32}$/.test(value)) {
    throw new Error('Nano seed must be exactly 64 hexadecimal characters');
  }
  return Uint8Array.from(value.match(/../g)!, (pair) => Number.parseInt(pair, 16));
}

/** Derives a Nano account private key from a native seed and uint32 account index. */
export function nanoPrivateKeyFromSeed(seedHex: string, index: number): string {
  if (!Number.isInteger(index) || index < 0 || index > 0xffff_ffff) {
    throw new Error('account index must be an unsigned 32-bit integer');
  }
  const input = new Uint8Array(36);
  input.set(bytesFromHex(seedHex));
  new DataView(input.buffer).setUint32(32, index, false);
  return Array.from(blake2b(input, { dkLen: 32 }), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
