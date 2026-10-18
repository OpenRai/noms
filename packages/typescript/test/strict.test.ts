import { describe, expect, it } from 'vitest';
import { decodeCanonicalPoint } from '../src/point.js';
import { encodePayload, publicKeyFromPrivateKey, publicKeyFromAccount, NomsInputError } from '../src/index.js';

describe('strict decoding boundaries', () => {
  it('rejects non-string key/account inputs without coercion', () => {
    for (const value of [null, undefined, 123, {}, [], { toString: () => '0'.repeat(64) }]) {
      expect(() => publicKeyFromPrivateKey(value as string)).toThrow(NomsInputError);
      expect(() => publicKeyFromAccount(value as string)).toThrow(NomsInputError);
    }
  });
  it('rejects a noncanonical identity encoding before subgroup checks', () => {
    const alias = new Uint8Array(32).fill(255);
    alias[0] = 0xee;
    alias[31] = 0x7f;
    expect(() => decodeCanonicalPoint(alias)).toThrow();
  });
  it('rejects an oversized UTF-8 input before invoking the encoder', () => {
    const original = TextEncoder.prototype.encode;
    let invoked = false;
    TextEncoder.prototype.encode = function () { invoked = true; throw new Error('must not allocate'); };
    try { expect(() => encodePayload('🥦'.repeat(4194305))).toThrow('16 MiB'); }
    finally { TextEncoder.prototype.encode = original; }
    expect(invoked).toBe(false);
  });
});
