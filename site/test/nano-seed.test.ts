import { describe, expect, it } from 'vitest';
import { accountFromPublicKey, publicKeyFromPrivateKey } from '../../packages/typescript/src/index.ts';
import { nanoPrivateKeyFromSeed } from '../src/nano-seed.js';

describe('Nano seed derivation used by the test page', () => {
  it('matches the Nano documentation example at account index 1', () => {
    const seed = '0000000000000000000000000000000000000000000000000000000000000001';
    const privateKey = nanoPrivateKeyFromSeed(seed, 1);
    expect(privateKey).toBe('1495f2d49159cc2eaaaa97ebb42346418e1268aff16d7fca90e6bad6d0965520');
    expect(accountFromPublicKey(publicKeyFromPrivateKey(privateKey))).toBe('nano_35s8xxbrurpph5zrcb8ey3y1j9niij7k1m645otcxdk3fxg517i6j5empshy');
  });

  it('rejects malformed seeds and indexes outside uint32', () => {
    expect(() => nanoPrivateKeyFromSeed('00', 0)).toThrow('64 hexadecimal');
    expect(() => nanoPrivateKeyFromSeed('00'.repeat(32), -1)).toThrow('32-bit');
    expect(() => nanoPrivateKeyFromSeed('00'.repeat(32), 0x1_0000_0000)).toThrow('32-bit');
  });
});
