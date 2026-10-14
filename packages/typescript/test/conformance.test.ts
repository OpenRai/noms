import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  accountFromPublicKey,
  encodePayload,
  hashMessage,
  publicKeyFromAccount,
  publicKeyFromPrivateKey,
  signMessage,
  verifyMessage,
} from '../src/index.js';

const vectors = JSON.parse(readFileSync(new URL('../../../conformance/vectors.json', import.meta.url), 'utf8')) as {
  keypair: { private_key: string; public_key: string; account: string };
  vectors: Array<{ name: string; message: string; payload_hex: string; digest: string; signature: string }>;
};
const cases = JSON.parse(readFileSync(new URL('../../../conformance/cases.json', import.meta.url), 'utf8')) as {
  boundary_messages: string[];
};
const hex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

describe('ORIS-001 conformance', () => {
  for (const vector of vectors.vectors) {
    it(`matches ${vector.name}`, () => {
      expect(hex(encodePayload(vector.message))).toBe(vector.payload_hex);
      expect(hex(hashMessage(vector.message))).toBe(vector.digest);
      expect(signMessage(vector.message, vectors.keypair.private_key)).toBe(vector.signature);
      expect(verifyMessage(vector.message, vector.signature, vectors.keypair.account)).toBe(true);
    });
  }

  it('derives and encodes the published account public key', () => {
    const publicKey = publicKeyFromPrivateKey(vectors.keypair.private_key);
    expect(hex(publicKey)).toBe(vectors.keypair.public_key);
    expect(accountFromPublicKey(publicKey)).toBe(vectors.keypair.account);
    expect(hex(publicKeyFromAccount(vectors.keypair.account))).toBe(vectors.keypair.public_key);
  });

  it('preserves exact Unicode, line endings, whitespace, and normalization forms', () => {
    const messages = cases.boundary_messages;
    expect(new Set(messages.map((message) => hex(hashMessage(message)))).size).toBe(messages.length);
  });

  it('rejects malformed keys, signatures, and addresses', () => {
    expect(() => signMessage('x', '00')).toThrow();
    expect(() => verifyMessage('x', '00', vectors.keypair.account)).toThrow();
    expect(() => verifyMessage('x', vectors.vectors[0]!.signature, 'nano_invalid')).toThrow();
    expect(verifyMessage('changed', vectors.vectors[0]!.signature, vectors.keypair.account)).toBe(false);
    const altered = `${vectors.vectors[0]!.signature.slice(0, -1)}${vectors.vectors[0]!.signature.endsWith('0') ? '1' : '0'}`;
    expect(verifyMessage(vectors.vectors[0]!.message, altered, vectors.keypair.account)).toBe(false);
    expect(() => publicKeyFromAccount(`${vectors.keypair.account.slice(0, -1)}1`)).toThrow('checksum');
  });

  it('rejects unpaired UTF-16 surrogates instead of encoding replacement characters', () => {
    expect(() => encodePayload('\ud800')).toThrow('unpaired UTF-16 surrogate');
    expect(() => encodePayload('\udc00')).toThrow('unpaired UTF-16 surrogate');
  });

  it('enforces the documented practical size limit', () => {
    expect(encodePayload('a'.repeat(16 * 1024 * 1024)).length).toBe(16 * 1024 * 1024 + 29);
    expect(() => encodePayload('a'.repeat(16 * 1024 * 1024 + 1))).toThrow('16 MiB');
  });
});
