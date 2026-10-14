import { blake2b } from '@noble/hashes/blake2b';
import nacl from 'tweetnacl-blake2b';

const HEADER = Uint8Array.from([
  0x18, 0x4e, 0x61, 0x6e, 0x6f, 0x20, 0x4f, 0x66, 0x66, 0x2d, 0x63, 0x68,
  0x61, 0x69, 0x6e, 0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3a,
  0x0a,
]);
const BASE32 = '13456789abcdefghijkmnopqrstuwxyz';
const MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
const encoder = new TextEncoder();

export class NomsInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NomsInputError';
  }
}

function bytesFromHex(value: string, bytes: number, field: string): Uint8Array {
  if (!new RegExp(`^(?:[0-9a-fA-F]{2}){${bytes}}$`).test(value)) {
    throw new NomsInputError(`${field} must be exactly ${bytes * 2} hexadecimal characters`);
  }
  return Uint8Array.from(value.match(/../g)!, (part) => Number.parseInt(part, 16));
}

function encodeInteger(value: Uint8Array, digits: number): string {
  let number = 0n;
  for (const byte of value) number = (number << 8n) | BigInt(byte);
  let output = '';
  for (let i = 0; i < digits; i += 1) {
    output = BASE32[Number(number & 31n)]! + output;
    number >>= 5n;
  }
  if (number !== 0n) throw new NomsInputError('value exceeds Nano base32 width');
  return output;
}

function decodeInteger(value: string, byteLength: number): Uint8Array {
  let number = 0n;
  for (const char of value) {
    const digit = BASE32.indexOf(char);
    if (digit < 0) throw new NomsInputError('account contains invalid Nano base32 characters');
    number = (number << 5n) | BigInt(digit);
  }
  const result = new Uint8Array(byteLength);
  for (let i = byteLength - 1; i >= 0; i -= 1) {
    result[i] = Number(number & 255n);
    number >>= 8n;
  }
  if (number !== 0n) throw new NomsInputError('account value exceeds its encoded width');
  return result;
}

export function encodePayload(message: string): Uint8Array {
  if (typeof message !== 'string') throw new NomsInputError('message must be a string');
  for (let index = 0; index < message.length; index += 1) {
    const unit = message.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = message.charCodeAt(index + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) throw new NomsInputError('message contains an unpaired UTF-16 surrogate');
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new NomsInputError('message contains an unpaired UTF-16 surrogate');
    }
  }
  const encoded = encoder.encode(message);
  if (encoded.length > MAX_MESSAGE_BYTES) throw new NomsInputError('message exceeds the 16 MiB implementation limit');
  const payload = new Uint8Array(HEADER.length + 4 + encoded.length);
  payload.set(HEADER);
  new DataView(payload.buffer).setUint32(HEADER.length, encoded.length, false);
  payload.set(encoded, HEADER.length + 4);
  return payload;
}

export function hashMessage(message: string): Uint8Array {
  return blake2b(encodePayload(message), { dkLen: 32 });
}

export function signMessage(message: string, privateKey: string): string {
  const seed = bytesFromHex(privateKey, 32, 'privateKey');
  const keyPair = nacl.sign.keyPair.fromSeed(seed);
  return Array.from(nacl.sign.detached(hashMessage(message), keyPair.secretKey), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function publicKeyFromPrivateKey(privateKey: string): Uint8Array {
  return nacl.sign.keyPair.fromSeed(bytesFromHex(privateKey, 32, 'privateKey')).publicKey;
}

export function accountFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new NomsInputError('publicKey must be 32 bytes');
  const checksum = blake2b(publicKey, { dkLen: 5 }).reverse();
  return `nano_${encodeInteger(publicKey, 52)}${encodeInteger(checksum, 8)}`;
}

export function publicKeyFromAccount(account: string): Uint8Array {
  const match = /^(nano|xrb)_([13456789abcdefghijkmnopqrstuwxyz]{60})$/.exec(account);
  if (!match) throw new NomsInputError('account must be a valid lowercase nano_ or xrb_ address');
  const encoded = match[2]!;
  const publicKey = decodeInteger(encoded.slice(0, 52), 32);
  const suppliedChecksum = decodeInteger(encoded.slice(52), 5);
  const expectedChecksum = blake2b(publicKey, { dkLen: 5 }).reverse();
  if (suppliedChecksum.some((byte, index) => byte !== expectedChecksum[index])) {
    throw new NomsInputError('account checksum is invalid');
  }
  return publicKey;
}

export function verifyMessage(message: string, signature: string, account: string): boolean {
  const signatureBytes = bytesFromHex(signature, 64, 'signature');
  const publicKey = publicKeyFromAccount(account);
  return nacl.sign.detached.verify(hashMessage(message), signatureBytes, publicKey);
}
