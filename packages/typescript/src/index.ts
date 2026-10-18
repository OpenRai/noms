import { blake2b } from '@noble/hashes/blake2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { eddsa } from '@noble/curves/abstract/edwards.js';
import { bytesToNumberLE, concatBytes } from '@noble/curves/utils.js';
import { decodeCanonicalPoint } from './point.js';

const nanoEdDSA = eddsa(ed25519.Point, blake2b, {
  zip215: false,
  adjustScalarBytes(bytes: Uint8Array) {
    bytes[0]! &= 248;
    bytes[31]! &= 127;
    bytes[31]! |= 64;
    return bytes;
  },
});

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
  if (typeof value !== 'string' || value.length !== bytes * 2 || /[^0-9a-fA-F]/.test(value)) {
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
  let byteLength = 0;
  for (let index = 0; index < message.length; index += 1) {
    const unit = message.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = message.charCodeAt(index + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) throw new NomsInputError('message contains an unpaired UTF-16 surrogate');
      index += 1;
      byteLength += 4;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new NomsInputError('message contains an unpaired UTF-16 surrogate');
    } else {
      byteLength += unit < 0x80 ? 1 : unit < 0x800 ? 2 : 3;
    }
    if (byteLength > MAX_MESSAGE_BYTES) throw new NomsInputError('message exceeds the 16 MiB implementation limit');
  }
  const encoded = encoder.encode(message);
  const payload = new Uint8Array(HEADER.length + 4 + encoded.length);
  payload.set(HEADER);
  new DataView(payload.buffer).setUint32(HEADER.length, encoded.length, false);
  payload.set(encoded, HEADER.length + 4);
  return payload;
}

/** Parses an exact ORIS-001 frame and returns its UTF-8 message. */
export function parsePayload(payload: Uint8Array): string {
  if (!(payload instanceof Uint8Array) || payload.length < HEADER.length + 4) {
    throw new NomsInputError('payload is a truncated NOMS frame');
  }
  for (let index = 0; index < HEADER.length; index += 1) {
    if (payload[index] !== HEADER[index]) throw new NomsInputError('payload has an invalid NOMS header');
  }
  const messageLength = new DataView(payload.buffer, payload.byteOffset, payload.byteLength)
    .getUint32(HEADER.length, false);
  if (messageLength > MAX_MESSAGE_BYTES) throw new NomsInputError('message exceeds the 16 MiB implementation limit');
  const messageStart = HEADER.length + 4;
  if (payload.length !== messageStart + messageLength) {
    throw new NomsInputError('payload length does not match the NOMS frame');
  }
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
      .decode(payload.subarray(messageStart));
  } catch {
    throw new NomsInputError('payload message is not valid UTF-8');
  }
}

export function hashMessage(message: string): Uint8Array {
  return blake2b(encodePayload(message), { dkLen: 32 });
}

export function signMessage(message: string, privateKey: string): string {
  const seed = bytesFromHex(privateKey, 32, 'privateKey');
  const signature = nanoEdDSA.sign(hashMessage(message), seed);
  if (ed25519.Point.fromBytes(signature.subarray(0, 32), false).is0()) {
    throw new NomsInputError('derived signing nonce is zero');
  }
  return Array.from(signature, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function publicKeyFromPrivateKey(privateKey: string): Uint8Array {
  return nanoEdDSA.getPublicKey(bytesFromHex(privateKey, 32, 'privateKey'));
}

export function accountFromPublicKey(publicKey: Uint8Array): string {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) throw new NomsInputError('publicKey must be 32 bytes');
  const checksum = blake2b(publicKey, { dkLen: 5 }).reverse();
  return `nano_${encodeInteger(publicKey, 52)}${encodeInteger(checksum, 8)}`;
}

export function publicKeyFromAccount(account: string): Uint8Array {
  if (typeof account !== 'string') throw new NomsInputError('account must be a string');
  const match = /^(nano|xrb)_([13456789abcdefghijkmnopqrstuwxyz]{60})$/.exec(account);
  if (!match || match[0].length !== account.length) throw new NomsInputError('account must be a valid lowercase nano_ or xrb_ address');
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
  const digest = hashMessage(message);
  try {
    const a = decodeCanonicalPoint(publicKey);
    const r = decodeCanonicalPoint(signatureBytes.subarray(0, 32));
    if (a.is0() || r.is0() || !a.isTorsionFree() || !r.isTorsionFree()) return false;
    const order = ed25519.Point.Fn.ORDER;
    const s = bytesToNumberLE(signatureBytes.subarray(32));
    if (s >= order) return false;
    const challenge = bytesToNumberLE(blake2b(concatBytes(signatureBytes.subarray(0, 32), publicKey, digest))) % order;
    return ed25519.Point.BASE.multiplyUnsafe(s % order).equals(r.add(a.multiplyUnsafe(challenge)));
  } catch {
    return false;
  }
}
