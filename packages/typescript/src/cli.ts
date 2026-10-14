#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises';
import { stdin } from 'node:process';
import {
  encodePayload,
  hashMessage,
  signMessage,
  verifyMessage,
} from './index.js';

const TEST_PRIVATE_KEY = '681fd5ed71a9f81e9d29e3450f6cd8aacb87346fd21a26003389290b9d0cb173';
const TEST_ACCOUNT = 'nano_3noms9a1zytox399kygpge6cc7hu1z79ms1cgzojodz8741qi7w5u3nzb8mn';
const TEST_MESSAGE = 'Hej Nano!🥦';
const TEST_SIGNATURE = '535c745819d0f40056f3c46402b4fae4356b3a8897bde99c955d411920e740d781e6dddcbde228e8b86c4383a1003f9f315519ff73bd356f561d19865dc90f09';
const EMPTY_SIGNATURE = '8fca45d1490a276ac9d4376d9251df3a1069f673013c33d49f3490077066f174d7fb6795b966e1d9078952ad065f836b35cd82d402cbeb63f9ace94b2123c506';
const EMPTY_DIGEST = '977a10e19a7857eefad986d73b071bbb7dad60846c7785f6d0ccffe0d7bd40b9';

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
}

function requiredOption(args: string[], name: string): string {
  const index = args.indexOf(name);
  if (index < 0 || !args[index + 1]) throw new Error(`missing ${name}`);
  return args[index + 1]!;
}

async function signingKey(args: string[]): Promise<string> {
  if (args.includes('--key-file')) {
    const path = requiredOption(args, '--key-file');
    const metadata = await stat(path);
    if (process.platform !== 'win32' && (metadata.mode & 0o077) !== 0) {
      throw new Error('key file permissions must exclude group and other access (use chmod 600)');
    }
    return (await readFile(path, 'utf8')).trim();
  }
  if (args.includes('--key-stdin')) return (await readStdin()).trim();
  throw new Error('provide --key-file PATH or --key-stdin; never pass a private key as an argument');
}

function positional(args: string[], valueOptions: string[], flagOptions: string[] = []): string {
  const values = args.filter((value, index) => {
    if (flagOptions.includes(value) || valueOptions.includes(value)) return false;
    if (index > 0 && valueOptions.includes(args[index - 1]!)) return false;
    return true;
  });
  if (values.length === 0) throw new Error('message argument is required');
  return values.join(' ');
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'sign') {
    const key = await signingKey(args);
    const message = positional(args, ['--key-file'], ['--key-stdin']);
    process.stdout.write(`${signMessage(message, key)}\n`);
    return;
  }
  if (command === 'verify') {
    const account = requiredOption(args, '--account');
    const signature = requiredOption(args, '--signature');
    const message = positional(args, ['--account', '--signature']);
    const valid = verifyMessage(message, signature, account);
    process.stdout.write(valid ? 'valid\n' : 'invalid\n');
    if (!valid) process.exitCode = 1;
    return;
  }
  if (command === 'inspect') {
    const message = positional(args, []);
    const payload = encodePayload(message);
    process.stdout.write(`utf8_bytes: ${new TextEncoder().encode(message).length}\npayload: ${hex(payload)}\ndigest: ${hex(hashMessage(message))}\n`);
    return;
  }
  if (command === 'self-test') {
    const ok = signMessage(TEST_MESSAGE, TEST_PRIVATE_KEY) === TEST_SIGNATURE
      && verifyMessage(TEST_MESSAGE, TEST_SIGNATURE, TEST_ACCOUNT)
      && hex(hashMessage('')) === EMPTY_DIGEST
      && signMessage('', TEST_PRIVATE_KEY) === EMPTY_SIGNATURE
      && verifyMessage('', EMPTY_SIGNATURE, TEST_ACCOUNT);
    process.stdout.write(ok ? 'NOMS conformance vectors passed\n' : 'NOMS conformance vectors failed\n');
    if (!ok) process.exitCode = 1;
    return;
  }
  if (command === 'help' || command === '--help' || command === undefined) {
    process.stdout.write('Usage: noms <sign|verify|inspect|self-test> ...\n');
    return;
  }
  throw new Error(`unknown command: ${command}`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
});
