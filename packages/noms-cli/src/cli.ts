#!/usr/bin/env node
import { open } from 'node:fs/promises';
import { stdin, stdout, stderr } from 'node:process';
import { emitKeypressEvents } from 'node:readline';
import {
  encodePayload,
  hashMessage,
  signMessage,
  verifyMessage,
} from '@openrai/noms';

import { TEST_PRIVATE_KEY, TEST_ACCOUNT, TEST_MESSAGE, TEST_SIGNATURE, EMPTY_SIGNATURE, EMPTY_DIGEST, NONCANONICAL_SIGNATURE } from './self-test-vectors.js';

function trimEnvelope(value: string): string {
  return value.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function optionValue(args: string[], name: string): string | undefined {
  const indexes: number[] = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === name) indexes.push(index);
    if (['--account', '--key-file', '--message', '--signature'].includes(args[index]!)) index += 1;
  }
  if (indexes.length > 1) throw new Error(`${name} may be provided only once`);
  if (indexes.length === 0) return undefined;
  const value = args[indexes[0]! + 1];
  if (value === undefined) throw new Error(`missing value for ${name}`);
  return value;
}

function selectOptions(args: string[], names: string[]): string[] {
  const selected: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const name = args[index]!;
    const takesValue = ['--account', '--key-file', '--message', '--signature'].includes(name);
    if (names.includes(name)) selected.push(...args.slice(index, index + (takesValue ? 2 : 1)));
    if (takesValue) index += 1;
  }
  return selected;
}

function hasFlag(args: string[], name: string): boolean {
  const valueOptions = new Set(['--account', '--key-file', '--message', '--signature']);
  for (let index = 0; index < args.length; index += 1) {
    if (valueOptions.has(args[index]!)) {
      index += 1;
      continue;
    }
    if (args[index] === name) return true;
  }
  return false;
}

function rejectUnknown(args: string[], valueOptions: string[], flagOptions: string[]): void {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (valueOptions.includes(arg)) {
      index += 1;
      continue;
    }
    if (flagOptions.includes(arg)) continue;
    throw new Error(`unexpected argument: ${arg}`);
  }
}

async function readBounded(source: AsyncIterable<Uint8Array>, limit: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of source) {
    length += chunk.length;
    if (length > limit) throw new Error('input exceeds the implementation size limit');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function readStdinText(label: string): Promise<string> {
  const bytes = await readBounded(stdin, label === 'message' ? 16 * 1024 * 1024 : 4096);
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Error(`${label} input must be valid UTF-8`);
  }
}

function promptHiddenKey(): Promise<string> {
  if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
    throw new Error('--prompt-key requires an interactive terminal');
  }
  emitKeypressEvents(stdin);
  stdin.setRawMode(true);
  stdin.resume();
  stderr.write('Nano account private key (hex): ');

  return new Promise((resolve, reject) => {
    let value = '';
    const finish = (error?: Error) => {
      stdin.off('keypress', onKeypress);
      stdin.setRawMode(false);
      stdin.pause();
      stderr.write('\n');
      if (error) reject(error);
      else resolve(value);
    };
    const onKeypress = (character: string, key: { name?: string; ctrl?: boolean } = {}) => {
      if (key.ctrl && key.name === 'c') {
        finish(new Error('key prompt cancelled'));
      } else if (key.name === 'return' || key.name === 'enter') {
        finish();
      } else if (key.name === 'backspace') {
        value = value.slice(0, -1);
      } else if (character && !key.ctrl) {
        value += character;
      }
    };
    stdin.on('keypress', onKeypress);
  });
}

async function readKey(args: string[]): Promise<string> {
  rejectUnknown(args, ['--key-file'], ['--key-stdin', '--prompt-key', '--message', '--message-stdin']);
  const keyFile = optionValue(args, '--key-file');
  const keyStdin = hasFlag(args, '--key-stdin');
  const promptKey = hasFlag(args, '--prompt-key');
  if (Number(keyFile !== undefined) + Number(keyStdin) + Number(promptKey) !== 1) {
    throw new Error('provide exactly one of --key-file PATH, --key-stdin, or --prompt-key; never pass a private key as an argument');
  }
  if (keyFile !== undefined) {
    const handle = await open(keyFile, 'r');
    try {
      const metadata = await handle.stat();
      if (metadata.size > 4096) throw new Error('key file exceeds the implementation size limit');
      if (process.platform !== 'win32' && (metadata.mode & 0o077) !== 0) {
        throw new Error('key file permissions must exclude group and other access (use chmod 600)');
      }
      return trimEnvelope((await readBounded(handle.createReadStream({ autoClose: false }), 4096)).toString('utf8'));
    } finally {
      await handle.close();
    }
  }
  return trimEnvelope(keyStdin ? await readStdinText('key') : await promptHiddenKey());
}

async function readMessage(args: string[]): Promise<string> {
  rejectUnknown(args, ['--message'], ['--message-stdin']);
  const message = optionValue(args, '--message');
  const messageStdin = hasFlag(args, '--message-stdin');
  if (Number(message !== undefined) + Number(messageStdin) !== 1) {
    throw new Error('provide exactly one of --message TEXT or --message-stdin');
  }
  return messageStdin ? readStdinText('message') : message!;
}

async function signingKeyAndMessage(args: string[]): Promise<{ key: string; message: string }> {
  if ((hasFlag(args, '--key-stdin') || hasFlag(args, '--prompt-key')) && hasFlag(args, '--message-stdin')) {
    throw new Error('standard input cannot supply both key and message; use --key-file with --message-stdin');
  }
  rejectUnknown(args, ['--key-file', '--message'], ['--key-stdin', '--prompt-key', '--message-stdin']);
  const keyArgs = selectOptions(args, ['--key-file', '--key-stdin', '--prompt-key']);
  const messageArgs = selectOptions(args, ['--message', '--message-stdin']);
  const key = await readKey(keyArgs);
  const message = await readMessage(messageArgs);
  return { key, message };
}

const HELP: Record<string, string> = {
  help: `Usage: noms <command> [options]

Commands:
  sign       Sign an exact message with a Nano account private key
  verify     Verify a signature against an exact message and Nano account
  inspect    Show the ORIS-001 payload bytes and digest
  self-test  Check the built-in NOMS conformance vectors

Run "noms <command> --help" for command-specific options and examples.`,
  sign: `Usage: noms sign (--key-file PATH | --key-stdin | --prompt-key) (--message TEXT | --message-stdin)

Sign an exact message with a raw 32-byte Nano account private key. A wallet
seed is not an account private key. The key is never accepted as an argument.

Examples:
  noms sign --key-file ./account-key.hex --message "Hello, Nano!"
  noms sign --prompt-key --message "Hello, Nano!"
  printf %s "Hello, Nano!" | noms sign --key-file ./account-key.hex --message-stdin
  cat ./account-key.hex | noms sign --key-stdin --message "Hello, Nano!"

On macOS and Linux, restrict a key file with: chmod 600 ./account-key.hex
The signature is written to stdout as 128 lowercase hexadecimal characters.`,
  verify: `Usage: noms verify --account NANO_ADDRESS (--signature HEX | --signature-stdin) (--message TEXT | --message-stdin)

Verify a NOMS signature for the exact message and Nano account. Prints "valid"
or "invalid"; exits with status 0 for valid, 1 for invalid, and 2 for errors.

Examples:
  noms verify --account nano_... --signature "$SIGNATURE" --message "Hello, Nano!"
  printf %s "Hello, Nano!" | noms verify --account nano_... --signature "$SIGNATURE" --message-stdin
  printf %s "$SIGNATURE" | noms verify --account nano_... --signature-stdin --message "Hello, Nano!"

The message is not trimmed, normalized, or otherwise changed.`,
  inspect: `Usage: noms inspect (--message TEXT | --message-stdin)

Display the exact UTF-8 byte length, ORIS-001 payload, and BLAKE2b-256 digest.

Examples:
  noms inspect --message "Hello, Nano!"
  printf %s "Hello, Nano!" | noms inspect --message-stdin`,
  'self-test': `Usage: noms self-test

Run the built-in known-answer and canonical-signature checks. This needs no
network connection or Nano node.

Example:
  noms self-test`,
};

function showHelp(topic?: string): boolean {
  const help = HELP[topic ?? 'help'];
  if (!help) return false;
  stdout.write(`${help}\n`);
  return true;
}

async function run(command: string | undefined, args: string[]): Promise<boolean> {
  if (command === 'sign') {
    const { key, message } = await signingKeyAndMessage(args);
    stdout.write(`${signMessage(message, key)}\n`);
    return true;
  }
  if (command === 'verify') {
    rejectUnknown(args, ['--account', '--signature', '--message'], ['--signature-stdin', '--message-stdin']);
    const account = optionValue(args, '--account');
    if (!account) throw new Error('missing --account');
    const signature = optionValue(args, '--signature');
    const signatureStdin = hasFlag(args, '--signature-stdin');
    if (Number(signature !== undefined) + Number(signatureStdin) !== 1) {
      throw new Error('provide exactly one of --signature HEX or --signature-stdin');
    }
    if (signatureStdin && hasFlag(args, '--message-stdin')) {
      throw new Error('standard input cannot supply both signature and message; use --message TEXT');
    }
    const message = await readMessage(selectOptions(args, ['--message', '--message-stdin']));
    const signatureText = signatureStdin ? trimEnvelope(await readStdinText('signature')) : signature!;
    const valid = verifyMessage(message, signatureText, account);
    stdout.write(valid ? 'valid\n' : 'invalid\n');
    return valid;
  }
  if (command === 'inspect') {
    const message = await readMessage(args);
    const payload = encodePayload(message);
    stdout.write(`utf8_bytes: ${new TextEncoder().encode(message).length}\npayload: ${hex(payload)}\ndigest: ${hex(hashMessage(message))}\n`);
    return true;
  }
  if (command === 'self-test') {
    rejectUnknown(args, [], []);
    const ok = signMessage(TEST_MESSAGE, TEST_PRIVATE_KEY) === TEST_SIGNATURE
      && verifyMessage(TEST_MESSAGE, TEST_SIGNATURE, TEST_ACCOUNT)
      && hex(hashMessage('')) === EMPTY_DIGEST
      && signMessage('', TEST_PRIVATE_KEY) === EMPTY_SIGNATURE
      && verifyMessage('', EMPTY_SIGNATURE, TEST_ACCOUNT);
    const strictOk = ok && !verifyMessage(TEST_MESSAGE, NONCANONICAL_SIGNATURE, TEST_ACCOUNT);
    stdout.write(strictOk ? 'NOMS conformance vectors passed\n' : 'NOMS conformance vectors failed\n');
    return strictOk;
  }
  throw new Error(`unknown command: ${command}`);
}

const [command, ...args] = process.argv.slice(2);
if (command === undefined || command === '--help' || command === '-h') {
  showHelp();
} else if (command === 'help') {
  if (!showHelp(args[0])) {
    stderr.write(`unknown help topic: ${args[0]}\n`);
    process.exitCode = 2;
  }
} else if (args.includes('--help') || args.includes('-h')) {
  if (!showHelp(command)) {
    stderr.write(`unknown command: ${command}\n`);
    process.exitCode = 2;
  }
} else {
  run(command, args).then((success) => {
    if (!success) process.exitCode = 1;
  }).catch((error: unknown) => {
    stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  });
}
