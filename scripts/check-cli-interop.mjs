import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { validateSuite } from './lib/conformance.mjs';

const suite = validateSuite(JSON.parse(readFileSync('conformance/suite.json')));
const tools = [
  { name: 'javascript', command: process.execPath, args: [process.env.NOMS_JS_CLI ?? 'packages/typescript/dist/cli.js'] },
  { name: 'rust', command: process.env.NOMS_RUST_CLI ?? `target/debug/noms${process.platform === 'win32' ? '.exe' : ''}`, args: [] },
];
function run(tool, args, input) {
  const result = spawnSync(tool.command, [...tool.args, ...args], { input, maxBuffer: 128 * 1024 * 1024, timeout: 30000 });
  if (result.error && !(result.error.code === 'EPIPE' && result.status === 2)) throw result.error;
  return { status: result.status, stdout: result.stdout?.toString('utf8') ?? '', stderr: result.stderr?.toString('utf8') ?? '' };
}
const directory = mkdtempSync(join(tmpdir(), 'noms-cli-corpus-'));
const executed = [];
const notApplicable = [];
try {
  const keyFile = join(directory, 'key.hex');
  for (const tool of tools) {
    const result = run(tool, ['self-test']);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, 'NOMS conformance vectors passed\n');
    assert.equal(result.stderr, '');
  }
  for (const test of suite.cases) {
    if (test.operation === 'derive' || test.operation === 'parse_frame' || 'message_utf16' in test.input) {
      const reason = test.operation === 'derive'
        ? 'No CLI key-derivation operation'
        : test.operation === 'parse_frame'
          ? 'CLI has no framed-input operation'
          : 'Unpaired UTF-16 is not representable on the UTF-8 stdin transport';
      notApplicable.push({ id: test.id, reason });
      continue;
    }
    const { input, expected } = test;
    let message = input.message ?? '';
    if (input.message_repeat) message = input.message_repeat.text.repeat(input.message_repeat.count);
    const bytes = input.message_utf8_hex !== undefined ? Buffer.from(input.message_utf8_hex, 'hex') : Buffer.from(message);
    for (const tool of tools) {
      let args;
      if (test.operation === 'sign') {
        writeFileSync(keyFile, input.private_key, { mode: 0o600 });
        args = ['sign', '--key-file', keyFile, '--message-stdin'];
      } else if (test.operation === 'verify') args = ['verify', '--account', input.account, '--signature', input.signature, '--message-stdin'];
      else args = ['inspect', '--message-stdin'];
      const result = run(tool, args, bytes);
      const label = `${tool.name}: ${test.id}`;
      assert.equal(result.status, { ok: 0, valid: 0, invalid: 1, input_error: 2 }[expected.status], `${label}: ${result.stderr}`);
      if (expected.status === 'input_error') {
        assert.equal(result.stdout, '', label);
        assert.notEqual(result.stderr, '', label);
      } else {
        assert.equal(result.stderr, '', label);
        const output = test.operation === 'inspect'
          ? `utf8_bytes: ${expected.message_utf8_hex.length / 2}\npayload: ${expected.payload_hex}\ndigest: ${expected.digest}\n`
          : `${expected.signature ?? expected.status}\n`;
        assert.equal(result.stdout, output, label);
      }
      executed.push(`${tool.name}:${test.id}`);
    }
  }
  const first = suite.cases.find((test) => test.id === 'sign-0-1');
  const account = suite.cases.find((test) => test.id === 'key-0').expected.account;
  writeFileSync(keyFile, first.input.private_key, { mode: 0o600 });
  for (const tool of tools) {
    for (const wrapper of [' \t\r\n', '\ufeff', '\u0085', '\u00a0', '\v', '\f']) {
      const expectedStatus = wrapper === ' \t\r\n' ? 0 : 2;
      writeFileSync(keyFile, wrapper + first.input.private_key + wrapper, { mode: 0o600 });
      const signed = run(tool, ['sign', '--key-file', keyFile, '--message', first.input.message]);
      assert.equal(signed.status, expectedStatus, `${tool.name}: key-file envelope ${JSON.stringify(wrapper)}`);
      const pipedKey = run(tool, ['sign', '--key-stdin', '--message', first.input.message], wrapper + first.input.private_key + wrapper);
      assert.equal(pipedKey.status, expectedStatus, `${tool.name}: key-stdin envelope ${JSON.stringify(wrapper)}`);
      const pipedSignature = run(tool, ['verify', '--account', account, '--signature-stdin', '--message', first.input.message], wrapper + first.expected.signature + wrapper);
      assert.equal(pipedSignature.status, expectedStatus, `${tool.name}: signature envelope ${JSON.stringify(wrapper)}`);
    }
  }
  writeFileSync(keyFile, first.input.private_key, { mode: 0o600 });
  for (let i = 0; i < tools.length; i++) {
    const signer = tools[i], verifier = tools[1-i];
    const signed = run(signer, ['sign', '--key-file', keyFile, '--message-stdin'], Buffer.from(first.input.message));
    const verified = run(verifier, ['verify', '--account', account, '--signature-stdin', '--message', first.input.message], signed.stdout);
    assert.equal(signed.status, 0); assert.equal(verified.status, 0); assert.equal(verified.stdout, 'valid\n');
    for (const message of ['--message', '--key-stdin', '--signature', '']) {
      const signed = run(signer, ['sign', '--key-file', keyFile, '--message', message]);
      assert.equal(signed.status, 0, signed.stderr);
      assert.equal(run(verifier, ['verify', '--account', account, '--signature', signed.stdout.trim(), '--message', message]).status, 0);
    }
    for (const args of [
      ['sign', '--private-key', first.input.private_key, '--message', 'x'],
      ['sign', '--key-stdin', '--message-stdin'],
      ['sign', '--prompt-key', '--message-stdin'],
      ['verify', '--account', account, '--signature-stdin', '--message-stdin'],
      ['inspect', '--message', 'a', '--message', 'b'],
      ['sign', '--prompt-key', '--message', 'x'],
    ]) {
      const result = run(signer, args, Buffer.alloc(0));
      assert.equal(result.status, 2, `${signer.name} arguments: ${result.stderr}`);
      assert.equal(result.stdout, '');
      if (args.includes('--message-stdin')) assert.match(result.stderr, /standard input cannot supply both/);
      assert(!result.stderr.includes(first.input.private_key), 'secret leaked in error');
    }
  }
  if (process.platform !== 'win32') {
    const insecure = join(directory, 'insecure.hex');
    writeFileSync(insecure, first.input.private_key, { mode: 0o644 });
    for (const tool of tools) assert.equal(run(tool, ['sign', '--key-file', insecure, '--message', 'x']).status, 2);
  }
  const oversizedKey = join(directory, 'oversized.hex');
  writeFileSync(oversizedKey, '0'.repeat(4097), { mode: 0o600 });
  for (const tool of tools) assert.equal(run(tool, ['sign', '--key-file', oversizedKey, '--message', 'x']).status, 2);
  writeFileSync('artifacts/conformance/cli-report.json', JSON.stringify({ platform: process.platform, executed, not_applicable: notApplicable }, null, 2));
  console.log(`Both CLIs passed ${executed.length} fixture executions, transport checks, and bidirectional pipes`);
} finally { rmSync(directory, { recursive: true, force: true }); }
