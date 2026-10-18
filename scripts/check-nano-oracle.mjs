import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import * as api from '../packages/typescript/dist/index.js';
import { hex } from './lib/conformance.mjs';

const pin = JSON.parse(readFileSync('conformance/nano-oracle.json'));
const directory = resolve('artifacts/nano-oracle');
const source = `${directory}/source`;
mkdirSync(source, { recursive: true });
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', maxBuffer: 128 * 1024 * 1024, timeout: 600000, ...options });
  if (result.error || result.status !== 0) throw new Error(`${command}: ${result.error?.message ?? result.stderr}`);
  return result.stdout;
}
if (!existsSync(`${source}/crypto/ed25519-donna/ed25519.c`)) {
  const archive = `${directory}/nano.tar.gz`;
  const response = await fetch(`https://api.github.com/repos/${pin.repository}/tarball/${pin.revision}`, { headers: { 'User-Agent': 'OpenRai-NOMS-conformance' } });
  if (!response.ok) throw new Error(`Nano source download failed: ${response.status}`);
  writeFileSync(archive, Buffer.from(await response.arrayBuffer()));
  run('tar', ['-xzf', archive, '--strip-components=1', '-C', source]);
}
for (const file of pin.files) {
  const bytes = readFileSync(`${source}/${file.path}`);
  const hash = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
  assert.equal(hash, file.sha, `Upstream source integrity: ${file.path}`);
}
const binary = `${directory}/oracle`;
run(process.env.CC ?? 'cc', ['-O2', '-DED25519_CUSTOMHASH', '-DED25519_CUSTOMRNG', '-I', source, 'scripts/oracle.c', `${source}/crypto/ed25519-donna/ed25519.c`, `${source}/crypto/blake2/blake2b-ref.c`, '-o', binary]);
const suite = JSON.parse(readFileSync('conformance/suite.json'));
const generated = JSON.parse(readFileSync('artifacts/conformance/generated.json'));
const requests = [];
const assertions = [];
for (const test of suite.cases.filter((test) => test.operation === 'inspect' && test.expected.status === 'ok')) {
  requests.push(`hash ${test.expected.payload_hex}`);
  assertions.push({ id: test.id, expected: test.expected.digest });
}
for (const test of [...suite.cases, ...generated].filter((test) => test.operation === 'verify' && test.expected.status === 'valid')) {
  requests.push(`verify ${hex(api.hashMessage(test.input.message))} ${test.input.signature.toLowerCase()} ${hex(api.publicKeyFromAccount(test.input.account))}`);
  assertions.push({ id: test.id, expected: 'valid' });
}
const malleable = suite.cases.find((test) => test.id === 's-plus-L');
requests.push(`verify ${hex(api.hashMessage(malleable.input.message))} ${malleable.input.signature} ${hex(api.publicKeyFromAccount(malleable.input.account))}`);
assertions.push({ id: 'documented-Nano-S-plus-L-difference', expected: 'valid' });
const signing = suite.cases.filter((test) => test.operation === 'sign');
for (const test of signing) requests.push(`sign ${hex(api.hashMessage(test.input.message))} ${test.input.private_key}`);
const lines = run(binary, [], { input: requests.join('\n') + '\n' }).trim().split('\n');
assert.equal(lines.length, requests.length, 'Oracle skipped cases');
for (const [i, item] of assertions.entries()) assert.equal(lines[i], item.expected, `Nano oracle: ${item.id}`);
const independent = signing.map((test, i) => ({ id: `nano-randomized-${test.id}`, operation: 'verify', input: { message: test.input.message, signature: lines[assertions.length + i], account: api.accountFromPublicKey(api.publicKeyFromPrivateKey(test.input.private_key)) }, expected: { status: 'valid' } }));
for (const test of independent) assert.equal(api.verifyMessage(test.input.message, test.input.signature, test.input.account), true, test.id);
const rust = run(`target/release/examples/conformance${process.platform === 'win32' ? '.exe' : ''}`, [], { input: independent.map((test) => JSON.stringify(test)).join('\n') + '\n' }).trim().split('\n').map(JSON.parse);
assert.equal(rust.length, independent.length);
for (const [i, result] of rust.entries()) { assert.equal(result.id, independent[i].id); assert.equal(result.status, 'valid', result.id); }
writeFileSync('artifacts/conformance/oracle-report.json', JSON.stringify({ upstream: pin.repository, revision: pin.revision, verified_source_files: pin.files.length, checks: requests.length + independent.length * 2, intentional_differences: ['S + L accepted by Nano; rejected by strict NOMS'] }, null, 2));
console.log(`Pinned Nano C oracle passed ${requests.length + independent.length * 2} checks, including independent randomized signatures`);
