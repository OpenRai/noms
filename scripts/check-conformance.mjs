import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import * as api from '../packages/typescript/dist/index.js';
import { hex, runCase, validateSuite } from './lib/conformance.mjs';

const suite = validateSuite(JSON.parse(readFileSync(new URL('../conformance/suite.json', import.meta.url))));
const manifest = JSON.parse(readFileSync(new URL('../conformance/manifest.json', import.meta.url)));
const extended = process.argv.includes('--extended');
const seed = Number(process.env.NOMS_TEST_SEED ?? 0x4e4f4d53) >>> 0;
let state = seed;
function random() { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; }
const generated = [];
for (let i = 0; i < (extended ? 10000 : 256); i++) {
  const key = createHash('sha256').update(`NOMS test key ${seed}:${i}`).digest('hex');
  const message = ['\0', '\ufeff', '\r\n', 'é', 'e\u0301', '🥦', ' ', String.fromCodePoint(0x10000 + random() % 0x10000)][i % 8] + String(random()) + (i % 19 === 0 ? '\n' : '');
  const publicKey = api.publicKeyFromPrivateKey(key);
  const account = api.accountFromPublicKey(publicKey);
  const signature = api.signMessage(message, key);
  for (const [operation, input] of [
    ['derive', { private_key: key }], ['inspect', { message }],
    ['sign', { message, private_key: key }], ['verify', { message, account, signature }],
  ]) {
    const test = { id: `generated-${i}-${operation}`, operation, input };
    generated.push({ ...test, expected: runCase(api, test), rule: 'Seeded differential test' });
  }
}
const verifications = generated.filter((test) => test.operation === 'verify');
for (let i = 0; i < (extended ? 10000 : 1024); i++) {
  const base = verifications[i % verifications.length];
  const input = { ...base.input };
  let status = 'invalid';
  if (i % 4 === 0) {
    const signature = Buffer.from(input.signature, 'hex');
    let s = BigInt(`0x${Buffer.from(signature.subarray(32)).reverse().toString('hex')}`) + (1n << 252n) + 27742317777372353535851937790883648493n;
    for (let n = 32; n < 64; n++) { signature[n] = Number(s & 255n); s >>= 8n; }
    input.signature = signature.toString('hex');
  } else if (i % 4 === 1) input.message += '!';
  else if (i % 4 === 2) {
    const signature = Buffer.from(input.signature, 'hex');
    signature[random() % 64] ^= 1 << (random() % 8);
    input.signature = signature.toString('hex');
  } else { input.account += '!'; status = 'input_error'; }
  generated.push({ id: `adversarial-${i}`, operation: 'verify', input, expected: { status }, rule: 'Seeded targeted mutation' });
}
const tests = [...suite.cases, ...generated];
const rustPath = process.env.NOMS_RUST_ADAPTER ?? `target/release/examples/conformance${process.platform === 'win32' ? '.exe' : ''}`;
const rust = spawnSync(rustPath, [], { input: tests.map((test) => JSON.stringify(test)).join('\n') + '\n', encoding: 'utf8', maxBuffer: 128 * 1024 * 1024, timeout: 600000 });
if (rust.error || rust.status !== 0) {
  mkdirSync('artifacts/conformance', { recursive: true });
  const completed = rust.stdout?.trim() ? rust.stdout.trim().split('\n').length : 0;
  writeFileSync('artifacts/conformance/failure.json', JSON.stringify({ seed, test: tests[completed], completed, error: rust.error?.message ?? rust.stderr }, null, 2));
}
if (rust.error) throw rust.error;
assert.equal(rust.status, 0, `Rust adapter crashed: ${rust.stderr}`);
const results = rust.stdout.trim().split('\n').map((line) => JSON.parse(line));
assert.equal(results.length, tests.length, 'Rust skipped or added cases');
const seen = new Set();
for (const [i, test] of tests.entries()) {
  const result = results[i];
  assert.equal(result.id, test.id, 'Rust case order/ID mismatch');
  assert(!seen.has(result.id), `duplicate result: ${result.id}`);
  seen.add(result.id);
  const { id, ...rustResult } = result;
  try {
    assert.deepEqual(runCase(api, test), test.expected, `TypeScript: ${test.id}`);
    assert.deepEqual(rustResult, test.expected, `Rust: ${test.id}`);
  } catch (error) {
    mkdirSync('artifacts/conformance', { recursive: true });
    writeFileSync('artifacts/conformance/failure.json', JSON.stringify({ seed, test, rustResult }, null, 2));
    throw error;
  }
}
// Persist the genuine generated signatures for the independent C oracle.
mkdirSync('artifacts/conformance', { recursive: true });
writeFileSync('artifacts/conformance/generated.json', JSON.stringify(generated.filter((test) => test.operation === 'verify' && test.expected.status === 'valid')));
const report = {
  profile: suite.profile, spec_sha256: manifest.spec_sha256, suite_sha256: manifest.suite_sha256,
  standards_revision: manifest.source_revision, seed, extended,
  fixture_cases: suite.cases.length, generated_cases: generated.length, executed_per_implementation: seen.size,
  cross_verified_signatures: tests.filter((test) => test.operation === 'sign').length,
  case_ids: [...seen], discrepancies: [],
  implementation_versions: { typescript: JSON.parse(readFileSync('packages/typescript/package.json')).version, rust: readFileSync('crates/noms/Cargo.toml', 'utf8').match(/^version = "([^"]+)"/m)[1], node: process.version, rustc: spawnSync('rustc', ['--version'], { encoding: 'utf8' }).stdout.trim() },
  implementation_sha256: Object.fromEntries(['packages/typescript/src/index.ts', 'packages/typescript/src/point.ts', 'crates/noms/src/lib.rs'].map((name) => [name, createHash('sha256').update(readFileSync(name)).digest('hex')])),
};
writeFileSync(`artifacts/conformance/${extended ? 'extended-report' : 'report'}.json`, JSON.stringify(report, null, 2) + '\n');
console.log(`Both libraries passed ${seen.size} cases each (${suite.cases.length} independent fixtures); seed=${seed}`);
