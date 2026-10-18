import * as api from '../packages/typescript/dist/index.js';
import { writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import assert from 'node:assert/strict';
const seconds = Number(process.env.NOMS_FUZZ_SECONDS ?? 120);
const seed = Number(process.env.NOMS_TEST_SEED ?? 1313819987) >>> 0;
if (!Number.isFinite(seconds) || seconds <= 0) throw new Error('invalid fuzz duration');
let state = seed;
const random = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
const started = performance.now();
let iterations = 0;
while (performance.now() - started < seconds * 1000) {
  const units = Array.from({ length: random() % 64 }, () => random() % 65536);
  const text = String.fromCharCode(...units);
  const publicKey = Uint8Array.from({ length: 32 }, () => random() & 255);
  const account = api.accountFromPublicKey(publicKey);
  assert.deepEqual(api.publicKeyFromAccount(account), publicKey);
  const signature = Array.from({ length: 64 }, () => (random() & 255).toString(16).padStart(2, '0')).join('');
  for (const invoke of [() => api.encodePayload(text), () => api.publicKeyFromPrivateKey(text), () => api.publicKeyFromAccount(text), () => api.verifyMessage(text, signature, account), () => api.verifyMessage('fuzz', text, account)]) {
    try { invoke(); } catch (error) { if (!(error instanceof api.NomsInputError)) throw error; }
  }
  assert.equal(api.verifyMessage('fuzz', signature, account), false);
  iterations++;
}
const rust = spawnSync(`target/release/examples/fuzz${process.platform === 'win32' ? '.exe' : ''}`, [], { encoding: 'utf8', env: { ...process.env, NOMS_TEST_SEED: String(seed) }, timeout: (seconds + 30) * 1000 });
if (rust.error || rust.status !== 0) throw new Error(`Rust fuzz campaign failed: ${rust.error?.message ?? rust.stderr}`);
mkdirSync('artifacts/conformance', { recursive: true });
const report = { typescript: { seed, iterations, seconds }, rust: JSON.parse(rust.stdout) };
writeFileSync('artifacts/conformance/fuzz-report.json', JSON.stringify(report, null, 2));
console.log(`Bounded fuzz campaigns passed: TypeScript ${iterations}; Rust ${report.rust.iterations}; seed=${seed}`);
