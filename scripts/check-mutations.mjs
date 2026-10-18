import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, cpSync, rmSync, symlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import { runCase } from './lib/conformance.mjs';

const suite = JSON.parse(readFileSync('conformance/suite.json'));
const baselineApi = await import('../packages/typescript/dist/index.js');
for (const test of suite.cases) assert.deepEqual(runCase(baselineApi, test), test.expected, `unmodified TypeScript baseline: ${test.id}`);
const baselineRust = spawnSync('cargo', ['test', '--locked', '-p', 'noms', '--lib'], { encoding: 'utf8', timeout: 180000 });
assert(!baselineRust.error && baselineRust.status === 0, `unmodified Rust baseline failed: ${baselineRust.stderr}\n${baselineRust.stdout}`);
mkdirSync('artifacts', { recursive: true });
const directory = mkdtempSync(resolve('artifacts/mutations-'));
const killed = [];
function replaceOnce(source, from, to) {
  const matches = source.match(from);
  assert(matches, `mutation anchor disappeared: ${from}`);
  const changed = source.replace(from, to);
  assert.notEqual(changed, source, 'empty mutation');
  return changed;
}
const jsMutants = [
  ['scalar', 'index.js', /if \(s >= order\)\s*return false;/, '', 's-plus-L'],
  ['subgroup', 'index.js', / \|\| !a\.isTorsionFree\(\) \|\| !r\.isTorsionFree\(\)/, '', 'mixed-A-equation'],
  ['identity', 'index.js', /a\.is0\(\) \|\| r\.is0\(\) \|\| /, '', 'identity-A-forgery'],
  ['canonical-point', 'point.js', /fromBytes\(bytes, false\)/, 'fromBytes(bytes, true)', null],
  ['length-endian', 'index.js', /setUint32\(HEADER.length, encoded.length, false\)/, 'setUint32(HEADER.length, encoded.length, true)', 'message-1'],
  ['trim', 'index.js', /let byteLength = 0;/, 'message = message.trim(); let byteLength = 0;', 'message-5'],
  ['header', 'index.js', /0x18, 0x4e/, '0x19, 0x4e', 'message-1'],
  ['checksum', 'index.js', /if \(suppliedChecksum.some\(\(byte, index\) => byte !== expectedChecksum\[index\]\)\)/, 'if (false)', null],
];
try {
  for (const [name, file, from, to, caseId] of jsMutants) {
    const copy = join(directory, `js-${name}`);
    cpSync('packages/typescript/dist', copy, { recursive: true });
    writeFileSync(join(copy, 'package.json'), '{"type":"module"}');
    symlinkSync(resolve('packages/typescript/node_modules'), join(copy, 'node_modules'), process.platform === 'win32' ? 'junction' : 'dir');
    const filePath = join(copy, file);
    writeFileSync(filePath, replaceOnce(readFileSync(filePath, 'utf8'), from, to));
    const api = await import(pathToFileURL(join(copy, 'index.js')).href);
    let detected = false;
    if (name === 'canonical-point') {
      const point = await import(pathToFileURL(join(copy, 'point.js')).href);
      const alias = new Uint8Array(32).fill(255); alias[0] = 0xee; alias[31] = 0x7f;
      try { point.decodeCanonicalPoint(alias); } catch { detected = true; }
      detected = !detected; // Canonical-decoder rejection test must fail.
    } else if (name === 'checksum') {
      const test = suite.cases.find((test) => test.id === 'key-0');
      const address = test.expected.account;
      try { api.publicKeyFromAccount(address.slice(0, -1) + (address.endsWith('1') ? '3' : '1')); detected = true; } catch { /* Validation still held. */ }
    } else {
      const test = suite.cases.find((test) => test.id === caseId);
      assert(test, `missing designated fixture ${caseId}`);
      try { assert.deepEqual(runCase(api, test), test.expected); } catch (error) { if (error.code !== 'ERR_ASSERTION') throw error; detected = true; }
    }
    assert(detected, `surviving JavaScript mutation: ${name}`);
    killed.push(`typescript:${name}`);
  }
  const rustMutants = [
    ['scalar', /Scalar::from_canonical_bytes\(s_bytes\)/, 'Some(Scalar::from_bytes_mod_order(s_bytes))', 'shared_adversarial_verification_corpus'],
    ['subgroup', /\|\| !point_a\.is_torsion_free\(\)\s*\|\| !point_r\.is_torsion_free\(\)/, '', 'shared_adversarial_verification_corpus'],
    ['canonical-point', /if point.compress\(\).to_bytes\(\) != bytes \{[\s\S]*?return None;[\s\S]*?\}/, '', 'canonical_decoder_rejects_alias_before_subgroup_checks'],
    ['length-endian', /length.to_be_bytes\(\)/, 'length.to_le_bytes()', 'published_vectors_match_and_cross_verify'],
  ];
  for (const [name, from, to, test] of rustMutants) {
    const copy = join(directory, `rust-${name}`);
    cpSync('crates/noms', copy, { recursive: true });
    const file = join(copy, 'src/lib.rs');
    writeFileSync(file, replaceOnce(readFileSync(file, 'utf8'), from, to));
    const manifest = join(copy, 'Cargo.toml');
    writeFileSync(manifest, readFileSync(manifest, 'utf8') + '\n[workspace]\n');
    const result = spawnSync('cargo', ['test', '--offline', '--manifest-path', manifest, '--target-dir', resolve('target/mutations'), '--lib', test], { encoding: 'utf8', timeout: 180000 });
    assert(!result.error && result.status !== 0 && result.stdout.includes('test result: FAILED'), `mutation ${name} did not fail a test: ${result.stderr}\n${result.stdout}`);
    killed.push(`rust:${name}`);
  }
  mkdirSync('artifacts/conformance', { recursive: true });
  writeFileSync('artifacts/conformance/mutation-report.json', JSON.stringify({ killed, survivors: [] }, null, 2));
  console.log(`All ${killed.length} targeted security mutations were detected`);
} finally { rmSync(directory, { recursive: true, force: true }); }
