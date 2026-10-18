import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, copyFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';

const root = process.cwd();
const directory = mkdtempSync(join(tmpdir(), 'noms-artifacts-'));
const env = { ...process.env };
for (const name of Object.keys(env)) if (/^npm_config_/i.test(name)) delete env[name];
function run(command, args, options = {}) {
  if (command === 'npm.cmd') {
    const cli = join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
    if (!existsSync(cli)) throw new Error('npm CLI not found beside the Node.js installation');
    command = process.execPath;
    args = [cli, ...args];
  }
  const result = spawnSync(command, args, { encoding: 'utf8', env, timeout: 600000, maxBuffer: 32 * 1024 * 1024, ...options });
  if (result.error || result.status !== 0) throw new Error(`${command}: ${result.error?.message ?? result.stderr}\n${result.stdout}`);
  return result.stdout;
}
try {
  console.log('Checking npm tarball in an isolated consumer project');
  const npmDirectory = join(directory, 'npm');
  mkdirSync(npmDirectory);
  writeFileSync(join(npmDirectory, 'package.json'), '{"private":true,"type":"module"}\n');
  const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const packed = JSON.parse(run(npmCommand, ['pack', '--json', '--pack-destination', directory], { cwd: resolve('packages/typescript') }))[0];
  run(npmCommand, ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--prefer-offline', join(directory, packed.filename)], { cwd: npmDirectory });
  const installed = join(npmDirectory, 'node_modules/@openrai/noms');
  const adapter = join(npmDirectory, 'adapter.mjs');
  writeFileSync(adapter, `import {readFileSync} from 'node:fs'; import assert from 'node:assert/strict'; import * as api from '@openrai/noms'; import {runCase} from ${JSON.stringify(pathToFileURL(resolve('scripts/lib/conformance.mjs')).href)}; const suite=JSON.parse(readFileSync(${JSON.stringify(resolve('conformance/suite.json'))})); for(const test of suite.cases) assert.deepEqual(runCase(api,test),test.expected,test.id); console.log(suite.cases.length);`);
  const count = Number(run(process.execPath, [adapter], { cwd: npmDirectory }).trim());
  assert.equal(count, JSON.parse(readFileSync('conformance/manifest.json')).case_count);
  console.log('Checking Cargo archives and their isolated native tests');
  run('cargo', ['package', '--workspace', '--locked', '--offline', '--allow-dirty']);
  const version = JSON.parse(readFileSync('packages/typescript/package.json')).version;
  const versions = Object.fromEntries(['noms', 'noms-cli'].map((name) => [name, readFileSync(`crates/${name}/Cargo.toml`, 'utf8').match(/^version = "([^"]+)"/m)[1]]));
  const rustDirectory = join(directory, 'rust');
  mkdirSync(rustDirectory);
  for (const name of ['noms', 'noms-cli']) run('tar', ['-xf', `${name}-${versions[name]}.crate`, '-C', rustDirectory], { cwd: resolve('target/package') });
  writeFileSync(join(rustDirectory, 'Cargo.toml'), `[workspace]\nmembers=["noms-${versions.noms}","noms-cli-${versions['noms-cli']}"]\nresolver="2"\n[patch.crates-io]\nnoms={path="noms-${versions.noms}"}\n`);
  copyFileSync('Cargo.lock', join(rustDirectory, 'Cargo.lock'));
  // Archive timestamps are normalized. Never reuse a target directory from a
  // previous extraction: Cargo can otherwise consider an old binary fresh.
  const target = join(rustDirectory, 'target');
  run('cargo', ['test', '--workspace', '--locked', '--offline', '--target-dir', target], { cwd: rustDirectory });
  run('cargo', ['build', '--locked', '--offline', '-p', 'noms-cli', '--target-dir', target], { cwd: rustDirectory });
  console.log('Checking interoperability of the installed artifact CLIs');
  run(process.execPath, ['scripts/check-cli-interop.mjs'], { env: { ...env, NOMS_JS_CLI: join(installed, 'dist/cli.js'), NOMS_RUST_CLI: join(target, `debug/noms${process.platform === 'win32' ? '.exe' : ''}`) } });
  mkdirSync('artifacts/conformance', { recursive: true });
  writeFileSync('artifacts/conformance/artifact-report.json', JSON.stringify({ npm: { name: '@openrai/noms', version, fixture_cases: count, integrity: packed.integrity }, rust: { versions, isolated_tests: true }, installed_cli_corpus: true }, null, 2));
  console.log('Installed npm artifact, isolated Rust crate tests, and installed CLI corpus passed');
} finally { rmSync(directory, { recursive: true, force: true }); }
