import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const bump = process.argv[2];
if (!['patch', 'minor', 'major'].includes(bump)) {
  throw new Error('Usage: pnpm release:cargo:patch|minor|major');
}

const run = (command, args) => execFileSync(command, args, { encoding: 'utf8' }).trim();
const status = run('git', ['status', '--porcelain']);
if (status) throw new Error('Commit or discard working tree changes before releasing Rust crates.');

const manifestPaths = ['crates/noms/Cargo.toml', 'crates/noms-cli/Cargo.toml'];
const manifests = manifestPaths.map((path) => readFileSync(path, 'utf8'));
const versions = manifests.map((manifest, index) => {
  const match = manifest.match(/^version = "(\d+)\.(\d+)\.(\d+)"$/m);
  if (!match) throw new Error(`Could not read stable package version from ${manifestPaths[index]}`);
  return match.slice(1).map(Number);
});
if (versions.some((version) => version.join('.') !== versions[0].join('.'))) {
  throw new Error('The noms and noms-cli versions must match before a coordinated release.');
}

const [major, minor, patch] = versions[0];
const nextVersion = bump === 'major'
  ? `${major + 1}.0.0`
  : bump === 'minor'
    ? `${major}.${minor + 1}.0`
    : `${major}.${minor}.${patch + 1}`;
const currentVersion = `${major}.${minor}.${patch}`;

const updatePackageVersion = (manifest) => manifest.replace(
  /^version = "\d+\.\d+\.\d+"$/m,
  `version = "${nextVersion}"`,
);
const cliDependency = `noms = { path = "../noms", version = "${currentVersion}" }`;
if (!manifests[1].includes(cliDependency)) {
  throw new Error(`Could not find the CLI dependency on noms ${currentVersion}.`);
}
const updatedManifests = [
  updatePackageVersion(manifests[0]),
  updatePackageVersion(manifests[1]).replace(
    cliDependency,
    `noms = { path = "../noms", version = "${nextVersion}" }`,
  ),
];

const lockPath = 'Cargo.lock';
const originalLock = readFileSync(lockPath, 'utf8');
let lock = originalLock;
for (const packageName of ['noms', 'noms-cli']) {
  const pattern = new RegExp(`(\\[\\[package\\]\\]\\nname = "${packageName}"\\nversion = ")${currentVersion}"`);
  if (!pattern.test(lock)) throw new Error(`Could not update ${packageName} in Cargo.lock.`);
  lock = lock.replace(pattern, `$1${nextVersion}"`);
}
const tags = [`noms-v${nextVersion}`, `noms-cli-v${nextVersion}`];
for (const tag of tags) {
  if (run('git', ['tag', '--list', tag])) throw new Error(`Release tag ${tag} already exists.`);
}

writeFileSync(manifestPaths[0], updatedManifests[0]);
writeFileSync(manifestPaths[1], updatedManifests[1]);
writeFileSync(lockPath, lock);
try {
  run('cargo', ['metadata', '--no-deps', '--format-version', '1', '--locked']);
} catch (error) {
  writeFileSync(manifestPaths[0], manifests[0]);
  writeFileSync(manifestPaths[1], manifests[1]);
  writeFileSync(lockPath, originalLock);
  throw error;
}
run('git', ['add', ...manifestPaths, lockPath]);
run('git', ['commit', '-m', `release: Rust NOMS ${nextVersion}`]);
for (const tag of tags) run('git', ['tag', '-a', tag, '-m', `Rust NOMS ${nextVersion}`]);

process.stdout.write(
  `Rust crates bumped from ${currentVersion} to ${nextVersion}.\n` +
  `Created release commit and tags: ${tags.join(', ')}.\n` +
  `Push main and ${tags[0]} first; push ${tags[1]} after the library publish succeeds.\n`,
);
