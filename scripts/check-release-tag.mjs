import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const artifact = process.argv[2];
if (!['npm', 'noms', 'noms-cli'].includes(artifact)) {
  throw new Error('usage: node scripts/check-release-tag.mjs <npm|noms|noms-cli>');
}

let version;
if (artifact === 'npm') {
  version = JSON.parse(readFileSync(new URL('../packages/typescript/package.json', import.meta.url), 'utf8')).version;
} else {
  const result = spawnSync('cargo', ['metadata', '--no-deps', '--format-version', '1'], { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr || 'cargo metadata failed');
  const packages = JSON.parse(result.stdout).packages;
  version = packages.find((pkg) => pkg.name === artifact)?.version;
}

const expectedTag = `${artifact}-v${version}`;
if (process.env.GITHUB_REF_NAME !== expectedTag) {
  throw new Error(`tag ${process.env.GITHUB_REF_NAME} does not match ${expectedTag}`);
}
process.stdout.write(`Release tag matches ${artifact} ${version}\n`);
