import { spawnSync } from 'node:child_process';

const result = spawnSync('npm', ['--version'], { encoding: 'utf8' });
if (result.status !== 0) throw new Error(result.stderr || 'could not read npm version');
const current = result.stdout.trim().split('.').map(Number);
const minimum = [11, 5, 1];
const meetsMinimum = current.some((part, index) => {
  if (part !== minimum[index]) return part > minimum[index];
  return false;
}) || current[0] === minimum[0] && current[1] === minimum[1] && current[2] >= minimum[2];

if (!meetsMinimum) throw new Error(`npm ${result.stdout.trim()} is too old for trusted publishing; need npm 11.5.1 or newer`);
process.stdout.write(`npm ${result.stdout.trim()} supports trusted publishing\n`);
