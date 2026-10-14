import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const cli = new URL('../dist/cli.js', import.meta.url);
const run = (...args: string[]) => spawnSync(process.execPath, [cli.pathname, ...args], { encoding: 'utf8' });

describe('noms CLI', () => {
  it('runs built-in known-answer vectors offline', () => {
    const result = run('self-test');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('passed');
  });

  it('inspects exact payload bytes and digest', () => {
    const result = run('inspect', 'Hej Nano!🥦');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('utf8_bytes: 13');
    expect(result.stdout).toContain('digest: 33ce285b257df1ba87e1a91f32211a3b900ab4fdf68bebb3f75bef4b85aef951');
  });

  it('signs from a restricted key file and verifies the resulting signature', () => {
    const directory = mkdtempSync(join(tmpdir(), 'noms-cli-'));
    try {
      const keyPath = join(directory, 'key.hex');
      writeFileSync(keyPath, '681fd5ed71a9f81e9d29e3450f6cd8aacb87346fd21a26003389290b9d0cb173\n', { mode: 0o600 });
      const signature = run('sign', '--key-file', keyPath, 'Hej Nano!🥦');
      expect(signature.status).toBe(0);
      expect(signature.stdout.trim()).toBe('535c745819d0f40056f3c46402b4fae4356b3a8897bde99c955d411920e740d781e6dddcbde228e8b86c4383a1003f9f315519ff73bd356f561d19865dc90f09');
      const verified = run('verify', '--account', 'nano_3noms9a1zytox399kygpge6cc7hu1z79ms1cgzojodz8741qi7w5u3nzb8mn', '--signature', signature.stdout.trim(), 'Hej Nano!🥦');
      expect(verified.status).toBe(0);
      expect(verified.stdout.trim()).toBe('valid');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
