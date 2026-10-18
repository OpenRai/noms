import { defineConfig, devices } from '@playwright/test';
import { createServer } from 'node:net';
// Playwright forces color in child processes; avoid conflicting Node settings.
delete process.env.NO_COLOR;
let port = Number(process.env.NOMS_BROWSER_PORT ?? 0);
if (!port) {
  const probe = createServer();
  await new Promise((resolve, reject) => { probe.once('error', reject); probe.listen(0, '127.0.0.1', resolve); });
  port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  process.env.NOMS_BROWSER_PORT = String(port);
}
export default defineConfig({
  testDir: './site/browser-test',
  timeout: 120000,
  retries: 0,
  workers: 3,
  outputDir: 'artifacts/browser',
  reporter: [['list'], ['json', { outputFile: 'artifacts/conformance/browser-report.json' }]],
  use: { baseURL: `http://127.0.0.1:${port}/noms/`, trace: 'retain-on-failure' },
  webServer: { command: `pnpm --filter @openrai/noms-site preview --host 127.0.0.1 --port ${port} --strictPort`, url: `http://127.0.0.1:${port}/noms/`, reuseExistingServer: false },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
