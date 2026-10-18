import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { validateSuite } from '../../scripts/lib/conformance.mjs';
const suite = validateSuite(JSON.parse(readFileSync(new URL('../../conformance/suite.json', import.meta.url))));

test('production crypto bundle executes every shared fixture', async ({ page }) => {
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('conformance.html');
  await page.waitForFunction(() => typeof window.runConformanceCase === 'function');
  const results = await page.evaluate((cases) => cases.map((item) => ({ id: item.id, result: window.runConformanceCase(item) })), suite.cases);
  expect(results).toHaveLength(suite.cases.length);
  for (const [i, result] of results.entries()) {
    expect(result.id).toBe(suite.cases[i].id);
    expect(result.result, result.id).toEqual(suite.cases[i].expected);
  }
  expect(errors).toEqual([]);
});

test('signing fills Verify, marks the tab, and strict rejection stays live', async ({ page }) => {
  await page.goto('./');
  await page.locator('#seed').fill('0'.repeat(64));
  await expect(page.locator('#derived-account')).toContainText('nano_');
  await page.locator('#sign').click();
  await expect(page.locator('#verify-notification')).toBeVisible();
  const signature = await page.locator('#signature-output').inputValue();
  await page.getByRole('tab', { name: /Verify/ }).click();
  await expect(page.locator('#verify-notification')).toBeHidden();
  await expect(page.locator('#verify-signature')).toHaveValue(signature);
  await expect(page.locator('#verification-result')).toHaveText('Valid signature');
  await page.locator('#verify-signature').fill('0'.repeat(128));
  await expect(page.locator('#verification-result')).toHaveText('Invalid signature');
  const bad = suite.cases.find((item) => item.id === 's-plus-L');
  await page.locator('#verify-message').fill(bad.input.message);
  await page.locator('#verify-account').fill(bad.input.account);
  await page.locator('#verify-signature').fill(bad.input.signature);
  await expect(page.locator('#verification-result')).toHaveText('Invalid signature');
  await page.locator('#verify-signature').fill('abc');
  await expect(page.locator('#verify-signature-error')).toContainText('128 hexadecimal');
  await page.locator('#verify-signature').fill(signature + '\n');
  await expect(page.locator('#verify-signature-error')).toContainText('128 hexadecimal');
});
