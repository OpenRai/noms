import { createInterface } from 'node:readline';
import * as api from '../packages/typescript/dist/index.js';
import { runCase } from './lib/conformance.mjs';

for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  const test = JSON.parse(line);
  process.stdout.write(`${JSON.stringify({ id: test.id, ...runCase(api, test) })}\n`);
}
