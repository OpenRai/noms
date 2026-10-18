import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as api from '../packages/typescript/dist/index.js';
import { runCase, validateSuite } from './lib/conformance.mjs';
const suite = JSON.parse(readFileSync(new URL('../conformance/suite.json', import.meta.url)));
validateSuite(suite);
for (const item of suite.cases) test(item.id, () => assert.deepEqual(runCase(api, item), item.expected));
for (const [name, mutate] of [
  ['unknown operation', (s) => { s.cases[0].operation = 'unknown'; }],
  ['duplicate ID', (s) => { s.cases[1].id = s.cases[0].id; }],
  ['missing expectation', (s) => { delete s.cases[0].expected; }],
  ['unknown field', (s) => { s.cases[0].skip = true; }],
  ['empty corpus', (s) => { s.cases = []; }],
  ['newline in transport hex', (s) => { s.cases.find((test) => test.operation === 'inspect').input = { message_utf8_hex: '00\n' }; }],
  ['non-string transport hex', (s) => { s.cases.find((test) => test.operation === 'inspect').input = { message_utf8_hex: 12 }; }],
  ['newline in expected payload', (s) => { s.cases.find((test) => test.operation === 'inspect').expected.payload_hex += '\n'; }],
]) test(`schema rejects ${name}`, () => { const copy = structuredClone(suite); mutate(copy); assert.throws(() => validateSuite(copy)); });
