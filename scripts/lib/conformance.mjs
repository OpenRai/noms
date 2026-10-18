// Portable adapter: runs against the installed library and the browser bundle.
export const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export function runCase(api, test) {
  const input = test.input;
  try {
    if (test.operation === 'parse_frame') {
      const payload = Uint8Array.from(input.payload_hex.match(/../g) ?? [], (part) => Number.parseInt(part, 16));
      api.parsePayload(payload);
      return { status: 'ok' };
    }
    let message = input.message;
    if (input.message_utf8_hex !== undefined) {
      const bytes = Uint8Array.from(input.message_utf8_hex.match(/../g) ?? [], (part) => Number.parseInt(part, 16));
      try { message = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
      catch { throw new api.NomsInputError('invalid UTF-8'); }
    }
    if (input.message_utf16 !== undefined) message = String.fromCharCode(...input.message_utf16);
    if (input.message_repeat !== undefined) message = input.message_repeat.text.repeat(input.message_repeat.count);
    if (test.operation === 'derive') {
      const publicKey = api.publicKeyFromPrivateKey(input.private_key);
      return { status: 'ok', public_key: hex(publicKey), account: api.accountFromPublicKey(publicKey) };
    }
    if (test.operation === 'inspect') {
      const payload = api.encodePayload(message);
      return { status: 'ok', message_utf8_hex: hex(new TextEncoder().encode(message)), payload_hex: hex(payload), digest: hex(api.hashMessage(message)) };
    }
    if (test.operation === 'sign') return { status: 'ok', signature: api.signMessage(message, input.private_key) };
    if (test.operation === 'verify') return { status: api.verifyMessage(message, input.signature, input.account) ? 'valid' : 'invalid' };
    throw new Error(`unknown operation: ${test.operation}`);
  } catch (error) {
    if (!(error instanceof api.NomsInputError)) throw error;
    return { status: 'input_error' };
  }
}

function fields(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('expected object');
  for (const key of required) if (!(key in value)) throw new Error(`missing field: ${key}`);
  for (const key of Object.keys(value)) if (![...required, ...optional].includes(key)) throw new Error(`unknown field: ${key}`);
}

const lowerHex = (value) => typeof value === 'string' && value.length % 2 === 0 && !/[^0-9a-f]/.test(value);

export function validateSuite(suite) {
  fields(suite, ['schema_version', 'profile', 'provenance', 'cases']);
  if (suite.schema_version !== 1 || suite.profile !== 'oris-001-strict-v1' || typeof suite.provenance !== 'string') throw new Error('unknown conformance schema/profile');
  if (!Array.isArray(suite.cases) || !suite.cases.length) throw new Error('empty corpus');
  const ids = new Set();
  const operations = new Set();
  const outcomes = new Set();
  for (const test of suite.cases) {
    fields(test, ['id', 'operation', 'input', 'expected', 'rule', 'scope']);
    if (!['protocol', 'reference_policy', 'compatibility'].includes(test.scope)) throw new Error(`unknown requirement scope: ${test.id}`);
    if (typeof test.id !== 'string' || !test.id || ids.has(test.id)) throw new Error(`duplicate/invalid case ID: ${test.id}`);
    if (typeof test.rule !== 'string' || !test.rule) throw new Error(`missing rule: ${test.id}`);
    ids.add(test.id);
    operations.add(test.operation);
    const allowed = { derive: ['private_key'], inspect: [], sign: ['private_key'], verify: ['signature', 'account'], parse_frame: ['payload_hex'] }[test.operation];
    if (!allowed) throw new Error(`unknown operation: ${test.operation}`);
    fields(test.input, allowed, test.operation === 'derive' ? [] : ['message', 'message_utf16', 'message_utf8_hex', 'message_repeat']);
    for (const key of allowed) if (typeof test.input[key] !== 'string') throw new Error(`invalid ${key}`);
    const sources = ['message', 'message_utf16', 'message_utf8_hex', 'message_repeat'].filter((key) => key in test.input);
    if (test.operation === 'parse_frame') {
      if (sources.length !== 0 || !lowerHex(test.input.payload_hex)) throw new Error(`invalid frame bytes: ${test.id}`);
    } else if (sources.length !== (test.operation === 'derive' ? 0 : 1)) throw new Error(`ambiguous message: ${test.id}`);
    if ('message' in test.input && typeof test.input.message !== 'string') throw new Error('invalid message');
    if ('message_utf8_hex' in test.input && !lowerHex(test.input.message_utf8_hex)) throw new Error('invalid byte transport');
    if ('message_utf16' in test.input && (!Array.isArray(test.input.message_utf16) || !test.input.message_utf16.every((unit) => Number.isInteger(unit) && unit >= 0 && unit <= 65535))) throw new Error('invalid UTF-16 transport');
    if ('message_repeat' in test.input) {
      fields(test.input.message_repeat, ['text', 'count']);
      if (typeof test.input.message_repeat.text !== 'string' || !Number.isInteger(test.input.message_repeat.count) || test.input.message_repeat.count < 0 || test.input.message_repeat.count > 16777217) throw new Error('invalid repeated message');
    }
    const status = test.expected.status;
    outcomes.add(status);
    if (status === 'ok') {
      const resultKeys = { derive: ['public_key', 'account'], inspect: ['message_utf8_hex', 'payload_hex', 'digest'], sign: ['signature'], parse_frame: [] }[test.operation];
      if (!resultKeys) throw new Error(`invalid result status: ${test.id}`);
      fields(test.expected, ['status', ...resultKeys]);
      for (const key of resultKeys) {
        const value = test.expected[key];
        if (typeof value !== 'string' || (key !== 'account' && !lowerHex(value))) throw new Error(`invalid expected ${key}`);
      }
      for (const [key, length] of [['public_key', 64], ['digest', 64], ['signature', 128]]) {
        if (key in test.expected && test.expected[key].length !== length) throw new Error(`invalid expected ${key} length`);
      }
    } else {
      fields(test.expected, ['status']);
      if (!['input_error', 'valid', 'invalid'].includes(status) || (status !== 'input_error' && test.operation !== 'verify')) throw new Error(`invalid result: ${test.id}`);
    }
  }
  if (operations.size !== 5 || !['ok', 'valid', 'invalid', 'input_error'].every((status) => outcomes.has(status))) throw new Error('missing operation or outcome category');
  return suite;
}
