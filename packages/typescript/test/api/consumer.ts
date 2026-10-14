import { encodePayload, hashMessage, signMessage, verifyMessage } from '@openrai/noms';

const key = '681fd5ed71a9f81e9d29e3450f6cd8aacb87346fd21a26003389290b9d0cb173';
const account = 'nano_3noms9a1zytox399kygpge6cc7hu1z79ms1cgzojodz8741qi7w5u3nzb8mn';
const payload: Uint8Array = encodePayload('example');
const digest: Uint8Array = hashMessage('example');
const signature: string = signMessage('example', key);
const valid: boolean = verifyMessage('example', signature, account);
void [payload, digest, valid];
