import { signMessage, verifyMessage } from '@openrai/noms';

const privateKey = process.env.NANO_ACCOUNT_PRIVATE_KEY;
if (!privateKey) throw new Error('Set NANO_ACCOUNT_PRIVATE_KEY to a raw 32-byte account private key.');

const message = 'NOMS example challenge';
const signature = signMessage(message, privateKey);
console.log(signature);
// Verification accepts a Nano account string and rejects malformed addresses.
