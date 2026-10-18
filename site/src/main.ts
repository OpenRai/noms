import {
  accountFromPublicKey,
  encodePayload,
  hashMessage,
  publicKeyFromAccount,
  publicKeyFromPrivateKey,
  signMessage,
  verifyMessage,
} from '@openrai/noms';
import vectors from '../../conformance/vectors.json';
import { nanoPrivateKeyFromSeed } from './nano-seed.js';
import './style.css';

const byId = <T extends HTMLElement>(id: string) => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`missing page element: ${id}`);
  return element as T;
};
const input = (id: string) => byId<HTMLInputElement>(id);
const textarea = (id: string) => byId<HTMLTextAreaElement>(id);
const output = (id: string) => byId<HTMLOutputElement>(id);
const usesCssSeedMask = CSS.supports('-webkit-text-security', 'disc');

if (!usesCssSeedMask) input('seed').type = 'password';

function clearVerifyNotification(): void {
  const tab = byId<HTMLButtonElement>('verify-tab');
  const marker = byId<HTMLSpanElement>('verify-notification');
  marker.hidden = true;
  marker.classList.remove('notify');
  tab.setAttribute('aria-label', 'Verify');
}

function markVerifyNotification(): void {
  const tab = byId<HTMLButtonElement>('verify-tab');
  const marker = byId<HTMLSpanElement>('verify-notification');
  marker.hidden = false;
  marker.classList.remove('notify');
  tab.setAttribute('aria-label', 'Verify, new signature ready');
  void marker.offsetWidth;
  marker.classList.add('notify');
}

function activateToolTab(selectedId: 'sign' | 'verify'): void {
  const signTab = byId<HTMLButtonElement>('sign-tab');
  const verifyTab = byId<HTMLButtonElement>('verify-tab');
  const signPanel = byId<HTMLElement>('sign-panel');
  const verifyPanel = byId<HTMLElement>('verify-panel');
  const showSign = selectedId === 'sign';

  signTab.setAttribute('aria-selected', String(showSign));
  signTab.tabIndex = showSign ? 0 : -1;
  verifyTab.setAttribute('aria-selected', String(!showSign));
  verifyTab.tabIndex = showSign ? -1 : 0;
  signPanel.hidden = !showSign;
  verifyPanel.hidden = showSign;

  if (!showSign) clearVerifyNotification();
}

const toolTabs = byId<HTMLDivElement>('tool-tabs');
toolTabs.addEventListener('click', (event) => {
  if (!(event.target instanceof Element)) return;
  const tab = event.target.closest<HTMLButtonElement>('[role="tab"]');
  if (tab?.id === 'sign-tab') activateToolTab('sign');
  if (tab?.id === 'verify-tab') activateToolTab('verify');
});
toolTabs.addEventListener('keydown', (event) => {
  const tabs = [byId<HTMLButtonElement>('sign-tab'), byId<HTMLButtonElement>('verify-tab')];
  const activeIndex = tabs.findIndex((tab) => tab.getAttribute('aria-selected') === 'true');
  let nextIndex: number | undefined;

  if (event.key === 'ArrowRight') nextIndex = (activeIndex + 1) % tabs.length;
  if (event.key === 'ArrowLeft') nextIndex = (activeIndex + tabs.length - 1) % tabs.length;
  if (event.key === 'Home') nextIndex = 0;
  if (event.key === 'End') nextIndex = tabs.length - 1;
  if (nextIndex === undefined) return;

  event.preventDefault();
  activateToolTab(nextIndex === 0 ? 'sign' : 'verify');
  tabs[nextIndex]?.focus();
});

activateToolTab('sign');

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function deriveAccount(): { privateKey: string; account: string } {
  const indexValue = input('account-index').value;
  if (indexValue === '') throw new Error('account index is required');
  const privateKey = nanoPrivateKeyFromSeed(input('seed').value.trim(), Number(indexValue));
  const account = accountFromPublicKey(publicKeyFromPrivateKey(privateKey));
  output('derived-account').value = account;
  input('verify-account').value = account;
  return { privateKey, account };
}

function reportError(error: unknown): void {
  output('error').value = error instanceof Error ? error.message : String(error);
}

function clearError(): void {
  output('error').value = '';
}

function setVerificationFieldError(fieldId: string, message: string): void {
  const field = byId<HTMLInputElement | HTMLTextAreaElement>(fieldId);
  const error = byId<HTMLElement>(`${fieldId}-error`);
  field.setAttribute('aria-invalid', String(message !== ''));
  error.textContent = message;
}

function updateVerificationStatus(): void {
  const message = textarea('verify-message').value;
  const account = input('verify-account').value;
  const signature = textarea('verify-signature').value;
  let messageError = '';
  let accountError = '';
  let signatureError = '';

  try {
    encodePayload(message);
  } catch (error) {
    messageError = error instanceof Error ? error.message : String(error);
  }

  if (!account) {
    accountError = 'Nano account is required.';
  } else {
    try {
      publicKeyFromAccount(account);
    } catch (error) {
      accountError = error instanceof Error ? error.message : String(error);
    }
  }

  if (!signature) {
    signatureError = 'Signature is required.';
  } else if (signature.length !== 128 || !/^[0-9a-fA-F]{128}$/.test(signature)) {
    signatureError = 'Signature must be exactly 128 hexadecimal characters.';
  }

  setVerificationFieldError('verify-message', messageError);
  setVerificationFieldError('verify-account', accountError);
  setVerificationFieldError('verify-signature', signatureError);

  const status = byId<HTMLDivElement>('verification-status');
  const result = output('verification-result');
  if (messageError || accountError || signatureError) {
    status.dataset.state = 'incomplete';
    result.value = 'Correct the highlighted fields to verify.';
    return;
  }

  const valid = verifyMessage(message, signature, account);
  status.dataset.state = valid ? 'valid' : 'invalid';
  result.value = valid ? 'Valid signature' : 'Invalid signature';
}

function updateDerivedAccount(): void {
  clearError();
  if (!input('seed').value.trim()) {
    output('derived-account').value = '';
    input('verify-account').value = '';
    updateVerificationStatus();
    return;
  }

  try {
    deriveAccount();
  } catch (error) {
    output('derived-account').value = '';
    input('verify-account').value = '';
    reportError(error);
  }
  updateVerificationStatus();
}

byId<HTMLButtonElement>('generate-seed').addEventListener('click', () => {
  clearError();
  try {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    input('seed').value = hex(seed);
    updateDerivedAccount();
  } catch (error) {
    reportError(error);
  }
});

input('seed').addEventListener('input', updateDerivedAccount);
input('account-index').addEventListener('input', updateDerivedAccount);
textarea('verify-message').addEventListener('input', updateVerificationStatus);
input('verify-account').addEventListener('input', updateVerificationStatus);
textarea('verify-signature').addEventListener('input', updateVerificationStatus);
updateVerificationStatus();

byId<HTMLButtonElement>('toggle-seed').addEventListener('click', (event) => {
  const button = event.currentTarget as HTMLButtonElement;
  const seed = input('seed');
  const show = seed.dataset.revealed !== 'true';
  seed.dataset.revealed = String(show);
  if (!usesCssSeedMask) seed.type = show ? 'text' : 'password';
  button.textContent = show ? 'Hide seed' : 'Show seed';
  button.setAttribute('aria-pressed', String(show));
});

byId<HTMLButtonElement>('sign').addEventListener('click', () => {
  clearError();
  try {
    const { privateKey, account } = deriveAccount();
    const message = textarea('sign-message').value;
    const signature = signMessage(message, privateKey);
    const payload = encodePayload(message);
    textarea('signature-output').value = signature;
    textarea('payload-output').value = hex(payload);
    input('digest-output').value = hex(hashMessage(message));
    input('verify-account').value = account;
    textarea('verify-message').value = message;
    textarea('verify-signature').value = signature;
    updateVerificationStatus();
    markVerifyNotification();
  } catch (error) {
    reportError(error);
  }
});

byId<HTMLButtonElement>('self-test').addEventListener('click', () => {
  clearError();
  try {
    const privateKey = vectors.keypair.private_key;
    const account = vectors.keypair.account;
    const ok = vectors.vectors.every((vector) =>
      hex(encodePayload(vector.message)) === vector.payload_hex
      && hex(hashMessage(vector.message)) === vector.digest
      && signMessage(vector.message, privateKey) === vector.signature
      && verifyMessage(vector.message, vector.signature, account),
    );
    output('self-test-result').value = ok ? 'All published vectors passed' : 'A published vector failed';
    output('self-test-result').dataset.valid = String(ok);
  } catch (error) {
    reportError(error);
  }
});

byId<HTMLButtonElement>('clear').addEventListener('click', () => {
  input('seed').value = '';
  input('seed').dataset.revealed = 'false';
  if (!usesCssSeedMask) input('seed').type = 'password';
  byId<HTMLButtonElement>('toggle-seed').textContent = 'Show seed';
  byId<HTMLButtonElement>('toggle-seed').setAttribute('aria-pressed', 'false');
  input('account-index').value = '0';
  output('derived-account').value = '';
  input('verify-account').value = '';
  textarea('sign-message').value = '';
  textarea('signature-output').value = '';
  textarea('payload-output').value = '';
  input('digest-output').value = '';
  textarea('verify-message').value = '';
  textarea('verify-signature').value = '';
  updateVerificationStatus();
  output('self-test-result').value = '';
  clearError();
});
