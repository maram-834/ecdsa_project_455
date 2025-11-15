/* app.js — ECDSA demo using elliptic + SHA-256
   Features:
   - Generates secp256k1 keypair on load
   - Signs messages using SHA-256 digest
   - Displays signature in DER hex and r/s components
   - Verifies a signature against the current public key
   - Copy to clipboard helpers
*/

(() => {
  // Ensure elliptic is available
  if (typeof elliptic === 'undefined' || !elliptic.ec) {
    console.error('elliptic library not loaded.');
    return;
  }

  const EC = new elliptic.ec('secp256k1');

  // DOM elements
  const publicKeyEl = document.getElementById('publicKey');
  const regenerateKeysBtn = document.getElementById('regenerateKeysBtn');
  const copyPubKeyBtn = document.getElementById('copyPubKeyBtn');

  const messageInput = document.getElementById('message');
  const signBtn = document.getElementById('signBtn');
  const signatureOutput = document.getElementById('signatureOutput');
  const rsOutput = document.getElementById('rsOutput');
  const copySigBtn = document.getElementById('copySigBtn');

  const verifyMessageInput = document.getElementById('verifyMessage');
  const verifySignatureInput = document.getElementById('verifySignature');
  const useLastSigBtn = document.getElementById('useLastSigBtn');
  const verifyBtn = document.getElementById('verifyBtn');
  const verificationResult = document.getElementById('verificationResult');

  let keyPair = null;
  let lastSignatureDERHex = null;

  // Utility: convert ArrayBuffer to hex
  function toHex(buffer) {
    const b = new Uint8Array(buffer);
    let s = '';
    for (let i = 0; i < b.length; i++) {
      s += b[i].toString(16).padStart(2, '0');
    }
    return s;
  }

  // Utility: SHA-256 hash of a UTF-8 string, returns hex
  async function sha256Hex(message) {
    const enc = new TextEncoder();
    const data = enc.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return toHex(hashBuffer);
  }

  // Generate a new keypair and render public key
  function generateKeyPair() {
    keyPair = EC.genKeyPair();
    // public key in hex (uncompressed)
    const pubHex = keyPair.getPublic('hex');
    publicKeyEl.value = pubHex;
  }

  // Copy helper
  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      // fallback
      const tmp = document.createElement('textarea');
      tmp.value = text;
      tmp.style.position = 'fixed';
      tmp.style.left = '-9999px';
      document.body.appendChild(tmp);
      tmp.select();
      try { document.execCommand('copy'); } catch (e) {}
      document.body.removeChild(tmp);
      return false;
    }
  }

  // Sign message (async because of sha256)
  async function signMessage() {
    const msg = messageInput.value ?? '';
    if (!msg.trim()) {
      alert('Please provide a message to sign.');
      return;
    }
    signBtn.disabled = true;
    signBtn.textContent = 'Signing…';
    try {
      const msgHashHex = await sha256Hex(msg);
      // elliptic accepts hex message hash for signing
      const sig = keyPair.sign(msgHashHex, { canonical: true });
      // signature DER (hex) and r,s
      const derHex = sig.toDER('hex');
      lastSignatureDERHex = derHex;
      signatureOutput.value = derHex;
      const rHex = sig.r.toString(16).padStart(64, '0');
      const sHex = sig.s.toString(16).padStart(64, '0');
      rsOutput.textContent = `${rHex} / ${sHex}`;
      verificationResult.textContent = 'Signature created — you can verify below.';
      verificationResult.style.color = '';
    } catch (err) {
      console.error('Signing failed', err);
      alert('An error occurred while signing. See console for details.');
    } finally {
      signBtn.disabled = false;
      signBtn.textContent = 'Sign Message';
    }
  }

  // Verify signature (async because of sha256)
  async function verifySignature() {
    const msg = verifyMessageInput.value ?? '';
    const sigHex = verifySignatureInput.value?.trim() ?? '';
    if (!msg.trim()) {
      alert('Please provide the message to verify.');
      return;
    }
    if (!sigHex) {
      alert('Please provide a signature (DER hex).');
      return;
    }

    verifyBtn.disabled = true;
    verifyBtn.textContent = 'Verifying…';
    try {
      const msgHashHex = await sha256Hex(msg);
      // Verify against current public key
      const pubHex = keyPair.getPublic('hex');
      const pubKey = EC.keyFromPublic(pubHex, 'hex');

      const ok = pubKey.verify(msgHashHex, sigHex);
      if (ok) {
        verificationResult.textContent = 'Signature is VALID ✓';
        verificationResult.style.color = 'var(--success)';
      } else {
        verificationResult.textContent = 'Signature is NOT valid ✗';
        verificationResult.style.color = 'var(--danger)';
      }
    } catch (err) {
      console.error('Verification failed', err);
      alert('An error occurred while verifying. Check the console for details.');
    } finally {
      verifyBtn.disabled = false;
      verifyBtn.textContent = 'Verify Signature';
    }
  }

  // Event wiring
  regenerateKeysBtn.addEventListener('click', () => {
    generateKeyPair();
    signatureOutput.value = '';
    rsOutput.textContent = '— / —';
    lastSignatureDERHex = null;
    verificationResult.textContent = 'Regenerated keys. Previous signatures are invalid for this new keypair.';
    verificationResult.style.color = '';
  });

  copyPubKeyBtn.addEventListener('click', async () => {
    const ok = await copyToClipboard(publicKeyEl.value);
    copyPubKeyBtn.textContent = ok ? 'Copied ✓' : 'Copy';
    setTimeout(() => (copyPubKeyBtn.textContent = 'Copy Public Key'), 1200);
  });

  signBtn.addEventListener('click', signMessage);

  copySigBtn.addEventListener('click', async () => {
    const ok = await copyToClipboard(signatureOutput.value);
    copySigBtn.textContent = ok ? 'Copied ✓' : 'Copy';
    setTimeout(() => (copySigBtn.textContent = 'Copy Signature'), 1200);
  });

  useLastSigBtn.addEventListener('click', () => {
    if (!lastSignatureDERHex) {
      alert('No signature available. Please sign a message first.');
      return;
    }
    verifySignatureInput.value = lastSignatureDERHex;
  });

  verifyBtn.addEventListener('click', verifySignature);

  // Initialize UI on load
  document.addEventListener('DOMContentLoaded', () => {
    generateKeyPair();
    verificationResult.textContent = 'Ready — generate and verify signatures.';
  });
})();
