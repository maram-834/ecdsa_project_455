// Create EC instance
const EC = new elliptic.ec("secp256k1");

// Generate key pair
let keyPair = EC.genKeyPair();

// Sign message
function generateSignature() {
    const message = document.getElementById("message").value.trim();

    if (!message) {
        alert("Enter a message");
        return;
    }

    const hash = new TextEncoder().encode(message);
    const signature = keyPair.sign(hash);

    const rHex = signature.r.toString(16);
    const sHex = signature.s.toString(16);

    // Display signature in r,s format
    document.getElementById("signatureOutput").textContent =
        `${rHex},${sHex}`;

    window.lastSignature = { r: rHex, s: sHex };
}

// Verify signature
function verifySignature() {
    const message = document.getElementById("verifyMessage").value.trim();
    const sigText = document.getElementById("verifySignature").value.trim();

    if (!message || !sigText) {
        alert("Enter message and signature");
        return;
    }

    const parts = sigText.split(",");
    if (parts.length !== 2) {
        alert("Signature must be in the form r,s");
        return;
    }

    const r = parts[0];
    const s = parts[1];

    const hash = new TextEncoder().encode(message);

    const isValid = EC.verify(hash, { r, s }, keyPair.getPublic());

    document.getElementById("verificationResult").textContent =
        isValid ? "Signature is VALID ✓" : "Signature is NOT valid ✗";
}
