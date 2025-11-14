// Create an elliptic curve object (using the SECP256k1 curve, common for ECDSA)
const EC = new elliptic.ec('secp256k1');

// Generate a new key pair (public and private keys)
let keyPair = EC.genKeyPair();

// Function to generate a signature
function generateSignature() {
    const message = document.getElementById("message").value.trim();

    if (!message) {
        alert("Please enter a message to sign.");
        return;
    }

    // Hash the message (using SHA256)
    const msgHash = new TextEncoder().encode(message);
    const signature = keyPair.sign(msgHash);

    // Display the signature
    document.getElementById("signatureOutput").textContent = 
        `r: ${signature.r.toString(16)}\ns: ${signature.s.toString(16)}`;

    // Store the signature globally for verification
    window.signature = signature;
}

// Function to verify the signature
function verifySignature() {
    const message = document.getElementById("verifyMessage").value.trim();
    const signatureInput = document.getElementById("verifySignature").value.trim();

    if (!message || !signatureInput) {
        alert("Please enter both message and signature.");
        return;
    }

    // Convert the input signature back to BigIntegers
    const signatureParts = signatureInput.split(',');
    if (signatureParts.length !== 2) {
        alert("Invalid signature format. Use the correct r,s format.");
        return;
    }

    const r = new EC.curve.n(signatureParts[0], 16);
    const s = new EC.curve.n(signatureParts[1], 16);

    const msgHash = new TextEncoder().encode(message);

    const result = EC.verify(msgHash, { r, s }, keyPair.getPublic());

    document.getElementById("verificationResult").textContent = 
        result ? "The signature is valid!" : "The signature is NOT valid.";
}
