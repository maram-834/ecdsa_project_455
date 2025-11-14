// Create an elliptic curve object (using the SECP256k1 curve, commonly used for ECDSA)
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

    // Hash the message (using SHA256 as recommended for ECDSA)
    const msgHash = new TextEncoder().encode(message); // Create a Uint8Array from the message

    // Sign the message hash
    const signature = keyPair.sign(msgHash);

    // Display the signature's r and s values (ECDSA signature components)
    document.getElementById("signatureOutput").textContent = 
        `Signature (r): ${signature.r.toString(16)}\nSignature (s): ${signature.s.toString(16)}`;

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

    const r = new EC.curve.n(signatureParts[0], 16); // Convert r to a BigInteger
    const s = new EC.curve.n(signatureParts[1], 16); // Convert s to a BigInteger

    const msgHash = new TextEncoder().encode(message); // Hash the message again for verification

    // Verify the signature
    const result = EC.verify(msgHash, { r, s }, keyPair.getPublic());

    // Display the verification result
    document.getElementById("verificationResult").textContent = 
        result ? "The signature is valid!" : "The signature is NOT valid.";
}
