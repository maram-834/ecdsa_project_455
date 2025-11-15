// Initialize elliptic curve
const EC = ellipticjs.ec;
const ec = new EC("secp256k1");

// Generate a fresh keypair once
const keyPair = ec.genKeyPair();

// Display keys on page load
window.onload = () => {
    document.getElementById("privateKey").value = keyPair.getPrivate("hex");
    document.getElementById("publicKey").value = keyPair.getPublic("hex");
};

function generateSignature() {
    const msg = document.getElementById("message").value.trim();

    if (msg === "") {
        alert("Please enter a message.");
        return;
    }

    // Hash message
    const msgHash = sha256(msg);

    // Sign
    const signature = keyPair.sign(msgHash);

    // Output signature
    const derSign = signature.toDER("hex");
    document.getElementById("signature").value = derSign;
}

// SHA-256 implementation
function sha256(message) {
    return CryptoJS.SHA256(message).toString();
}
