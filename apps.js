function generateSignature() {
    const message = document.getElementById("message").value;
    const signature = "This is where your ECDSA signature will appear"; // Placeholder

    document.getElementById("signature").innerHTML = `Signature: ${signature}`;
}
