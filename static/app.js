document.getElementById("generateKeys").addEventListener("click", function() {
    const curve = window.location.pathname.split("/")[2];  // Detects the curve (p256, p384, p521)

    fetch(`/generate_keys/${curve}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById("keyStatus").textContent = data.message;
        });
});

document.getElementById("signMessage").addEventListener("click", function() {
    const message = document.getElementById("message").value;

    if (!message) {
        alert("Please enter a message.");
        return;
    }

    const curve = window.location.pathname.split("/")[2];  // Detects the curve

    fetch(`/sign_message/${curve}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById("signatureResult").value = data.signature;
    });
});

document.getElementById("verifySignature").addEventListener("click", function() {
    const message = document.getElementById("verifyMessage").value;
    const signature = document.getElementById("signatureInput").value;

    if (!message || !signature) {
        alert("Please enter both message and signature.");
        return;
    }

    const curve = window.location.pathname.split("/")[2];  // Detects the curve

    fetch(`/verify_signature/${curve}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, signature })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById("verificationResult").textContent = data.message;
    });
});
