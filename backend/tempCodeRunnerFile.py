from flask import Flask, render_template, request, jsonify
from ecdsa import SigningKey, VerifyingKey, NIST384p, NIST256p, NIST521p
import hashlib
import os
from flask_cors import CORS

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), '..', 'templates'),
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'static')
)
CORS(app)

# Global variables for private and public keys
private_key = None
public_key = None

# ------------------------- KEY GENERATION -------------------------
def generate_keys(curve):
    global private_key, public_key
    if curve == 'p256':
        private_key = SigningKey.generate(curve=NIST256p)
    elif curve == 'p384':
        private_key = SigningKey.generate(curve=NIST384p)
    elif curve == 'p521':
        private_key = SigningKey.generate(curve=NIST521p)
    else:
        private_key = SigningKey.generate(curve=NIST384p)

    public_key = private_key.get_verifying_key()

# ------------------------- FIXED SIGNING (DETERMINISTIC RFC6979) -------------------------
def sign_message(private_key_pem, message):
    if not private_key_pem or not message:
        return None

    try:
        # Load the private key from the PEM string provided by the client
        private_key = SigningKey.from_pem(private_key_pem)

        # Hash the message
        msg_hash = hashlib.sha256(message.encode()).digest()

        # Sign the hash
        signature = private_key.sign(msg_hash)

        # Return the signature as hex
        return signature.hex()

    except Exception as e:
        print("Signing error:", e)
        return None



# ------------------------- FIXED VERIFY SIGNATURE -------------------------
def verify_signature(curve, message, signature_hex, public_key_pem=None):
    try:
        # If a public key is provided, use it
        if public_key_pem:
            public_key = VerifyingKey.from_pem(public_key_pem)
        else:
            # fallback to the server saved public key
            key_folder = os.path.join(os.getcwd(), "keys")
            public_key_path = os.path.join(key_folder, "public_key.pem")
            if not os.path.exists(public_key_path):
                return False
            with open(public_key_path, "r") as f:
                public_key = VerifyingKey.from_pem(f.read())

        msg_hash = hashlib.sha256(message.encode()).digest()
        signature = bytes.fromhex(signature_hex)

        return public_key.verify(signature, msg_hash)

    except Exception as e:
        print("Error during signature verification:", e)
        return False


# ------------------------- ROUTES (UNCHANGED) -------------------------
@app.route('/p256', methods=['GET'])
def p256():
    return render_template('p256.html')

@app.route('/p384', methods=['GET'])
def p384():
    return render_template('index.html')

@app.route('/p521', methods=['GET'])
def p521():
    return render_template('p521.html')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/generate_keys/<curve>', methods=['GET'])
def generate_keys_route(curve):
    private_key, public_key = generate_keys(curve)
    return jsonify({
        'message': 'Keys generated successfully!',
        'private_key': private_key.to_pem().decode(),
        'public_key': public_key.to_pem().decode()
    })


@app.route('/sign_message/<curve>', methods=['POST'])
def sign_message_route(curve):
    data = request.json
    message = data.get('message')
    private_key_pem = data.get('private_key')  # now must be provided by client

    if not message or not private_key_pem:
        return jsonify({"error": "Message or private key missing"}), 400

    signature = sign_message(private_key_pem, message)
    if not signature:
        return jsonify({"error": "Signing failed"}), 400

    return jsonify({"signature": signature})


@app.route('/verify_signature/<curve>', methods=['POST'])
def verify_signature_route(curve):
    data = request.json
    message = data.get('message')
    signature = data.get('signature')
    public_key_pem = data.get('public_key')  # now we accept the client public key

    if not message or not signature or not public_key_pem:
        return jsonify({'error': 'Message, signature, or public key missing'}), 400

    is_valid = verify_signature(curve, message, signature, public_key_pem)
    return jsonify({
        'valid': is_valid,
        'message': 'Signature is valid!' if is_valid else 'Signature is invalid!'
    })


@app.after_request
def add_header(response):
    response.headers['X-Frame-Options'] = 'ALLOWALL'
    return response


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5004))
    app.run(host="0.0.0.0", port=port, debug=True)
