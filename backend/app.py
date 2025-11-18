from flask import Flask, render_template, request, jsonify
from ecdsa import SigningKey, NIST384p, NIST256p, NIST521p
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

# Generate keys for the specified curve
def generate_keys(curve):
    global private_key, public_key
    if curve == 'p256':
        private_key = SigningKey.generate(curve=NIST256p)  # P-256 curve
    elif curve == 'p384':
        private_key = SigningKey.generate(curve=NIST384p)  # P-384 curve
    elif curve == 'p521':
        private_key = SigningKey.generate(curve=NIST521p)  # P-521 curve
    else:
        private_key = SigningKey.generate(curve=NIST384p)  # Default curve (P-384)

    public_key = private_key.get_verifying_key()

    # Save keys to files
    key_folder = os.path.join(os.getcwd(), "keys")
    if not os.path.exists(key_folder):
        os.makedirs(key_folder)

    private_key_path = os.path.join(key_folder, "private_key.pem")
    public_key_path = os.path.join(key_folder, "public_key.pem")

    with open(private_key_path, "w") as f:
        f.write(private_key.to_pem().decode())
    with open(public_key_path, "w") as f:
        f.write(public_key.to_pem().decode())

    return private_key, public_key

# Sign a message for the specified curve
def sign_message(curve, message):
    if not private_key:
        return None
    msg_hash = hashlib.sha256(message.encode()).digest()
    signature = private_key.sign(msg_hash)
    return signature.hex()

@app.route('/p256', methods=['GET'])
def p256():
    return render_template('p256.html')

@app.route('/p384', methods=['GET'])
def p384():
    return render_template('index.html')  # This is the page you already have for P-384

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
    message = request.json.get('message')
    signature = sign_message(curve, message)
    return jsonify({'signature': signature})

@app.route('/verify_signature/<curve>', methods=['POST'])
def verify_signature_route(curve):
    message = request.json.get('message')
    signature = request.json.get('signature')
    if not message or not signature:
        return jsonify({'error': 'Message or signature missing'}), 400
    is_valid = verify_signature(curve, message, signature)
    return jsonify({'valid': is_valid, 'message': 'Signature is valid!' if is_valid else 'Signature is invalid!'})
@app.after_request
def add_header(response):
    response.headers['X-Frame-Options'] = 'ALLOWALL'
    return response

# Verify the signature for the specified curve
from ecdsa import VerifyingKey

# Verify the signature for the specified curve
def verify_signature(curve, message, signature_hex):
    # Load the public key from the saved file
    key_folder = os.path.join(os.getcwd(), "keys")
    
    public_key_path = os.path.join(key_folder, "public_key.pem")
    
    if not os.path.exists(public_key_path):
        return False  # Public key not found
    
    with open(public_key_path, "r") as f:
        public_key_pem = f.read()

    try:
        # Create the VerifyingKey object from the public key
        public_key = VerifyingKey.from_pem(public_key_pem)

        # Hash the message
        msg_hash = hashlib.sha256(message.encode()).digest()
        
        # Convert the signature back to bytes
        signature = bytes.fromhex(signature_hex)

        # Verify the signature using the public key
        return public_key.verify(signature, msg_hash)
    
    except Exception as e:
        print(f"Error during signature verification: {e}")
        return False


if __name__ == '__main__':
    app.run(debug=True)
