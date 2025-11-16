from flask import Flask, render_template, request, jsonify
from ecdsa import SigningKey, NIST384p, util
import hashlib
import os

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), '..', 'templates'),
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'static')
)


# Global variables for private and public keys
private_key = None
public_key = None

# Generate keys
def generate_keys():
    global private_key, public_key
    private_key = SigningKey.generate(curve=NIST384p)
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

# Sign a message
def sign_message(message):
    global private_key
    if not private_key:
        return None
    msg_hash = hashlib.sha256(message.encode()).digest()
    signature = private_key.sign(msg_hash)
    return signature.hex()

# Verify the signature
def verify_signature(message, signature_hex):
    global public_key
    if not public_key:
        return False
    msg_hash = hashlib.sha256(message.encode()).digest()
    signature = bytes.fromhex(signature_hex)
    try:
        return public_key.verify(signature, msg_hash)
    except:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/generate_keys', methods=['GET'])
def generate_keys_route():
    private_key, public_key = generate_keys()
    return jsonify({
        'message': 'Keys generated successfully!',
        'private_key': private_key.to_pem().decode(),
        'public_key': public_key.to_pem().decode()
    })

@app.route('/sign_message', methods=['POST'])
def sign_message_route():
    message = request.json.get('message')
    if not message:
        return jsonify({'error': 'No message provided'}), 400
    signature = sign_message(message)
    return jsonify({'signature': signature})

@app.route('/verify_signature', methods=['POST'])
def verify_signature_route():
    message = request.json.get('message')
    signature = request.json.get('signature')
    if not message or not signature:
        return jsonify({'error': 'Message or signature missing'}), 400
    is_valid = verify_signature(message, signature)
    return jsonify({'valid': is_valid, 'message': 'Signature is valid!' if is_valid else 'Signature is invalid!'})

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
