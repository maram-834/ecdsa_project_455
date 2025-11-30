from flask import Flask, render_template, request, jsonify
from ecdsa import SigningKey, VerifyingKey, NIST384p, NIST256p, NIST521p, ellipticcurve
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

def get_curve_obj(curve_name):
    if curve_name == 'p256':
        return NIST256p
    elif curve_name == 'p384':
        return NIST384p
    elif curve_name == 'p521':
        return NIST521p
    # default to P-384 if something weird is passed
    return NIST384p

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

# ------------------------- SIGNING (PEM OR RAW SCALAR) -------------------------
def sign_message(curve_name, message, private_key_pem=None, private_scalar_hex=None):
    if not message:
        return None

    try:
        curve_obj = get_curve_obj(curve_name)

        if private_key_pem:
            # Load the private key from PEM
            private_key = SigningKey.from_pem(private_key_pem)
        elif private_scalar_hex:
            # Build key from raw scalar d (hex)
            secexp = int(private_scalar_hex, 16)
            private_key = SigningKey.from_secret_exponent(secexp, curve=curve_obj)
        else:
            # Nothing provided
            return None

        # Hash the message (you already used sha256 everywhere before)
        msg_hash = hashlib.sha256(message.encode()).digest()

        # Sign the hash – returns raw bytes
        signature = private_key.sign(msg_hash)

        # Return hex so it's easy to copy/paste
        return signature.hex()

    except Exception as e:
        print("Signing error:", e)
        return None

# ------------------------- VERIFY SIGNATURE (PEM OR RAW POINT) -------------------------
def verify_signature(curve_name, message, signature_hex,
                     public_key_pem=None,
                     public_x_hex=None,
                     public_y_hex=None):
    try:
        curve_obj = get_curve_obj(curve_name)

        if public_key_pem:
            # Normal PEM path
            public_key = VerifyingKey.from_pem(public_key_pem)
        elif public_x_hex and public_y_hex:
            # Build key from raw point (x, y) in hex
            x = int(public_x_hex, 16)
            y = int(public_y_hex, 16)

            # Validate that the point lies on the curve
            if not curve_obj.curve.contains_point(x, y):
                print("Point is NOT on the curve")
                return False

            point = ellipticcurve.Point(curve_obj.curve, x, y)
            public_key = VerifyingKey.from_public_point(point, curve=curve_obj)
        else:
            # Fallback: use stored public key file if present
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
    data = request.json or {}
    message = data.get('message')
    private_key_pem = data.get('private_key')          # PEM option
    private_scalar_hex = data.get('private_scalar_hex')  # raw scalar option

    if not message:
        return jsonify({"error": "Message is missing"}), 400

    if not private_key_pem and not private_scalar_hex:
        return jsonify({"error": "Provide either private_key (PEM) or private_scalar_hex"}), 400

    signature_hex = sign_message(curve, message,
                                 private_key_pem=private_key_pem,
                                 private_scalar_hex=private_scalar_hex)
    if not signature_hex:
        return jsonify({"error": "Signing failed"}), 400

    return jsonify({"signature_hex": signature_hex})



@app.route('/verify_signature/<curve>', methods=['POST'])
def verify_signature_route(curve):
    data = request.json or {}
    message = data.get('message')
    signature_hex = data.get('signature_hex')  # hex string
    public_key_pem = data.get('public_key')    # optional PEM
    public_x_hex = data.get('public_x_hex')    # optional X coordinate
    public_y_hex = data.get('public_y_hex')    # optional Y coordinate

    if not message or not signature_hex:
        return jsonify({'error': 'Message or signature missing'}), 400

    if not public_key_pem and not (public_x_hex and public_y_hex):
        return jsonify({'error': 'Provide either public_key (PEM) or (public_x_hex, public_y_hex)'}), 400

    is_valid = verify_signature(
        curve,
        message,
        signature_hex,
        public_key_pem=public_key_pem,
        public_x_hex=public_x_hex,
        public_y_hex=public_y_hex
    )

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
