from ecdsa import SigningKey, NIST384p
import hashlib

# 1. Generate keypair on P-384
sk = SigningKey.generate(curve=NIST384p)
vk = sk.get_verifying_key()

# 2. Private scalar d
d = sk.privkey.secret_multiplier
print("d (hex) =", hex(d)[2:])

# 3. Public point (x, y)
point = vk.pubkey.point
print("x (hex) =", hex(point.x())[2:])
print("y (hex) =", hex(point.y())[2:])

# 4. Message + SHA-256 hash (to match your backend!)
message = "hello from python external tool (P-384)"
msg_hash = hashlib.sha256(message.encode()).digest()

# 5. Signature over the hash
signature = sk.sign(msg_hash)
print("signature (hex) =", signature.hex())

print("\nUse exactly this message in the web app:")
print(message)
