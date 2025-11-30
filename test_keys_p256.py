from ecdsa import SigningKey, NIST256p
import hashlib

# 1. Generate keypair
sk = SigningKey.generate(curve=NIST256p)
vk = sk.get_verifying_key()

# Private scalar d
d = sk.privkey.secret_multiplier
print("d (hex) =", hex(d)[2:])

# Public point (x, y)
point = vk.pubkey.point
print("x (hex) =", hex(point.x())[2:])
print("y (hex) =", hex(point.y())[2:])

# 2. Sign a message using the same hashing as your backend
message = "hello from python external tool"
msg_hash = hashlib.sha256(message.encode()).digest()
sig = sk.sign(msg_hash)
print("signature (hex) =", sig.hex())

print("\nUse exactly this message in the web app:")
print(message)
