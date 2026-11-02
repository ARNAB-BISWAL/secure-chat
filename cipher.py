import base64

def encrypt(text, key):
    data = text.encode("utf-8")
    key_bytes = key.encode("utf-8")
    if not key_bytes:
        raise ValueError("Encryption key cannot be empty")
    encrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return base64.b64encode(encrypted).decode("ascii")

def decrypt(token, key):
    data = base64.b64decode(token.encode("ascii"), validate=True)
    key_bytes = key.encode("utf-8")
    if not key_bytes:
        raise ValueError("Encryption key cannot be empty")
    decrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return decrypted.decode("utf-8")
