# Base64 Encryption and Decryption

import base64

def encrypt(text):
    if isinstance(text, str):
        text_bytes = text.encode('utf-8')  # Convert to bytes
        base64_bytes = base64.b64encode(text_bytes)
        return base64_bytes.decode('utf-8')  # Convert back to string
    else:
        raise TypeError("Input must be a string.")

def decrypt(base64_text):
    if isinstance(base64_text, str):
        base64_bytes = base64_text.encode('utf-8')  # Convert to bytes
        text_bytes = base64.b64decode(base64_bytes)
        return text_bytes.decode('utf-8')  # Convert back to string
    else:
        raise TypeError("Input must be a string.")
