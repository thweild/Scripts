import base64
import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# === HELPER FUNCTIONS ===

def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Derives a secure AES key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())

def pad(data: bytes) -> bytes:
    """Pads the data to be a multiple of AES block size."""
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad(padded_data: bytes) -> bytes:
    """Removes padding from the data."""
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# === MAIN FUNCTIONS ===

def encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(16)  # 16 bytes random salt
    iv = os.urandom(16)    # 16 bytes random IV
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padded_data = pad(plaintext.encode())
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combine salt + iv + ciphertext, then encode in base64
    encrypted_data = base64.b64encode(salt + iv + ciphertext)
    return encrypted_data.decode()

def decrypt(encrypted_text: str, password: str) -> str:
    try:
        decoded_data = base64.b64decode(encrypted_text.encode())

        salt = decoded_data[:16]
        iv = decoded_data[16:32]
        ciphertext = decoded_data[32:]

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpad(padded_plaintext)
        return plaintext.decode()

    except Exception as e:
        return "Wrong password or corrupted data!"


