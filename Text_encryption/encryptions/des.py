from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii
import os

# Function to generate a DES key
def generate_des_key():
    key = os.urandom(8)  # DES key is 8 bytes (64 bits)
    return key

# Helper function to prepare the DES key
def prepare_key(key):
    key = key.encode()
    if len(key) < 8:
        key = key.ljust(8, b' ')  # pad with spaces
    else:
        key = key[:8]  # cut if too long
    return key

# Function to encrypt text using DES
def encrypt(text, key):
    key = prepare_key(key)  # prepare the key properly

    padded_data = pad(text.encode(), DES.block_size)
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_text = cipher.encrypt(padded_data)
    
    return binascii.hexlify(encrypted_text).decode()

# Function to decrypt text using DES
def decrypt(encrypted_text, key):
    try:
        key = prepare_key(key)  # prepare the key properly

        encrypted_data = binascii.unhexlify(encrypted_text)
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)

        return decrypted_data.decode()
    
    except (ValueError, KeyError):
        return "Decryption failed. Incorrect key or corrupted data."
