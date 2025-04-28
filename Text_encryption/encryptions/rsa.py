from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Public key
    public_key = private_key.public_key()

    # Serialize both keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return public_pem.decode('utf-8'), private_pem.decode('utf-8')

def encrypt(text, public_key):
    # Load public key
    public_key = serialization.load_pem_public_key(public_key.encode('utf-8'))

    # Encrypt the text using RSA with OAEP padding
    ciphertext = public_key.encrypt(
        text.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex()  # Return encrypted text as a hex string

def decrypt(text, private_key_path):
    # Read private key from the specified file
    with open(private_key_path, 'rb') as key_file:
        private_key = key_file.read()

    # Load private key
    private_key = serialization.load_pem_private_key(private_key, password=None)

    # Convert the hex string back to bytes
    ciphertext = bytes.fromhex(text)

    # Decrypt the ciphertext using RSA with OAEP padding
    decrypted_text = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_text.decode('utf-8')
