# Base64 Encryption and Decryption

def generate_key(text, key):
    key = list(key)
    new_key = []
    key_index = 0

    for char in text:
        if char.isalpha():
            new_key.append(key[key_index % len(key)])
            key_index += 1
        else:
            new_key.append(char)
    return "".join(new_key)

def encrypt(text, key):
    encrypted_text = []
    key = generate_key(text, key)

    for i in range(len(text)):
        if text[i].isalpha():
            shift = (ord(text[i].upper()) + ord(key[i].upper())) % 26
            encrypted_char = chr(shift + ord('A'))
            if text[i].islower():
                encrypted_char = encrypted_char.lower()
            encrypted_text.append(encrypted_char)
        else:
            encrypted_text.append(text[i])
    return "".join(encrypted_text)

def decrypt(cipher_text, key):
    decrypted_text = []
    key = generate_key(cipher_text, key)

    for i in range(len(cipher_text)):
        if cipher_text[i].isalpha():
            shift = (ord(cipher_text[i].upper()) - ord(key[i].upper()) + 26) % 26
            decrypted_char = chr(shift + ord('A'))
            if cipher_text[i].islower():
                decrypted_char = decrypted_char.lower()
            decrypted_text.append(decrypted_char)
        else:
            decrypted_text.append(cipher_text[i])
    return "".join(decrypted_text)
