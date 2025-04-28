from encryptions import caesar, vigenere, base64_enc, aes, des, rsa

# Safe encryption and decryption functions
def safe_decrypt(decrypt_function, encrypted_text, key):
    try:
        return decrypt_function(encrypted_text, key)
    except (ValueError, KeyError):
        return "Decryption failed. Incorrect key or corrupted data."

def show_encryption_decryption_menu():
    print("===Welcome to the Text Encryption Program!===")
    print("1. Encryption")
    print("2. Decryption")
    print("0. Exit")
    print("===========================================")

def show_method_menu():
    print("Choose the encryption/decryption method:")
    print("1. Caesar Cipher")
    print("2. Vigenère Cipher")
    print("3. Base64 Encoding")
    print("4. AES Encryption")
    print("5. DES Encryption")
    print("6. RSA Encryption")
    print("===========================================")

def get_choice():
    try:
        return int(input("Choose an option: "))
    except ValueError:
        return -1

def run():
    while True:
        # First loop: choose encryption or decryption
        show_encryption_decryption_menu()
        mode_choice = get_choice()

        if mode_choice == 0:
            print("Exiting the program.")
            break
        elif mode_choice == 1 or mode_choice == 2:
            # Second loop: choose encryption/decryption method
            show_method_menu()
            method_choice = get_choice()

            if method_choice == 0:
                print("Exiting the program.")
                break
            elif method_choice < 1 or method_choice > 6:
                print("Invalid choice. Please try again.")
                continue
            
            # Input text
            text = input("Enter the text to Encrypt/Decrypt: ")

            # Encryption logic
            if mode_choice == 1:  # Encryption mode
                if method_choice == 1:
                    shift = int(input("Enter shift value for Caesar Cipher: "))
                    result = caesar.encrypt(text, shift)
                elif method_choice == 2:
                    key = input("Enter key for Vigenère Cipher: ")
                    result = vigenere.encrypt(text, key)
                elif method_choice == 3:
                    result = base64_enc.encrypt(text)
                elif method_choice == 4:
                    key = input("Enter key for AES Encryption: ")
                    result = aes.encrypt(text, key)
                elif method_choice == 5:
                    key = input("Enter key for DES Encryption: ")
                    result = des.encrypt(text, key)
                elif method_choice == 6:
                    public_key, private_key = rsa.generate_rsa_keys()  # Fix: Correct function call
                    result = rsa.encrypt(text, public_key)
                    print(f"Public Key: {public_key}")
                    print(f"Private Key: {private_key}")
                
                print("==================================")
                print(f"Encrypted text: {result}")
                print("==================================")
            
            # Decryption logic
            elif mode_choice == 2:  # Decryption mode
                if method_choice == 1:
                    shift = int(input("Enter shift value for Caesar Cipher: "))
                    result = caesar.decrypt(text, shift)
                elif method_choice == 2:
                    key = input("Enter key for Vigenère Cipher: ")
                    result = vigenere.decrypt(text, key)
                elif method_choice == 3:
                    result = base64_enc.decrypt1(text)
                elif method_choice == 4:
                    key = input("Enter key for AES Decryption: ")
                    result = aes.decrypt(text, key)
                elif method_choice == 5:
                    key = input("Enter key for DES Decryption: ")
                    result = safe_decrypt(des.decrypt, text, key)
                elif method_choice == 6:
                    private_key_path = input("Enter file path for private key for RSA Decryption: ")
                    result = rsa.decrypt(text, private_key_path)
                
                print("==================================")
                print(f"Decrypted text: {result}")
                print("==================================")

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    run()
