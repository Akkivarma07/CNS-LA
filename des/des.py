
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def des_encrypt(plain_text, key):
    """Encrypts plaintext using DES."""
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plain_text.encode(), DES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return encrypted_text

def des_decrypt(cipher_text, key):
    """Decrypts ciphertext using DES."""
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(cipher_text), DES.block_size)
    return decrypted_text.decode()

def main():
    """Main function with menu-driven options."""
    print("\nDES Encryption and Decryption")
    
    # Generate or input key
    key_option = input("Generate a new key (g) or enter an existing key (e)? (g/e): ")
    if key_option.lower() == 'g':
        key = get_random_bytes(8)
        print(f"\nGenerated Key (in hexadecimal): {key.hex()}")
    elif key_option.lower() == 'e':
        key_hex = input("Enter the key in hexadecimal: ")
        key = bytes.fromhex(key_hex)
    else:
        print("Invalid option. Exiting.")
        return

    while True:
        print("\nChoose an option:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            plain_text = input("Enter the plain text to encrypt: ")
            encrypted_text = des_encrypt(plain_text, key)
            print(f"\nEncrypted Text (in hexadecimal): {encrypted_text.hex()}")
        elif choice == '2':
            cipher_text_hex = input("Enter the cipher text in hexadecimal: ")
            cipher_text = bytes.fromhex(cipher_text_hex)
            decrypted_text = des_decrypt(cipher_text, key)
            print(f"\nDecrypted Text: {decrypted_text}")
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()