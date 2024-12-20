# C-Crypt: A Simple Encryption/Decryption Tool

"""
C-Crypt is a Python-based command-line utility for securely encrypting and decrypting text using the AES encryption standard. 
It utilizes the PBKDF2 key derivation function for strong password-based key generation.

Author: Bell (github.com/Bell-O)
"""

import random
import base64
from colorama import Fore
import os, sys, subprocess, platform
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import pyfiglet

def clear():
    """Clears the console screen based on the user's operating system."""
    if platform.system() == "Windows":
        subprocess.Popen("cls", shell=True).communicate()
    else:  # Linux and Mac
        print("\033c", end="")

def derive_key(password, salt, iterations=1_000_000):
    """Derives a cryptographic key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(text, password):
    """Encrypts the provided text with a password."""
    salt = os.urandom(32)  # Larger salt for added randomness
    key = derive_key(password, salt, iterations=1_000_000)  # Stronger KDF
    iv = os.urandom(16)  # Random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    # Return all data encoded to avoid metadata leaks
    return base64.b64encode(salt + iv + ciphertext).decode()

def decrypt(encoded_text, password):
    """Decrypts the provided encoded text with a password."""
    decoded_data = base64.b64decode(encoded_text)
    salt = decoded_data[:32]  # Match larger salt size
    iv = decoded_data[32:48]
    ciphertext = decoded_data[48:]
    key = derive_key(password, salt, iterations=1_000_000)  # Match KDF settings
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpadder.update(padded_data) + unpadder.finalize()

def main():
    """Main function to handle user input and program flow."""
    print(Fore.GREEN + "---------------------------------------------------")
    print(Fore.WHITE + "")
    choice = input("Select an option (1: Encode, 2: Decode): ")
    print("")
    if choice == '1':
        input_text = input("Enter the text to encode: ")
        print("")
        password = input("Enter the password: ")
        print("")

        encrypted_text = encrypt(input_text, password)

        print("Encoded text:", encrypted_text)
        print("")
        main()

    elif choice == '2':
        input_text = input("Enter the text to decode: ")
        print("")
        password = input("Enter the password: ")
        print("")

        try:
            decrypted_text = decrypt(input_text, password).decode()
            print("Decoded text:", decrypted_text)
        except Exception as e:
            print("Decryption failed. Incorrect password or corrupted data.")

        print("")
        main()

    else:
        print("Invalid choice. Please try again.")
        print("")
        main()

# Clear the screen and display program title
clear()

text = "C-Crypt"

figlet_font = pyfiglet.Figlet(font="standard")
ascii_art = figlet_font.renderText(text)

print(ascii_art)
print(Fore.RED + "Made by Bell (github.com/Bell-O)")

if __name__ == "__main__":
    main()
