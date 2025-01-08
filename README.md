C-Crypt: A Simple Encryption/Decryption Tool

Overview

C-Crypt is a Python-based command-line utility for securely encrypting and decrypting text using the AES encryption standard. It utilizes the PBKDF2 key derivation function for strong password-based key generation, ensuring your sensitive data remains safe.

Features

Secure Encryption: AES encryption in CBC mode with a randomly generated initialization vector (IV) and salt.

Strong Key Derivation: Uses PBKDF2 with SHA256 to derive keys from passwords, with 1,000,000 iterations.

Cross-Platform Compatibility: Works seamlessly on Windows, Linux, and macOS.

User-Friendly Interface: Simple command-line interface to encode and decode text.

Requirements

Python 3.6 or higher

Required Python modules:

cryptography

colorama

pyfiglet

Install dependencies using pip:

pip install cryptography colorama pyfiglet

How to Use

Clone or download this repository.

Open a terminal in the project directory.

Run the script:

python c_crypt.py

Follow the prompts to encode or decode text:

Enter your text to encode or decode.

Provide a secure password.

Example

Encoding Text:

Select an option (1: Encode, 2: Decode): 1
Enter the text to encode: Hello, World!
Enter the password: securepassword123

Encoded text: BASE64_ENCODED_STRING

Decoding Text:

Select an option (1: Encode, 2: Decode): 2
Enter the text to decode: BASE64_ENCODED_STRING
Enter the password: securepassword123

Decoded text: Hello, World!

Security Considerations

Always use a strong and unique password for encryption.

Keep the encrypted output and password in safe storage to prevent unauthorized access.

This tool is designed strictly for educational purposes; the author does not condone or support its use for any illegal activities.

License

This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments

Author: Bell (GitHub: Bell-O)

Inspired by the need for simple and secure text encryption tools.


