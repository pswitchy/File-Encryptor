# File Encryptor

This Rust project provides a command-line tool to encrypt and decrypt files using AES-256-GCM with best practices for key derivation and authenticated encryption.

## Features

* **Strong Encryption:** Uses AES-256-GCM, a robust authenticated encryption algorithm.
* **Secure Key Derivation:** Derives encryption keys from passwords using PBKDF2 with a random salt, protecting against rainbow table attacks.
* **Unique Nonce:** Generates a random nonce for each encryption operation, ensuring ciphertext uniqueness.
* **Embedded Metadata:** Securely stores encryption parameters (salt and nonce) within the encrypted file for easy decryption.
* **User-Friendly CLI:** Provides a simple command-line interface with clear usage instructions.
* **Error Handling:** Includes comprehensive error handling to prevent data loss and improve user experience.

## Getting Started

### Prerequisites

* **Rust:** Install Rust using [rustup](https://rustup.rs/).

### Building

1. Clone the repository:

   ```bash
   git clone https://github.com/pswitchy/file-encryptor.git  
   cd file-encryptor
   ```

2. Build the project:

   ```bash
   cargo build --release  # For an optimized release build
   ```


**Encryption:**

```bash
cargo run -- encrypt -i "FileToBeEncrypted" -o output.enc -p "YourStrongPassword"
```

**Decryption:**

```bash
cargo run -- decrypt -i output.enc -o "DecryptedOutputFile" -p "YourStrongPassword"
```

## Security Considerations

* **Password Strength:** The security of your encrypted files depends entirely on the strength of your password. Use a long, complex password with a mix of uppercase and lowercase letters, numbers, and symbols.  Consider using a password manager.
* **Key Management:** *Never* store the encryption key directly with the data.
