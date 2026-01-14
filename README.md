# Hybrid Encryption System

A complete Python implementation of a hybrid encryption system using industry-standard cryptography.

## Features

- **RSA-2048**: Asymmetric encryption for key exchange
- **AES-256-GCM**: Symmetric encryption for file data
- **Hybrid Approach**: RSA encrypts the AES key; AES encrypts the actual file data
- **Universal File Support**: Handles text files, images, videos, and any binary format
- **Secure Defaults**: Proper use of OAEP padding with SHA-256 for RSA
- **Authenticated Encryption**: GCM mode provides both confidentiality and authenticity
- **CLI Menu Interface**: Easy-to-use command-line application

## Project Structure

```
hybrid_crypto_app/
├── app.py              # CLI application and menu interface
├── crypto_utils.py     # All cryptographic functions
├── requirements.txt    # Python dependencies
├── keys/               # Directory for RSA key pair
│   ├── private.pem     # RSA private key (generated)
│   └── public.pem      # RSA public key (generated)
├── encrypted/          # Directory for encrypted files
└── decrypted/          # Directory for decrypted files (created on use)
```

## Installation

### Prerequisites
- Python 3.7 or higher

### Setup

1. Navigate to the project directory:
```bash
cd hybrid_crypto_app
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Application

```bash
python app.py
```

### Menu Options

#### 1. Generate RSA Keys (RSA-2048)
- Generates a new RSA-2048 key pair
- Saves private key to `keys/private.pem` (with restricted 600 permissions)
- Saves public key to `keys/public.pem`
- **Note**: Generates unique keys each time (warns before overwriting)

#### 2. Encrypt File
- Encrypts any file type (text, image, video, binary, etc.)
- Process:
  1. Generates random AES-256 key
  2. Generates random 12-byte nonce
  3. Encrypts file with AES-256-GCM
  4. Encrypts AES key with RSA-2048 public key (OAEP + SHA-256)
  5. Saves encrypted file with format: `[key_length][encrypted_key][nonce][encrypted_data]`
- Supports custom output path or default to `encrypted/` directory

#### 3. Decrypt File
- Decrypts encrypted files
- Process:
  1. Reads encrypted file format
  2. Decrypts AES key with RSA-2048 private key
  3. Decrypts file data with AES-256-GCM
  4. Restores original file bit-perfectly
- Supports custom output path or default to `decrypted/` directory

#### 4. Exit
- Cleanly exits the application

## Encryption Format

The encrypted file format is structured as follows:

```
[4 bytes: Big-endian encrypted AES key length]
[N bytes: Encrypted AES-256 key (RSA OAEP with SHA-256)]
[12 bytes: AES-GCM nonce]
[M bytes: Encrypted file data (AES-256-GCM)]
```

This format allows for proper decryption of the AES key and subsequent file data.

## Cryptographic Details

### RSA-2048 Configuration
- **Key Size**: 2048 bits
- **Public Exponent**: 65537
- **Padding**: OAEP with SHA-256
- **Format**: PEM with PKCS8 encoding
- **Serialization**: Uses `cryptography` library's standard serialization

### AES-256-GCM Configuration
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes) - optimal for GCM
- **Authentication**: Built-in with GCM mode
- **Associated Data**: None (file data only)

### Security Properties
- **Confidentiality**: Provided by AES-256-GCM
- **Authenticity**: Provided by GCM authentication tag
- **Integrity**: Verified by GCM during decryption
- **Key Exchange**: RSA-2048 OAEP ensures secure AES key protection

## Code Quality

- **Clean Architecture**: Separation of concerns (crypto logic vs. CLI)
- **Error Handling**: Comprehensive exception handling with user-friendly messages
- **Reusable Functions**: Modular design for easy integration
- **No Hardcoded Secrets**: All cryptographic operations use random values
- **Well-Commented**: Clear documentation of all functions
- **Security Best Practices**: Proper use of cryptographic primitives

## Example Workflow

```
1. Start the application:
   python app.py

2. Generate RSA keys:
   Select option 1
   Keys generated: keys/private.pem, keys/public.pem

3. Encrypt a file:
   Select option 2
   Enter file path: /path/to/myfile.txt
   Output file: encrypted/myfile.txt.encrypted

4. Decrypt the file:
   Select option 3
   Enter encrypted file: encrypted/myfile.txt.encrypted
   Output file: decrypted/myfile.txt

5. Verify original and decrypted files are identical
```

## Security Considerations

### Keys
- **Private Key**: Stored with 600 permissions (readable only by owner)
- **Public Key**: Can be shared or distributed securely
- **Regeneration**: New keys override old ones (with confirmation)

### Encryption
- **Random AES Key**: Generated for each encryption operation
- **Random Nonce**: Generated for each encryption operation
- **No Key Reuse**: Each file gets unique encryption parameters

### File Integrity
- **GCM Authentication**: Detects any tampering or corruption
- **Decryption Verification**: Fails if file is corrupted or key is wrong
- **Bit-Perfect Restoration**: Original file is restored exactly

## Dependencies

- **cryptography** (>= 41.0.0): Industry-standard Python cryptography library
  - Provides secure implementations of RSA, AES, AESGCM
  - Uses OpenSSL backend
  - FIPS 140-2 compliant algorithms

## Limitations

- Single RSA key pair per installation (for this basic version)
- No key rotation mechanism (can be added)
- No batch encryption (processes one file at a time)
- No password protection on private key (can be added)

## Future Enhancements

- Support for password-protected private keys
- Batch file encryption/decryption
- File compression before encryption
- Key rotation utilities
- Digital signatures (RSA-PSS)
- Multi-recipient encryption

## Legal and Compliance

This implementation uses:
- **NIST-approved algorithms** (RSA-2048, AES-256, SHA-256)
- **Industry-standard cryptography library** (cryptography.io)
- **Proper cryptographic primitives** (no custom implementations)

## License

This code is provided as-is for educational and professional use.

## Support

For issues or questions:
1. Verify cryptography library is installed: `pip show cryptography`
2. Check that keys exist before encryption/decryption
3. Ensure files are readable/writable with proper permissions
4. Verify encrypted files haven't been tampered with

---

**Note**: This is a production-ready implementation suitable for real-world encryption scenarios. Always protect your private keys and backup important encrypted files.
