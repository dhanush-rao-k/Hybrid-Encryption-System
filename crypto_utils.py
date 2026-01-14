"""
Cryptography utilities for hybrid encryption system.
Implements RSA-2048 + AES-256-GCM hybrid encryption.
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class HybridCrypto:
    """Handles hybrid encryption/decryption operations."""

    # RSA Configuration
    RSA_KEY_SIZE = 2048
    RSA_PUBLIC_EXPONENT = 65537

    # AES Configuration
    AES_KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits for GCM

    def __init__(self, keys_dir: str = "keys"):
        """
        Initialize the crypto module.

        Args:
            keys_dir: Directory where RSA keys are stored.
        """
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)
        self.private_key_path = self.keys_dir / "private.pem"
        self.public_key_path = self.keys_dir / "public.pem"
        self.private_key = None
        self.public_key = None

    def generate_rsa_keys(self) -> bool:
        """
        Generate RSA-2048 key pair and save to files.

        Returns:
            True if successful, False otherwise.
        """
        try:
            print(f"\n[*] Generating RSA-2048 key pair...")

            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=self.RSA_PUBLIC_EXPONENT,
                key_size=self.RSA_KEY_SIZE,
                backend=default_backend(),
            )

            # Extract public key
            public_key = private_key.public_key()

            # Serialize private key to PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Serialize public key to PEM format
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Save to files
            with open(self.private_key_path, "wb") as f:
                f.write(private_pem)
            os.chmod(self.private_key_path, 0o600)  # Restrictive permissions

            with open(self.public_key_path, "wb") as f:
                f.write(public_pem)

            self.private_key = private_key
            self.public_key = public_key

            print(f"[+] Keys generated successfully!")
            print(f"[+] Private key: {self.private_key_path}")
            print(f"[+] Public key: {self.public_key_path}")
            return True

        except Exception as e:
            print(f"[-] Error generating RSA keys: {e}")
            return False

    def load_private_key(self) -> bool:
        """
        Load RSA private key from file.

        Returns:
            True if successful, False otherwise.
        """
        try:
            if not self.private_key_path.exists():
                print(f"[-] Private key not found at {self.private_key_path}")
                return False

            with open(self.private_key_path, "rb") as f:
                private_pem = f.read()

            self.private_key = serialization.load_pem_private_key(
                private_pem, password=None, backend=default_backend()
            )
            return True

        except Exception as e:
            print(f"[-] Error loading private key: {e}")
            return False

    def load_public_key(self) -> bool:
        """
        Load RSA public key from file.

        Returns:
            True if successful, False otherwise.
        """
        try:
            if not self.public_key_path.exists():
                print(f"[-] Public key not found at {self.public_key_path}")
                return False

            with open(self.public_key_path, "rb") as f:
                public_pem = f.read()

            self.public_key = serialization.load_pem_public_key(
                public_pem, backend=default_backend()
            )
            return True

        except Exception as e:
            print(f"[-] Error loading public key: {e}")
            return False

    def _generate_aes_key(self) -> bytes:
        """
        Generate a random AES-256 key.

        Returns:
            32-byte random key for AES-256.
        """
        return os.urandom(self.AES_KEY_SIZE)

    def _generate_nonce(self) -> bytes:
        """
        Generate a random nonce for AES-GCM.

        Returns:
            12-byte random nonce for GCM.
        """
        return os.urandom(self.NONCE_SIZE)

    def encrypt_file(self, input_file: str, output_file: str) -> bool:
        """
        Encrypt a file using hybrid encryption.

        Process:
        1. Generate random AES-256 key
        2. Generate random nonce
        3. Encrypt file data with AES-256-GCM
        4. Encrypt AES key with RSA public key (OAEP + SHA-256)
        5. Write output format: [key_len][encrypted_key][nonce][encrypted_data]

        Args:
            input_file: Path to input file to encrypt.
            output_file: Path to output encrypted file.

        Returns:
            True if successful, False otherwise.
        """
        try:
            # Load public key if not already loaded
            if self.public_key is None:
                if not self.load_public_key():
                    return False

            print(f"\n[*] Encrypting file: {input_file}")

            # Read input file
            input_path = Path(input_file)
            if not input_path.exists():
                print(f"[-] Input file not found: {input_file}")
                return False

            with open(input_path, "rb") as f:
                plaintext = f.read()

            print(f"[*] File size: {len(plaintext)} bytes")

            # Generate AES key and nonce
            aes_key = self._generate_aes_key()
            nonce = self._generate_nonce()

            # Encrypt data with AES-256-GCM
            cipher = AESGCM(aes_key)
            ciphertext = cipher.encrypt(nonce, plaintext, None)

            # Encrypt AES key with RSA public key (OAEP + SHA-256)
            encrypted_aes_key = self.public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Write encrypted file format
            output_path = Path(output_file)
            with open(output_path, "wb") as f:
                # Write encrypted AES key length (4 bytes, big-endian)
                key_length = len(encrypted_aes_key).to_bytes(4, byteorder="big")
                f.write(key_length)

                # Write encrypted AES key
                f.write(encrypted_aes_key)

                # Write nonce (12 bytes)
                f.write(nonce)

                # Write encrypted data
                f.write(ciphertext)

            print(f"[+] File encrypted successfully!")
            print(f"[+] Output: {output_file}")
            print(f"[+] Encrypted file size: {output_path.stat().st_size} bytes")
            return True

        except Exception as e:
            print(f"[-] Error encrypting file: {e}")
            return False

    def encrypt_file_with_public_key(
        self, input_file: str, output_file: str, public_key_path: str
    ) -> bool:
        """
        Encrypt a file using an external public key.

        This allows encryption-only mode when you only have someone's public key.
        You can encrypt files that only they can decrypt with their private key.

        Args:
            input_file: Path to input file to encrypt.
            output_file: Path to output encrypted file.
            public_key_path: Path to external public key file (.pem).

        Returns:
            True if successful, False otherwise.
        """
        try:
            print(f"\n[*] Encrypting file with external public key: {input_file}")

            # Load external public key
            public_key_path_obj = Path(public_key_path)
            if not public_key_path_obj.exists():
                print(f"[-] Public key file not found: {public_key_path}")
                return False

            with open(public_key_path_obj, "rb") as f:
                public_pem = f.read()

            external_public_key = serialization.load_pem_public_key(
                public_pem, backend=default_backend()
            )

            # Read input file
            input_path = Path(input_file)
            if not input_path.exists():
                print(f"[-] Input file not found: {input_file}")
                return False

            with open(input_path, "rb") as f:
                plaintext = f.read()

            print(f"[*] File size: {len(plaintext)} bytes")

            # Generate AES key and nonce
            aes_key = self._generate_aes_key()
            nonce = self._generate_nonce()

            # Encrypt data with AES-256-GCM
            cipher = AESGCM(aes_key)
            ciphertext = cipher.encrypt(nonce, plaintext, None)

            # Encrypt AES key with external RSA public key (OAEP + SHA-256)
            encrypted_aes_key = external_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Write encrypted file format
            output_path = Path(output_file)
            with open(output_path, "wb") as f:
                # Write encrypted AES key length (4 bytes, big-endian)
                key_length = len(encrypted_aes_key).to_bytes(4, byteorder="big")
                f.write(key_length)

                # Write encrypted AES key
                f.write(encrypted_aes_key)

                # Write nonce (12 bytes)
                f.write(nonce)

                # Write encrypted data
                f.write(ciphertext)

            print(f"[+] File encrypted successfully!")
            print(f"[+] Output: {output_file}")
            print(f"[+] Encrypted file size: {output_path.stat().st_size} bytes")
            return True

        except Exception as e:
            print(f"[-] Error encrypting file: {e}")
            return False

    def decrypt_file(self, input_file: str, output_file: str) -> bool:
        """
        Decrypt a file using hybrid decryption.

        Process:
        1. Read encrypted file format: [key_len][encrypted_key][nonce][encrypted_data]
        2. Decrypt AES key with RSA private key
        3. Decrypt file data with AES-256-GCM
        4. Write decrypted data to output file

        Args:
            input_file: Path to encrypted file.
            output_file: Path to output decrypted file.

        Returns:
            True if successful, False otherwise.
        """
        try:
            # Load private key if not already loaded
            if self.private_key is None:
                if not self.load_private_key():
                    return False

            print(f"\n[*] Decrypting file: {input_file}")

            # Read encrypted file
            input_path = Path(input_file)
            if not input_path.exists():
                print(f"[-] Input file not found: {input_file}")
                return False

            with open(input_path, "rb") as f:
                # Read encrypted AES key length (4 bytes, big-endian)
                key_length_bytes = f.read(4)
                if len(key_length_bytes) < 4:
                    print("[-] Invalid encrypted file format (too short)")
                    return False

                key_length = int.from_bytes(key_length_bytes, byteorder="big")

                # Read encrypted AES key
                encrypted_aes_key = f.read(key_length)
                if len(encrypted_aes_key) < key_length:
                    print("[-] Invalid encrypted file format (incomplete key)")
                    return False

                # Read nonce (12 bytes)
                nonce = f.read(self.NONCE_SIZE)
                if len(nonce) < self.NONCE_SIZE:
                    print("[-] Invalid encrypted file format (missing nonce)")
                    return False

                # Read encrypted data
                ciphertext = f.read()

            print(f"[*] Encrypted file size: {input_path.stat().st_size} bytes")

            # Decrypt AES key with RSA private key
            try:
                aes_key = self.private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            except Exception as e:
                print(f"[-] Failed to decrypt AES key: {e}")
                print("[-] This may indicate the wrong private key or corrupted file")
                return False

            # Decrypt data with AES-256-GCM
            try:
                cipher = AESGCM(aes_key)
                plaintext = cipher.decrypt(nonce, ciphertext, None)
            except Exception as e:
                print(f"[-] Failed to decrypt file data: {e}")
                print("[-] File may be corrupted or authentication failed")
                return False

            # Write decrypted file
            output_path = Path(output_file)
            with open(output_path, "wb") as f:
                f.write(plaintext)

            print(f"[+] File decrypted successfully!")
            print(f"[+] Output: {output_file}")
            print(f"[+] Decrypted file size: {len(plaintext)} bytes")
            return True

        except Exception as e:
            print(f"[-] Error decrypting file: {e}")
            return False

    def keys_exist(self) -> bool:
        """Check if RSA keys exist."""
        return self.private_key_path.exists() and self.public_key_path.exists()
