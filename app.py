"""
Hybrid Encryption System CLI Application
Implements RSA-2048 + AES-256-GCM encryption/decryption
"""

import os
import sys
from pathlib import Path
from crypto_utils import HybridCrypto


class EncryptionApp:
    """CLI application for hybrid encryption operations."""

    def __init__(self):
        """Initialize the encryption application."""
        self.crypto = HybridCrypto(keys_dir="keys")
        self.encrypted_dir = Path("encrypted")
        self.encrypted_dir.mkdir(exist_ok=True)

    def display_banner(self):
        """Display application banner."""
        print("\n" + "=" * 60)
        print("     HYBRID ENCRYPTION SYSTEM (RSA-2048 + AES-256-GCM)")
        print("=" * 60)

    def display_menu(self):
        """Display main menu options."""
        print("\n[MENU]")
        print("1. Generate RSA Keys (RSA-2048)")
        print("2. Encrypt File")
        print("3. Decrypt File")
        print("4. Exit")
        print("-" * 40)

    def option_generate_keys(self):
        """Generate RSA key pair."""
        print("\n" + "=" * 60)
        print("GENERATE RSA KEYS")
        print("=" * 60)

        if self.crypto.keys_exist():
            response = (
                input("\n[!] Keys already exist. Overwrite? (y/n): ").strip().lower()
            )
            if response != "y":
                print("[*] Key generation cancelled.")
                return

        if self.crypto.generate_rsa_keys():
            print("\n[SUCCESS] RSA key pair generated successfully!")
        else:
            print("\n[FAILED] Failed to generate RSA keys.")

    def option_encrypt_file(self):
        """Encrypt a file."""
        print("\n" + "=" * 60)
        print("ENCRYPT FILE")
        print("=" * 60)

        # Check if keys exist
        if not self.crypto.keys_exist():
            print("\n[-] Error: RSA keys not found!")
            print("[*] Please generate keys first (option 1)")
            return

        # Get input file
        input_file = input("\nEnter path to file to encrypt: ").strip()
        if not Path(input_file).exists():
            print(f"[-] File not found: {input_file}")
            return

        # Get output file name (default in encrypted/ directory)
        file_name = Path(input_file).name
        default_output = self.encrypted_dir / f"{file_name}.encrypted"

        output_prompt = f"Enter output file path [{default_output}]: ".strip()
        output_file = input(output_prompt).strip()

        if not output_file:
            output_file = str(default_output)

        # Ensure output directory exists
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if self.crypto.encrypt_file(input_file, output_file):
            print(f"\n[SUCCESS] File encrypted to: {output_file}")
        else:
            print("\n[FAILED] File encryption failed.")

    def option_decrypt_file(self):
        """Decrypt a file."""
        print("\n" + "=" * 60)
        print("DECRYPT FILE")
        print("=" * 60)

        # Check if keys exist
        if not self.crypto.keys_exist():
            print("\n[-] Error: RSA keys not found!")
            print("[*] Please generate keys first (option 1)")
            return

        # Get input file
        input_file = input("\nEnter path to encrypted file: ").strip()
        if not Path(input_file).exists():
            print(f"[-] File not found: {input_file}")
            return

        # Get output file name
        file_name = Path(input_file).stem  # Remove .encrypted extension if present
        default_output = Path("decrypted") / file_name

        output_prompt = f"Enter output file path [{default_output}]: ".strip()
        output_file = input(output_prompt).strip()

        if not output_file:
            output_file = str(default_output)

        # Ensure output directory exists
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if self.crypto.decrypt_file(input_file, output_file):
            print(f"\n[SUCCESS] File decrypted to: {output_file}")
        else:
            print("\n[FAILED] File decryption failed.")

    def run(self):
        """Run the application main loop."""
        self.display_banner()

        while True:
            self.display_menu()
            choice = input("Select option (1-4): ").strip()

            if choice == "1":
                self.option_generate_keys()
            elif choice == "2":
                self.option_encrypt_file()
            elif choice == "3":
                self.option_decrypt_file()
            elif choice == "4":
                print("\n[*] Exiting application. Goodbye!")
                sys.exit(0)
            else:
                print("[-] Invalid option. Please try again.")


def main():
    """Entry point for the application."""
    try:
        app = EncryptionApp()
        app.run()
    except KeyboardInterrupt:
        print("\n\n[*] Application interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
