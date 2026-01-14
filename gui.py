"""
Hybrid Encryption System - GUI Application with Tkinter
Provides drag-and-drop file encryption/decryption with clipboard support
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import sys
from pathlib import Path
from crypto_utils import HybridCrypto
import threading
import base64

# Try to import tkinterdnd2 for drag-and-drop, fallback to click-based selection
try:
    from tkinterdnd2 import DND_FILES, getdraggedfiles
    DRAG_DROP_AVAILABLE = True
except ImportError:
    DRAG_DROP_AVAILABLE = False


class EncryptionGUI:
    """GUI Application for hybrid encryption using tkinter."""

    def __init__(self, root):
        """Initialize the GUI application."""
        self.root = root
        self.root.title("Hybrid Encryption System")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # Initialize crypto
        self.crypto = HybridCrypto(keys_dir="keys")

        # Color scheme
        self.bg_color = "#2b2b2b"
        self.fg_color = "#ffffff"
        self.accent_color = "#007acc"
        self.success_color = "#00aa00"
        self.error_color = "#ff4444"

        self.root.configure(bg=self.bg_color)

        # Configure styles
        self.setup_styles()

        # Build GUI
        self.build_gui()

        # Check if keys exist
        self.check_keys()

    def setup_styles(self):
        """Configure tkinter styles."""
        style = ttk.Style()
        style.theme_use("clam")

        # Configure dark theme
        style.configure(
            "TFrame",
            background=self.bg_color,
            foreground=self.fg_color,
        )
        style.configure(
            "TLabel",
            background=self.bg_color,
            foreground=self.fg_color,
        )
        style.configure(
            "TButton",
            background=self.accent_color,
            foreground=self.fg_color,
            borderwidth=1,
            focuscolor="none",
        )
        style.map(
            "TButton",
            background=[("active", "#0099cc"), ("pressed", "#005a99")],
        )

    def build_gui(self):
        """Build the GUI interface."""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Header
        self.build_header(main_frame)

        # Key management section
        self.build_key_section(main_frame)

        # Notebook (tabs)
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        # Tab 1: Encrypt File
        self.build_encrypt_file_tab(notebook)

        # Tab 2: Encrypt Text
        self.build_encrypt_text_tab(notebook)

        # Tab 3: Decrypt File
        self.build_decrypt_file_tab(notebook)

        # Tab 4: Decrypt Text
        self.build_decrypt_text_tab(notebook)

        # Status bar
        self.build_status_bar(main_frame)

    def build_header(self, parent):
        """Build the header section."""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        title_label = ttk.Label(
            header_frame,
            text="🔐 Hybrid Encryption System",
            font=("Arial", 16, "bold"),
        )
        title_label.pack(side=tk.LEFT)

        subtitle_label = ttk.Label(
            header_frame,
            text="RSA-2048 + AES-256-GCM",
            font=("Arial", 10),
        )
        subtitle_label.pack(side=tk.LEFT, padx=20)

    def build_key_section(self, parent):
        """Build the key management section."""
        key_frame = ttk.LabelFrame(parent, text="Key Management", padding=10)
        key_frame.pack(fill=tk.X, pady=10)

        button_frame = ttk.Frame(key_frame)
        button_frame.pack(fill=tk.X)

        self.generate_btn = ttk.Button(
            button_frame,
            text="Generate RSA Keys",
            command=self.generate_keys,
        )
        self.generate_btn.pack(side=tk.LEFT, padx=5)

        self.export_btn = ttk.Button(
            button_frame,
            text="Export Public Key",
            command=self.export_public_key,
        )
        self.export_btn.pack(side=tk.LEFT, padx=5)

        self.import_btn = ttk.Button(
            button_frame,
            text="Import Public Key",
            command=self.import_public_key,
        )
        self.import_btn.pack(side=tk.LEFT, padx=5)

        self.key_status_label = ttk.Label(
            button_frame, text="Keys: Not found", foreground=self.error_color
        )
        self.key_status_label.pack(side=tk.LEFT, padx=10)

    def build_encrypt_file_tab(self, parent):
        """Build the encrypt file tab."""
        frame = ttk.Frame(parent, padding=10)
        parent.add(frame, text="📁 Encrypt File")

        # Drag and drop area
        drag_frame = tk.Frame(
            frame, bg="#3d3d3d", relief=tk.SUNKEN, borderwidth=2
        )
        drag_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.encrypt_file_label = tk.Label(
            drag_frame,
            text="Drag and drop a file here\nor click to select",
            bg="#3d3d3d",
            fg="#888888",
            font=("Arial", 14),
        )
        self.encrypt_file_label.pack(fill=tk.BOTH, expand=True)

        # Make it a drop target
        self.encrypt_file_path = tk.StringVar()
        self.setup_drop_target(self.encrypt_file_label, self.on_encrypt_file_drop)

        # Click to select
        self.encrypt_file_label.bind("<Button-1>", self.on_encrypt_file_click)

        # File path display
        path_frame = ttk.Frame(frame)
        path_frame.pack(fill=tk.X, pady=10)

        ttk.Label(path_frame, text="File:").pack(side=tk.LEFT)
        ttk.Label(path_frame, text="None selected", textvariable=self.encrypt_file_path).pack(
            side=tk.LEFT, padx=5
        )

        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)

        self.encrypt_file_btn = ttk.Button(
            button_frame,
            text="Encrypt File",
            command=self.encrypt_file,
        )
        self.encrypt_file_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="Encrypt as Text (Base64)",
            command=self.encrypt_file_as_base64,
        ).pack(side=tk.LEFT, padx=5)

    def build_encrypt_text_tab(self, parent):
        """Build the encrypt text tab."""
        frame = ttk.Frame(parent, padding=10)
        parent.add(frame, text="📝 Encrypt Text")

        # Input section
        input_label = ttk.Label(frame, text="Enter text to encrypt:", font=("Arial", 10, "bold"))
        input_label.pack(anchor=tk.W, pady=(0, 5))

        # Text input
        self.encrypt_text_input = tk.Text(
            frame, height=8, width=60, bg="#3d3d3d", fg="#ffffff", insertbackground="white"
        )
        self.encrypt_text_input.pack(fill=tk.BOTH, expand=True, pady=5)

        # Paste button
        paste_frame = ttk.Frame(frame)
        paste_frame.pack(fill=tk.X, pady=5)

        ttk.Button(
            paste_frame,
            text="📋 Paste",
            command=self.paste_encrypt_text,
        ).pack(side=tk.LEFT, padx=2)

        ttk.Button(
            paste_frame,
            text="🗑️ Clear",
            command=lambda: self.encrypt_text_input.delete("1.0", tk.END),
        ).pack(side=tk.LEFT, padx=2)

        # Output section
        output_label = ttk.Label(
            frame, text="Encrypted output (Base64):", font=("Arial", 10, "bold")
        )
        output_label.pack(anchor=tk.W, pady=(10, 5))

        # Text output
        self.encrypt_text_output = tk.Text(
            frame, height=6, width=60, bg="#3d3d3d", fg="#00ff00", state=tk.DISABLED
        )
        self.encrypt_text_output.pack(fill=tk.BOTH, expand=True, pady=5)

        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            button_frame,
            text="🔒 Encrypt",
            command=self.encrypt_text,
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="📋 Copy",
            command=self.copy_encrypt_text,
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="💾 Save",
            command=self.save_encrypt_text,
        ).pack(side=tk.LEFT, padx=5)

    def build_decrypt_file_tab(self, parent):
        """Build the decrypt file tab."""
        frame = ttk.Frame(parent, padding=10)
        parent.add(frame, text="📁 Decrypt File")

        # Drag and drop area
        drag_frame = tk.Frame(
            frame, bg="#3d3d3d", relief=tk.SUNKEN, borderwidth=2
        )
        drag_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.decrypt_file_label = tk.Label(
            drag_frame,
            text="Drag and drop encrypted file here\nor click to select",
            bg="#3d3d3d",
            fg="#888888",
            font=("Arial", 14),
        )
        self.decrypt_file_label.pack(fill=tk.BOTH, expand=True)

        # Make it a drop target
        self.decrypt_file_path = tk.StringVar()
        self.setup_drop_target(self.decrypt_file_label, self.on_decrypt_file_drop)

        # Click to select
        self.decrypt_file_label.bind("<Button-1>", self.on_decrypt_file_click)

        # File path display
        path_frame = ttk.Frame(frame)
        path_frame.pack(fill=tk.X, pady=10)

        ttk.Label(path_frame, text="File:").pack(side=tk.LEFT)
        ttk.Label(path_frame, text="None selected", textvariable=self.decrypt_file_path).pack(
            side=tk.LEFT, padx=5
        )

        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)

        self.decrypt_file_btn = ttk.Button(
            button_frame,
            text="Decrypt File",
            command=self.decrypt_file,
        )
        self.decrypt_file_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="Decrypt from Text (Base64)",
            command=self.decrypt_file_from_base64,
        ).pack(side=tk.LEFT, padx=5)

    def build_decrypt_text_tab(self, parent):
        """Build the decrypt text tab."""
        frame = ttk.Frame(parent, padding=10)
        parent.add(frame, text="📝 Decrypt Text")

        # Input section
        input_label = ttk.Label(
            frame, text="Enter encrypted text (Base64):", font=("Arial", 10, "bold")
        )
        input_label.pack(anchor=tk.W, pady=(0, 5))

        # Text input
        self.decrypt_text_input = tk.Text(
            frame, height=8, width=60, bg="#3d3d3d", fg="#ffffff", insertbackground="white"
        )
        self.decrypt_text_input.pack(fill=tk.BOTH, expand=True, pady=5)

        # Paste button
        paste_frame = ttk.Frame(frame)
        paste_frame.pack(fill=tk.X, pady=5)

        ttk.Button(
            paste_frame,
            text="📋 Paste",
            command=self.paste_decrypt_text,
        ).pack(side=tk.LEFT, padx=2)

        ttk.Button(
            paste_frame,
            text="🗑️ Clear",
            command=lambda: self.decrypt_text_input.delete("1.0", tk.END),
        ).pack(side=tk.LEFT, padx=2)

        # Output section
        output_label = ttk.Label(
            frame, text="Decrypted output:", font=("Arial", 10, "bold")
        )
        output_label.pack(anchor=tk.W, pady=(10, 5))

        # Text output
        self.decrypt_text_output = tk.Text(
            frame, height=6, width=60, bg="#3d3d3d", fg="#00ff00", state=tk.DISABLED
        )
        self.decrypt_text_output.pack(fill=tk.BOTH, expand=True, pady=5)

        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            button_frame,
            text="🔓 Decrypt",
            command=self.decrypt_text,
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="📋 Copy",
            command=self.copy_decrypt_text,
        ).pack(side=tk.LEFT, padx=5)

    def build_status_bar(self, parent):
        """Build the status bar."""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(10, 0))

        self.status_label = ttk.Label(
            status_frame, text="Ready", relief=tk.SUNKEN, font=("Arial", 9)
        )
        self.status_label.pack(fill=tk.X)

    def setup_drop_target(self, widget, callback):
        """Make a widget a drop target for files."""
        if DRAG_DROP_AVAILABLE:
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", callback)
        # If drag-drop not available, click-based selection is used instead

    def check_keys(self):
        """Check if RSA keys exist and update status."""
        if self.crypto.keys_exist():
            self.key_status_label.config(
                text="Keys: Found ✓", foreground=self.success_color
            )
            self.set_status("Keys loaded successfully")
        else:
            self.key_status_label.config(
                text="Keys: Not found", foreground=self.error_color
            )
            self.set_status("Please generate RSA keys first")

    def generate_keys(self):
        """Generate RSA keys in a separate thread."""
        if self.crypto.keys_exist():
            response = messagebox.askyesno(
                "Overwrite Keys",
                "RSA keys already exist. Do you want to overwrite them?",
            )
            if not response:
                return

        def generate():
            self.generate_btn.config(state=tk.DISABLED)
            self.set_status("Generating RSA-2048 keys...")
            try:
                if self.crypto.generate_rsa_keys():
                    self.check_keys()
                    self.set_status("Keys generated successfully!")
                    messagebox.showinfo(
                        "Success",
                        "RSA-2048 keys generated successfully!\n\nPrivate key: keys/private.pem\nPublic key: keys/public.pem",
                    )
                else:
                    self.set_status("Failed to generate keys")
                    messagebox.showerror("Error", "Failed to generate RSA keys")
            finally:
                self.generate_btn.config(state=tk.NORMAL)

        thread = threading.Thread(target=generate, daemon=True)
        thread.start()

    def export_public_key(self):
        """Export public key to file for sharing."""
        if not self.crypto.keys_exist():
            messagebox.showerror("Error", "Please generate RSA keys first")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="public_key.pem",
        )

        if not file_path:
            return

        try:
            # Copy public key to selected location
            import shutil
            shutil.copy(self.crypto.public_key_path, file_path)
            self.set_status(f"Public key exported to {Path(file_path).name}")
            messagebox.showinfo(
                "Success",
                f"Public key exported successfully!\n\n{file_path}\n\nYou can share this file with others for encryption.",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export public key: {e}")
            self.set_status("Export failed")

    def import_public_key(self):
        """Import public key for encryption-only mode."""
        file_path = filedialog.askopenfilename(
            title="Select public key file to import",
            filetypes=[("PEM files", "*.pem"), ("Text files", "*.txt"), ("All files", "*.*")],
        )

        if not file_path:
            return

        try:
            # Store imported public key path
            self._imported_public_key_path = file_path
            key_name = Path(file_path).name
            self.key_status_label.config(
                text=f"Imported: {key_name}", foreground=self.success_color
            )
            self.set_status(f"Public key imported: {key_name}")
            messagebox.showinfo(
                "Success",
                f"Public key imported successfully!\n\n{file_path}\n\nYou can now encrypt files with this key.",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import public key: {e}")
            self.set_status("Import failed")

    def on_encrypt_file_click(self, event):
        """Handle click on encrypt file drop area."""
        file_path = filedialog.askopenfilename(
            title="Select file to encrypt",
            filetypes=[("All files", "*.*")],
        )
        if file_path:
            self.encrypt_file_path.set(Path(file_path).name)
            self.encrypt_file_label.config(
                text=f"✓ Selected: {Path(file_path).name}",
                fg="#00ff00",
            )
            self._encrypt_file_path = file_path

    def on_encrypt_file_drop(self, event):
        """Handle file drop on encrypt file area."""
        files = getdraggedfiles(event)
        if files:
            self._encrypt_file_path = files[0]
            self.encrypt_file_path.set(Path(files[0]).name)
            self.encrypt_file_label.config(
                text=f"✓ Dropped: {Path(files[0]).name}",
                fg="#00ff00",
            )

    def on_decrypt_file_click(self, event):
        """Handle click on decrypt file drop area."""
        file_path = filedialog.askopenfilename(
            title="Select encrypted file to decrypt",
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")],
        )
        if file_path:
            self.decrypt_file_path.set(Path(file_path).name)
            self.decrypt_file_label.config(
                text=f"✓ Selected: {Path(file_path).name}",
                fg="#00ff00",
            )
            self._decrypt_file_path = file_path

    def on_decrypt_file_drop(self, event):
        """Handle file drop on decrypt file area."""
        files = getdraggedfiles(event)
        if files:
            self._decrypt_file_path = files[0]
            self.decrypt_file_path.set(Path(files[0]).name)
            self.decrypt_file_label.config(
                text=f"✓ Dropped: {Path(files[0]).name}",
                fg="#00ff00",
            )

    def encrypt_file(self):
        """Encrypt selected file in a separate thread."""
        # Check if we have either local keys or imported public key
        has_local_keys = self.crypto.keys_exist()
        has_imported_key = hasattr(self, "_imported_public_key_path")

        if not has_local_keys and not has_imported_key:
            messagebox.showerror(
                "Error",
                "Please generate RSA keys first or import a public key",
            )
            return

        if not hasattr(self, "_encrypt_file_path"):
            messagebox.showerror("Error", "Please select a file to encrypt")
            return

        output_path = filedialog.asksaveasfilename(
            defaultextension=".encrypted",
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")],
            initialfile=f"{Path(self._encrypt_file_path).name}.encrypted",
        )

        if not output_path:
            return

        def encrypt():
            self.encrypt_file_btn.config(state=tk.DISABLED)
            self.set_status(f"Encrypting {Path(self._encrypt_file_path).name}...")
            try:
                # Use imported key if available, otherwise use local key
                if has_imported_key:
                    # Encrypt using imported public key
                    if self.crypto.encrypt_file_with_public_key(
                        self._encrypt_file_path, output_path, self._imported_public_key_path
                    ):
                        self.set_status(f"File encrypted: {Path(output_path).name}")
                        messagebox.showinfo(
                            "Success",
                            f"File encrypted successfully!\n\n{output_path}",
                        )
                    else:
                        self.set_status("Encryption failed")
                        messagebox.showerror("Error", "Failed to encrypt file")
                else:
                    # Encrypt using local keys
                    if self.crypto.encrypt_file(self._encrypt_file_path, output_path):
                        self.set_status(f"File encrypted: {Path(output_path).name}")
                        messagebox.showinfo(
                            "Success",
                            f"File encrypted successfully!\n\n{output_path}",
                        )
                    else:
                        self.set_status("Encryption failed")
                        messagebox.showerror("Error", "Failed to encrypt file")
            finally:
                self.encrypt_file_btn.config(state=tk.NORMAL)

        thread = threading.Thread(target=encrypt, daemon=True)
        thread.start()

    def encrypt_file_as_base64(self):
        """Encrypt file and encode as Base64 text for messaging apps (WhatsApp, etc)."""
        # Check if we have either local keys or imported public key
        has_local_keys = self.crypto.keys_exist()
        has_imported_key = hasattr(self, "_imported_public_key_path")

        if not has_local_keys and not has_imported_key:
            messagebox.showerror(
                "Error",
                "Please generate RSA keys first or import a public key",
            )
            return

        if not hasattr(self, "_encrypt_file_path"):
            messagebox.showerror("Error", "Please select a file to encrypt")
            return

        output_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"{Path(self._encrypt_file_path).name}.encrypted.txt",
        )

        if not output_path:
            return

        def encrypt():
            self.encrypt_file_btn.config(state=tk.DISABLED)
            self.set_status(f"Encrypting and converting to Base64...")
            try:
                import tempfile
                
                # Create temp encrypted file
                with tempfile.NamedTemporaryFile(delete=False, suffix=".encrypted") as tmp:
                    tmp_encrypted = tmp.name
                
                try:
                    # Encrypt to temp file
                    if has_imported_key:
                        success = self.crypto.encrypt_file_with_public_key(
                            self._encrypt_file_path, tmp_encrypted, self._imported_public_key_path
                        )
                    else:
                        success = self.crypto.encrypt_file(self._encrypt_file_path, tmp_encrypted)
                    
                    if success:
                        # Read encrypted file and encode to Base64
                        with open(tmp_encrypted, "rb") as f:
                            encrypted_data = f.read()
                        
                        encrypted_b64 = base64.b64encode(encrypted_data).decode("utf-8")
                        
                        # Save Base64 as text file
                        with open(output_path, "w") as f:
                            f.write(encrypted_b64)
                        
                        self.set_status(f"✓ File encrypted as text: {Path(output_path).name}")
                        messagebox.showinfo(
                            "Success",
                            f"File encrypted and saved as Base64 text!\n\n"
                            f"Can now be safely sent via WhatsApp, email, etc.\n\n{output_path}",
                        )
                    else:
                        self.set_status("Encryption failed")
                        messagebox.showerror("Error", "Failed to encrypt file")
                finally:
                    # Clean up temp file
                    if os.path.exists(tmp_encrypted):
                        os.remove(tmp_encrypted)
            finally:
                self.encrypt_file_btn.config(state=tk.NORMAL)

        thread = threading.Thread(target=encrypt, daemon=True)
        thread.start()

    def decrypt_file(self):
        """Decrypt selected file in a separate thread."""
        if not self.crypto.keys_exist():
            messagebox.showerror("Error", "Please generate RSA keys first")
            return

        if not hasattr(self, "_decrypt_file_path"):
            messagebox.showerror("Error", "Please select a file to decrypt")
            return

        output_path = filedialog.asksaveasfilename(
            filetypes=[("All files", "*.*")],
            initialfile=Path(self._decrypt_file_path).stem,
        )

        if not output_path:
            return

        def decrypt():
            self.decrypt_file_btn.config(state=tk.DISABLED)
            self.set_status(f"Decrypting {Path(self._decrypt_file_path).name}...")
            try:
                if self.crypto.decrypt_file(self._decrypt_file_path, output_path):
                    self.set_status(f"✓ File decrypted: {Path(output_path).name}")
                    messagebox.showinfo(
                        "Success",
                        f"File decrypted successfully!\n\n{output_path}",
                    )
                else:
                    self.set_status("Decryption failed")
                    messagebox.showerror("Error", "Failed to decrypt file")
            finally:
                self.decrypt_file_btn.config(state=tk.NORMAL)

        thread = threading.Thread(target=decrypt, daemon=True)
        thread.start()

    def decrypt_file_from_base64(self):
        """Decrypt file from Base64 text (received from messaging apps)."""
        if not self.crypto.keys_exist():
            messagebox.showerror("Error", "Please generate RSA keys first")
            return

        # Ask for Base64 file
        base64_file = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )

        if not base64_file:
            return

        output_path = filedialog.asksaveasfilename(
            filetypes=[("All files", "*.*")],
        )

        if not output_path:
            return

        def decrypt():
            self.decrypt_file_btn.config(state=tk.DISABLED)
            self.set_status("Decoding from Base64 and decrypting...")
            try:
                import tempfile
                
                # Read Base64 file
                with open(base64_file, "r") as f:
                    encrypted_b64 = f.read().strip()
                
                # Remove any whitespace/newlines that might have been added
                encrypted_b64 = ''.join(encrypted_b64.split())
                
                # Decode from Base64
                try:
                    encrypted_data = base64.b64decode(encrypted_b64, validate=True)
                except Exception as decode_err:
                    self.set_status("Error: Invalid Base64 format")
                    messagebox.showerror("Error", f"Failed to decode Base64: {str(decode_err)}")
                    return
                
                # Create temp encrypted file
                with tempfile.NamedTemporaryFile(delete=False, suffix=".encrypted") as tmp:
                    tmp.write(encrypted_data)
                    tmp_encrypted = tmp.name
                
                try:
                    # Decrypt temp file
                    if self.crypto.decrypt_file(tmp_encrypted, output_path):
                        self.set_status(f"✓ File decrypted: {Path(output_path).name}")
                        messagebox.showinfo(
                            "Success",
                            f"File decrypted successfully!\n\n{output_path}",
                        )
                    else:
                        self.set_status("Decryption failed - check private key")
                        messagebox.showerror("Error", "Failed to decrypt file.\n\nPossible reasons:\n- Wrong file\n- Private key mismatch\n- File corruption")
                finally:
                    # Clean up temp file
                    if os.path.exists(tmp_encrypted):
                        os.remove(tmp_encrypted)
            except Exception as e:
                self.set_status(f"Error: {str(e)}")
                messagebox.showerror("Error", f"Decryption error: {str(e)}")
            finally:
                self.decrypt_file_btn.config(state=tk.NORMAL)

        thread = threading.Thread(target=decrypt, daemon=True)
        thread.start()

    def encrypt_text(self):
        """Encrypt text from input area."""
        if not self.crypto.keys_exist():
            messagebox.showerror("Error", "Please generate RSA keys first")
            return

        text = self.encrypt_text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "Please enter text to encrypt")
            return

        def encrypt():
            self.set_status("Encrypting text...")
            try:
                # Convert text to bytes
                plaintext = text.encode("utf-8")

                # Create a temporary file for encryption
                import tempfile
                import base64

                with tempfile.NamedTemporaryFile(delete=False) as tmp_in:
                    tmp_in.write(plaintext)
                    tmp_in_path = tmp_in.name

                with tempfile.NamedTemporaryFile(delete=False, suffix=".encrypted") as tmp_out:
                    tmp_out_path = tmp_out.name

                try:
                    # Encrypt
                    if self.crypto.encrypt_file(tmp_in_path, tmp_out_path):
                        # Read encrypted file and encode to base64
                        with open(tmp_out_path, "rb") as f:
                            encrypted_data = f.read()
                        encrypted_b64 = base64.b64encode(encrypted_data).decode("utf-8")

                        # Display output
                        self.encrypt_text_output.config(state=tk.NORMAL)
                        self.encrypt_text_output.delete("1.0", tk.END)
                        self.encrypt_text_output.insert("1.0", encrypted_b64)
                        self.encrypt_text_output.config(state=tk.DISABLED)

                        self.set_status("✓ Text encrypted successfully")
                    else:
                        messagebox.showerror("Error", "Failed to encrypt text")
                        self.set_status("Encryption failed")
                finally:
                    # Clean up
                    Path(tmp_in_path).unlink(missing_ok=True)
                    Path(tmp_out_path).unlink(missing_ok=True)
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
                self.set_status("Encryption failed")

        thread = threading.Thread(target=encrypt, daemon=True)
        thread.start()

    def decrypt_text(self):
        """Decrypt text from input area."""
        if not self.crypto.keys_exist():
            messagebox.showerror("Error", "Please generate RSA keys first")
            return

        text = self.decrypt_text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "Please enter encrypted text to decrypt")
            return

        def decrypt():
            self.set_status("Decrypting text...")
            try:
                import tempfile
                import base64

                # Decode from base64
                try:
                    encrypted_data = base64.b64decode(text)
                except Exception:
                    messagebox.showerror("Error", "Invalid Base64 format")
                    self.set_status("Decryption failed - invalid format")
                    return

                with tempfile.NamedTemporaryFile(delete=False, suffix=".encrypted") as tmp_in:
                    tmp_in.write(encrypted_data)
                    tmp_in_path = tmp_in.name

                with tempfile.NamedTemporaryFile(delete=False) as tmp_out:
                    tmp_out_path = tmp_out.name

                try:
                    # Decrypt
                    if self.crypto.decrypt_file(tmp_in_path, tmp_out_path):
                        # Read decrypted file
                        with open(tmp_out_path, "rb") as f:
                            decrypted_data = f.read()
                        decrypted_text = decrypted_data.decode("utf-8")

                        # Display output
                        self.decrypt_text_output.config(state=tk.NORMAL)
                        self.decrypt_text_output.delete("1.0", tk.END)
                        self.decrypt_text_output.insert("1.0", decrypted_text)
                        self.decrypt_text_output.config(state=tk.DISABLED)

                        self.set_status("✓ Text decrypted successfully")
                    else:
                        messagebox.showerror("Error", "Failed to decrypt text")
                        self.set_status("Decryption failed")
                finally:
                    # Clean up
                    Path(tmp_in_path).unlink(missing_ok=True)
                    Path(tmp_out_path).unlink(missing_ok=True)
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
                self.set_status("Decryption failed")

        thread = threading.Thread(target=decrypt, daemon=True)
        thread.start()

    def paste_encrypt_text(self):
        """Paste from clipboard to encrypt text input."""
        try:
            clipboard_text = self.root.clipboard_get()
            self.encrypt_text_input.delete("1.0", tk.END)
            self.encrypt_text_input.insert("1.0", clipboard_text)
        except tk.TclError:
            messagebox.showerror("Error", "Failed to read clipboard")

    def paste_decrypt_text(self):
        """Paste from clipboard to decrypt text input."""
        try:
            clipboard_text = self.root.clipboard_get()
            self.decrypt_text_input.delete("1.0", tk.END)
            self.decrypt_text_input.insert("1.0", clipboard_text)
        except tk.TclError:
            messagebox.showerror("Error", "Failed to read clipboard")

    def copy_encrypt_text(self):
        """Copy encrypted text to clipboard."""
        text = self.encrypt_text_output.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "No encrypted text to copy")
            return

        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.set_status("✓ Copied to clipboard")
            messagebox.showinfo("Success", "Encrypted text copied to clipboard")
        except tk.TclError:
            messagebox.showerror("Error", "Failed to copy to clipboard")

    def copy_decrypt_text(self):
        """Copy decrypted text to clipboard."""
        text = self.decrypt_text_output.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "No decrypted text to copy")
            return

        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.set_status("✓ Copied to clipboard")
            messagebox.showinfo("Success", "Decrypted text copied to clipboard")
        except tk.TclError:
            messagebox.showerror("Error", "Failed to copy to clipboard")

    def save_encrypt_text(self):
        """Save encrypted text to file."""
        text = self.encrypt_text_output.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "No encrypted text to save")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="encrypted_text.txt",
        )

        if not file_path:
            return

        try:
            with open(file_path, "w") as f:
                f.write(text)
            self.set_status(f"✓ Saved to {Path(file_path).name}")
            messagebox.showinfo("Success", f"Text saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

    def set_status(self, message):
        """Update status bar message."""
        self.status_label.config(text=message)
        self.root.update_idletasks()


def main():
    """Main entry point for the GUI application."""
    root = tk.Tk()
    app = EncryptionGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
