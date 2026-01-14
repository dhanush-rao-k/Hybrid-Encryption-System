# Cross-System Encryption Guide

## Overview

This guide explains how to encrypt files on one system and decrypt them on another system using the Hybrid Encryption System.

---

## Workflow: Alice encrypts for Bob

### Step 1: Bob Generates Keys (System B)

**Bob's System:**
```
1. python gui.py
2. Click "Generate RSA Keys"
3. Keys created: keys/private.pem, keys/public.pem
```

### Step 2: Bob Exports Public Key (System B)

**Bob's System:**
```
1. In GUI, click "Export Public Key"
2. Save as: bob_public.pem
3. Share file with Alice (email, cloud, USB, etc.)
```

### Step 3: Alice Imports Bob's Public Key (System A)

**Alice's System:**
```
1. python gui.py
2. Receive bob_public.pem from Bob
3. Click "Import Public Key"
4. Select bob_public.pem
5. Status shows: "Imported: bob_public.pem"
```

### Step 4: Alice Encrypts File for Bob (System A)

**Alice's System:**
```
1. Go to "Encrypt File" tab
2. Select file: secret.pdf
3. Click "Encrypt File"
4. Save as: secret.pdf.encrypted
5. File encrypted with Bob's public key
```

### Step 5: Alice Sends Encrypted File to Bob (Network)

**Alice's System:**
```
1. Send secret.pdf.encrypted to Bob
   (Email, cloud storage, USB, etc.)
2. File is secure - only Bob can decrypt!
```

### Step 6: Bob Decrypts File (System B)

**Bob's System:**
```
1. Receive secret.pdf.encrypted from Alice
2. Go to "Decrypt File" tab
3. Select: secret.pdf.encrypted
4. Click "Decrypt File"
5. Save as: secret.pdf
6. Original file restored!
```

---

## Step-by-Step: Detailed Instructions

### For the Person Creating Keys (Key Owner)

#### Generate Keys
```
1. Launch GUI: python gui.py
2. Click "Generate RSA Keys"
3. Wait for completion
4. Status shows "Keys: Found"
5. Keys saved: keys/private.pem, keys/public.pem
```

#### Export Public Key
```
1. Click "Export Public Key"
2. Choose save location
3. File saved as: public_key.pem (or custom name)
4. Safe to share - only encrypts, doesn't decrypt
```

#### Keep Private Key Safe
```
1. NEVER share keys/private.pem
2. NEVER share keys/public.pem with untrusted parties
3. BACKUP: cp keys/private.pem keys/private.pem.backup
4. Store in secure location
```

#### Decrypt Files from Others
```
1. Others use YOUR exported public key to encrypt
2. They send you encrypted files
3. You receive: file.encrypted
4. Go to "Decrypt File" tab
5. Select encrypted file
6. Click "Decrypt File"
7. Original file restored (only you can do this!)
```

---

### For the Person Encrypting (Encryption Only)

#### Import Public Key
```
1. Receive public_key.pem from key owner
2. Click "Import Public Key"
3. Select public_key.pem
4. Status shows: "Imported: public_key.pem"
```

#### Encrypt Files
```
1. Go to "Encrypt File" tab
2. Select file to encrypt
3. Click "Encrypt File"
4. Save as: file.encrypted
5. Send file.encrypted to key owner
```

#### Cannot Decrypt
```
Important: You cannot decrypt files encrypted with this key!
- You only have public key (encryption)
- You don't have private key (decryption)
- Only key owner can decrypt!
```

---

## Use Cases

### Use Case 1: Secure File Sharing

**Scenario:** Alice wants to send confidential document to Bob

```
Step 1: Bob sends Alice his public_key.pem
Step 2: Alice imports Bob's public key
Step 3: Alice encrypts document with Bob's key
Step 4: Alice sends encrypted file to Bob
Step 5: Bob decrypts with his private key
Result: Secure, verifiable encryption
```

### Use Case 2: Secure Backup

**Scenario:** Alice backs up personal files to cloud storage

```
Step 1: Alice generates RSA keys
Step 2: Alice exports her public key
Step 3: Alice encrypts all files with her key
Step 4: Alice uploads encrypted files to cloud
Step 5: Alice stores private key in safe location
Step 6: Later: Alice decrypts from cloud with private key
Result: Secure cloud backup only Alice can access
```

### Use Case 3: Multi-Person Encryption

**Scenario:** Team needs to send encrypted data

```
Person A: Generates keys, exports public key
Person B: Imports Person A's key
Person C: Imports Person A's key
Person D: Imports Person A's key

Result: B, C, D all encrypt files for A
A can decrypt all, others cannot decrypt
```

### Use Case 4: Cross-Platform Usage

**Scenario:** Windows PC encrypts, Mac decrypts

```
Step 1: Mac generates keys, exports public_key.pem
Step 2: Windows imports public_key.pem
Step 3: Windows encrypts files
Step 4: Windows sends encrypted files to Mac
Step 5: Mac decrypts files
Result: Platform-agnostic encryption!
```

---

## Technical Details

### Key Components

**Public Key (exportable)**
- Used for ENCRYPTION
- Safe to share
- File: `public_key.pem`
- Location: Can be anywhere
- Action: Click "Export Public Key" to share

**Private Key (keep secret)**
- Used for DECRYPTION
- Never share!
- File: `keys/private.pem`
- Location: keys/ directory only
- Action: Keep backed up safely

### Encryption Flow (Cross-System)

```
Original File (Alice's System)
    ↓
Generate random AES-256 key
Generate random nonce
    ↓
Encrypt file data: AES-256-GCM
    ↓
Encrypt AES key with Bob's RSA public key
    ↓
Output: [key_len][encrypted_key][nonce][encrypted_data]
    ↓
Encrypted File (share with Bob)
    ↓
Send over network (safe!)
    ↓
Bob's System receives encrypted file
    ↓
Decrypt AES key with Bob's RSA private key
    ↓
Decrypt file data: AES-256-GCM
    ↓
Original File (Bob's System)
```

### Security Guarantees

**Alice cannot:**
- Decrypt files she encrypts for Bob
- Recover encrypted file if she loses it
- Change encrypted file afterward

**Bob can:**
- Decrypt any files encrypted with his public key
- Verify Alice encrypted it (via RSA)
- Prove when file was created

**Network cannot:**
- Read encrypted files in transit
- Modify encrypted data undetectably
- Decrypt without Bob's private key

---

## Troubleshooting

### Problem: "Import Public Key" doesn't work

**Solution:**
- File must be in PEM format (.pem)
- File must be valid RSA public key
- Check file isn't corrupted

### Problem: "Encryption failed" error

**Solution (if importing public key):**
- Import key again: Click "Import Public Key"
- Select correct key file
- Try encrypting a small test file first

**Solution (if using generated keys):**
- Generate fresh keys
- Ensure keys/ directory exists
- Check file permissions

### Problem: "Decryption failed" error

**Causes:**
1. Wrong private key being used
2. Encrypted file is corrupted
3. File wasn't encrypted with this key

**Solutions:**
1. Use private key that matches the public key used for encryption
2. Verify encrypted file integrity
3. Test with a file encrypted on same system first

### Problem: Can't find exported public key

**Solution:**
```
1. Click "Export Public Key"
2. Note the file path shown in message
3. Look for .pem file in that location
4. Or search for "public_key.pem"
```

### Problem: Multiple systems, which key to use?

**Answer:**
- Each system generates its OWN RSA keys
- Each system exports its OWN public key
- Systems import OTHER people's public keys
- Everyone keeps their own private key secret

---

## Best Practices

### 1. Key Management
```
DO:
✓ Backup private key: cp keys/private.pem keys/private.pem.backup
✓ Store backup safely
✓ Share only public key
✓ Use strong system password

DON'T:
✗ Share private key
✗ Email private key
✗ Store in cloud (unencrypted)
✗ Commit to public git repos
```

### 2. File Sharing
```
DO:
✓ Verify sender before importing public key
✓ Confirm key fingerprint (first 8 chars)
✓ Test with non-critical files first
✓ Keep encrypted file backup

DON'T:
✗ Import unknown public keys
✗ Assume encrypted = safe
✗ Delete original after encrypting
✗ Trust unsigned keys
```

### 3. System Setup
```
DO:
✓ Generate unique key for each system
✓ Export each system's public key
✓ Create organized key storage
✓ Document key ownership

DON'T:
✗ Reuse same key across systems
✗ Share private key between systems
✗ Lose track of key files
✗ Mix up which key is whose
```

---

## Example: Alice & Bob Setup

### Initial Setup

**Bob's System:**
```bash
1. python gui.py
2. Click "Generate RSA Keys"
3. Click "Export Public Key" → save "bob_public.pem"
4. Email bob_public.pem to Alice
5. Keep keys/private.pem safe (NEVER SHARE!)
```

**Alice's System:**
```bash
1. Receive bob_public.pem from Bob
2. python gui.py
3. Click "Import Public Key" → select bob_public.pem
4. Status shows "Imported: bob_public.pem"
```

### File Exchange

**Alice encrypts for Bob:**
```
1. Select file: "report.docx"
2. Click "Encrypt File"
3. File encrypted with Bob's public key
4. Output: "report.docx.encrypted"
5. Send to Bob
```

**Bob decrypts from Alice:**
```
1. Receive "report.docx.encrypted"
2. Go to "Decrypt File" tab
3. Select "report.docx.encrypted"
4. Click "Decrypt File"
5. File restored: "report.docx"
6. Only Bob could do this!
```

---

## Security Questions & Answers

**Q: Can Alice decrypt files she encrypted for Bob?**
A: No! She only has Bob's public key, not his private key.

**Q: Can someone intercept the encrypted file and read it?**
A: No! Only Bob's private key can decrypt it.

**Q: What if Alice loses the encrypted file?**
A: Bob still has the decrypted original. Encryption is one-way.

**Q: Can Bob decrypt files Alice encrypted for him?**
A: Yes! It was encrypted with HIS public key, and he has the private key.

**Q: What if private key is stolen?**
A: All files encrypted with that public key can be decrypted.
Recommendation: Generate new keys immediately.

**Q: Can I use same public key on multiple systems?**
A: Yes! But backup private key on all systems or keep centralized.

---

## Migration: Moving to New System

### Backup & Restore Keys

**Old System:**
```bash
1. Backup both keys:
   cp keys/private.pem keys/private.pem.backup
   cp keys/public.pem keys/public.pem.backup
2. Store safely (USB, cloud, email)
```

**New System:**
```bash
1. Copy backed-up keys to new system
2. Create keys/ directory
3. Place private.pem and public.pem in keys/
4. Launch GUI
5. Status shows "Keys: Found"
6. Ready to decrypt old encrypted files!
```

---

## Conclusion

The Hybrid Encryption System enables:
- ✓ Secure file sharing between systems
- ✓ Encryption-only mode (import public key)
- ✓ Decryption-only mode (keep private key)
- ✓ Cross-platform compatibility
- ✓ Portable encrypted files
- ✓ No password needed (RSA-based)

**It's that simple!** Share public keys, encrypt files, decrypt on other systems.

---

**Status**: Ready for Cross-System Use
**Date**: January 14, 2026
