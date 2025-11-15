Digital Document Signing & Verification System

DACS 3101 – Applied Cryptography – Term Project (Version E)
Team Project – Fall 2025

📌 Project Overview

Digital documents such as contracts, official reports, and certificates are vulnerable to tampering, impersonation, or unauthorized modification.
This project implements a complete Digital Document Signing & Verification System ensuring:

✔ Authenticity (who created/signed the document)
✔ Integrity (the document was not modified)
✔ Confidentiality (encrypted document transfer)
✔ Non-repudiation (signers cannot deny signing)

The system uses a combination of:

AES symmetric encryption for protecting files

RSA asymmetric encryption for per-recipient AES key protection

SHA-256 hashing for content integrity

RSA-PSS signatures for digital signing

Multi-signature workflow for multiple approvals

A user-friendly GUI built with Tkinter

This project fully implements Phases 1–6 described in the assignment.

📁 Project Structure
Cryptography-Project/
│
├── keys/                     # Auto-generated RSA public/private keys
│   ├── <username>_private.pem
│   ├── <username>_public.pem
│
├── samples/                  # Test files
│   ├── test_document.docx
│   ├── test_document.secure.json
│
├── src/
│   ├── gui.py                # Full GUI (Phase 6)
│   ├── crypto_backend.py     # Core encryption, signing, verification logic
│   ├── phase1_*.py           # Earlier phase development
│   ├── phase2_*.py
│   ├── phase3_*.py
│   ├── phase4_*.py
│   ├── phase5_*.py
│
├── README.md
└── requirements.txt

🧑‍💻 Team Members

(Fill this section with your team names and IDs)

Name	Student ID	Role
Ali Awadallah	60301637	Team Leader, Security & Integration
Member 2	XXXXXXXX	UI / Documentation
Member 3	XXXXXXXX	Testing & Verification
Member 4	XXXXXXXX	Encryption/Backend
Member 5	XXXXXXXX	Multi-signature logic
📌 PHASE-BY-PHASE DESCRIPTION

The following explains exactly how your project fulfills each assigned phase.

🔹 Phase 1 – Symmetric AES Encryption

File encrypted using AES/Fernet

Shared static AES key (early version)

Receiver decrypts and recovers identical file

This laid the foundation for secure file transfer.

🔹 Phase 2 – Per-Recipient RSA Protection

Each user has a unique RSA-2048 keypair

AES key is generated per-file

AES key encrypted with recipient’s public key (RSA-OAEP)

Only the intended recipient can decrypt the file

This implements confidential document transfer.

🔹 Phase 3 – Digital Signing & Hashing

Compute SHA-256 hash of plaintext

Sign using RSA-PSS with the sender’s private key

Store signature + signer ID inside secure JSON package

Receiver recomputes hash and verifies signature

This ensures authenticity + integrity.

🔹 Phase 4 – Multi-Signature Workflow

Any user can append their own digital signature

Each signature is stored with:

signer ID

RSA-PSS signature

Receiver verifies all signatures, not only the first

Used for multi-manager approval workflows

🔹 Phase 5 – Full Integration

All components integrated into a single JSON package:

{
  sender,
  recipient,
  original_filename,
  encrypted_key,
  ciphertext,
  file_hash,
  signatures: [
      { signer, signature }
  ]
}


The receiver performs:

✔ RSA decryption of AES key
✔ AES decryption of ciphertext
✔ SHA-256 hash recomputation
✔ Full signature chain verification
✔ Detailed verification logs
✔ “Signature Details” window

🔹 Phase 6 – Graphical User Interface (GUI)

The GUI provides:

1️⃣ Send Secure File

Choose file

Choose sender / recipient

Encrypt + sign + package in one click

2️⃣ Receive & Verify

Full verification

Color-coded “VALID/INVALID” results

Stored vs recomputed SHA-256 hashes

Auto-naming decrypted file as *_decrypted.ext

Logs showing every backend step

3️⃣ Multi-Sign Package

Select existing .secure.json

Add additional signatures

4️⃣ Key Management

Auto-generate RSA keys for any username

Stored in /keys/<username>_*.pem

5️⃣ Verification Details Pop-up

Shows each signer

Shows VALID / INVALID

Shows errors if any key is missing

📌 HOW THE SOFTWARE IS USED — USER MANUAL
▶ 1. Generate Keys

Go to Key Management → enter username → click Generate Keys.
Two files are created:

keys/<username>_private.pem
keys/<username>_public.pem

▶ 2. Sending a Secure File

GUI tab: Send Secure File

Browse and select a document

Enter sender username

Enter recipient username

Click Send Secure

Output:
yourfile.secure.json

This file contains encrypted data + signatures.

▶ 3. Receiving & Verifying a File

GUI tab: Receive & Verify

Select .secure.json

Enter recipient username

Click Receive & Verify

GUI will show:

Stored vs recomputed SHA-256

Hash match / mismatch

Signature verification

Full log

Decrypted file saved as:

originalname_decrypted.ext

▶ 4. Adding Additional Signatures

GUI tab: Multi-Sign Package

Select package

Enter signer username

Click Add Signature

New signature appended to the package.

📌 Testing Scenarios (Required in Phase 5)
Attack 1 – Tampered File

Modify ciphertext in JSON

Receiver sees:
❌ AES decryption fails
or
❌ Hash mismatch

Attack 2 – Wrong Recipient

Person without correct private key tries to decrypt

Decryption fails

Attack 3 – Missing or Fake Signature

Remove a signature

Modify signature field

Receiver sees INVALID for that signer

📌 Technologies Used
Component	Algorithm
Symmetric Encryption	AES (Fernet 128-bit)
Key Encryption	RSA-OAEP (RSA-2048)
Hash Function	SHA-256
Signatures	RSA-PSS
GUI	Tkinter
Packaging	JSON
Language	Python 3.12
📌 Installation & Running
1. Install dependencies
pip install -r requirements.txt

2. Run the GUI
python src/gui.py

3. Keys auto-generate into:
/keys/

📌 What to Submit

Your GitHub repo already contains:

✔ Full source code
✔ GUI (Phase 6)
✔ Integrated backend
✔ Multi-signature logic
✔ Samples for testing
✔ README (this file)

Remaining deliverables you must prepare:

1. Final Written Report

Should include:

Explanation of Phases 1–5

Screenshots of GUI

Architecture diagram

Workflow diagrams

Attack scenario results

Team member responsibilities

2. PowerPoint Presentation

Include:

Overview

Demo screenshots

How encryption/signatures work

Multi-sign example

Conclusion

🎉 Final Notes

This project fully satisfies every requirement:
✔ Cryptography phases 1–5
✔ Multi-signer support
✔ Working GUI
✔ Verification logs
✔ Signature detail window
✔ Secure file exchange
✔ Keys per user
✔ Full hash + signature verification

You are 100% ready for submission and presentation.
