📄 README.md
Digital Document Signing and Verification System
DACS 3101 – Applied Cryptography
University of Doha for Science and Technology
🚀 Project Overview

This project implements a secure digital document signing and verification system designed to guarantee the confidentiality, integrity, authenticity, and non-repudiation of digital files.

The system uses a combination of:

AES (Symmetric Encryption) – to securely encrypt documents

RSA (Asymmetric Encryption) – for per-recipient AES key protection

SHA-256 (Hashing) – to ensure integrity

RSA Digital Signatures – to prove authorship and detect tampering

Users can securely exchange encrypted documents, verify signatures, and participate in multi-signature approval workflows.

🧩 Key Features
🔐 1. User Registration & Key Management

Each user generates their own RSA public–private key pair.

Public keys stored in a local Key Directory.

Private keys securely stored (optionally AES-encrypted).

📨 2. Secure File Encryption (AES)

A random AES session key is created for every file transfer.

The document is encrypted using AES-256 (CBC or GCM mode).

🔑 3. Per-Recipient RSA Key Protection

The AES session key is encrypted with the recipient’s RSA public key.

Only the intended receiver can decrypt it using their private key.

✍️ 4. Digital Signing (RSA + SHA-256)

The sender computes a SHA-256 hash of the file.

This hash is signed with the sender’s RSA private key.

The receiver validates the signature with the sender’s public key.

📝 5. Signature Verification

Recompute SHA-256 hash.

Verify RSA signature.

Detect any tampering or impersonation.

👥 6. Multi-Signature Workflow

The system supports multiple sequential signatures.

Signatures are chained and validated in the correct order.

🧪 7. Full Integration & Attack Testing

The system is tested for:

Modified documents

Wrong signatures

Wrong recipient keys

Corrupted metadata

📁 Project Structure
project/
│
├── src/
│   ├── keygen.py          # RSA key generation & storage
│   ├── encrypt.py         # AES encryption + RSA key wrapping
│   ├── decrypt.py         # Decrypt AES key + decrypt document
│   ├── sign.py            # Digital signature generation
│   ├── verify.py          # Signature verification
│   ├── multisig.py        # Multi-signature workflow
│   ├── utils.py           # Hashing, file helpers, metadata
│
├── keys/
│   ├── user_public.pem
│   ├── user_private.pem
│
├── docs/
│   ├── Report.pdf
│   ├── Presentation.pptx
│
├── samples/
│   └── sample_document.pdf
│
└── README.md

🛠 Technologies Used
Component	Technology
Language	Python 3
Crypto Library	cryptography (hazmat)
Hashing	hashlib (SHA-256)
Key Format	PEM
Packaging	JSON + binary bundles
📦 Installation
1. Clone the Repository
git clone https://github.com/<your-repo>/digital-signing-system.git
cd digital-signing-system

2. Create Virtual Environment
python3 -m venv venv
source venv/bin/activate        # Mac/Linux
venv\Scripts\activate           # Windows

3. Install Dependencies
pip install -r requirements.txt

▶️ How to Use
🔑 Generate RSA Keys
python src/keygen.py --user ali

🔏 Sign a Document
python src/sign.py --file report.pdf --key keys/ali_private.pem

🔐 Encrypt for a Recipient
python src/encrypt.py --file report.signed --recipient ahmed

🔓 Decrypt & Verify
python src/decrypt.py --file received.enc
python src/verify.py --file decrypted.pdf --signer ali

🧾 Add a Multi-Signature
python src/multisig.py --file doc.pdf --signer manager2


📚 Academic Context

This project is built for the course DACS 3101 – Applied Cryptography
College of Computing & IT – University of Doha for Science and Technology.

Project Requirements Source: Term Project (Version E) 

Project_E_DocumentSigningSharin…

📝 License

This project is for academic purposes only.
