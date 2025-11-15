import sys
import json
import base64
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ---------- Helpers ----------

def base_dir() -> Path:
    # project root = parent of src
    return Path(__file__).resolve().parent.parent


def load_private_key(username: str):
    priv_path = base_dir() / "keys" / f"{username}_private.pem"

    if not priv_path.exists():
        print(f"[-] Private key for user '{username}' not found at '{priv_path}'")
        sys.exit(1)

    priv_bytes = priv_path.read_bytes()
    try:
        private_key = serialization.load_pem_private_key(priv_bytes, password=None)
    except Exception as e:
        print(f"[-] Failed to load private key: {e}")
        sys.exit(1)

    return private_key


def load_public_key(username: str):
    pub_path = base_dir() / "keys" / f"{username}_public.pem"

    if not pub_path.exists():
        print(f"[-] Public key for user '{username}' not found at '{pub_path}'")
        sys.exit(1)

    pub_bytes = pub_path.read_bytes()
    try:
        public_key = serialization.load_pem_public_key(pub_bytes)
    except Exception as e:
        print(f"[-] Failed to load public key: {e}")
        sys.exit(1)

    return public_key


def compute_sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


# ---------- Core logic ----------

def send_secure_file(input_path: Path, sender: str, recipient: str, out_package: Path):
    print(f"[i] Sender   : {sender}")
    print(f"[i] Recipient: {recipient}")
    print(f"[i] Input    : {input_path}")

    # 1) Load keys
    sender_priv = load_private_key(sender)
    recipient_pub = load_public_key(recipient)

    # 2) Read plaintext
    plaintext = input_path.read_bytes()

    # 3) Compute SHA-256 of plaintext
    file_hash = compute_sha256(plaintext)

    # 4) Generate fresh AES/Fernet key
    aes_key = Fernet.generate_key()
    f = Fernet(aes_key)

    # 5) Encrypt plaintext with AES
    ciphertext = f.encrypt(plaintext)

    # 6) Encrypt AES key with recipient's RSA public key (RSA-OAEP + SHA256)
    encrypted_aes_key = recipient_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 7) Sign the hash with sender's private key (RSA-PSS + SHA256)
    signature = sender_priv.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # 8) Build JSON secure package
    package = {
        "sender": sender,
        "recipient": recipient,
        "original_filename": input_path.name,
        "crypto": {
            "encryption": "AES (Fernet)",
            "key_encryption": "RSA-OAEP",
            "hash_algorithm": "SHA-256",
            "signature_algorithm": "RSA-PSS"
        },
        "encrypted_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "file_hash": base64.b64encode(file_hash).decode("utf-8"),
        "signatures": [
            {
                "signer": sender,
                "signature": base64.b64encode(signature).decode("utf-8"),
            }
        ],
    }

    out_package.write_text(json.dumps(package, indent=2))
    print(f"[+] Secure package written to '{out_package}'")


def main():
    if len(sys.argv) != 5:
        print("Usage: python phase5_send.py <input_file> <sender_username> <recipient_username> <output_package_file>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    sender = sys.argv[2]
    recipient = sys.argv[3]
    out_package = Path(sys.argv[4])

    if not input_file.exists():
        print(f"[-] Input file '{input_file}' does not exist.")
        sys.exit(1)

    send_secure_file(input_file, sender, recipient, out_package)


if __name__ == "__main__":
    main()
