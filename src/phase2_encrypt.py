import sys
import json
import base64
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


def load_recipient_public_key(username: str):
    base_dir = Path(__file__).resolve().parent.parent
    pub_path = base_dir / "keys" / f"{username}_public.pem"

    if not pub_path.exists():
        print(f"[-] Public key for user '{username}' not found at '{pub_path}'")
        sys.exit(1)

    pub_bytes = pub_path.read_bytes()
    return serialization.load_pem_public_key(pub_bytes)


def encrypt_for_recipient(input_path: Path, recipient: str, out_path: Path):
    # 1) Load recipient public key
    public_key = load_recipient_public_key(recipient)

    # 2) Generate fresh AES/Fernet key
    aes_key = Fernet.generate_key()
    f = Fernet(aes_key)

    # 3) Encrypt file contents with AES
    plaintext = input_path.read_bytes()
    ciphertext = f.encrypt(plaintext)

    # 4) Encrypt AES key with RSA public key (OAEP + SHA-256)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 5) Build JSON package with base64
    package = {
        "recipient": recipient,
        "original_filename": input_path.name,
        "encrypted_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }

    out_path.write_text(json.dumps(package))
    print(f"[+] Encrypted '{input_path}' for recipient '{recipient}'")
    print(f"[+] Package written to '{out_path}'")


def main():
    if len(sys.argv) != 4:
        print("Usage: python phase2_encrypt.py <input_file> <recipient_username> <output_package_file>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    recipient = sys.argv[2]
    out_file = Path(sys.argv[3])

    if not input_file.exists():
        print(f"[-] Input file '{input_file}' does not exist.")
        sys.exit(1)

    encrypt_for_recipient(input_file, recipient, out_file)


if __name__ == "__main__":
    main()
