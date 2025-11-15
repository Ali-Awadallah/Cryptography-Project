import sys
import json
import base64
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


def load_recipient_private_key(username: str):
    base_dir = Path(__file__).resolve().parent.parent
    priv_path = base_dir / "keys" / f"{username}_private.pem"

    if not priv_path.exists():
        print(f"[-] Private key for user '{username}' not found at '{priv_path}'")
        sys.exit(1)

    priv_bytes = priv_path.read_bytes()
    return serialization.load_pem_private_key(priv_bytes, password=None)


def decrypt_package(package_path: Path, recipient: str, out_path: Path):
    private_key = load_recipient_private_key(recipient)

    # 1) Load JSON package
    package = json.loads(package_path.read_text())

    enc_key_b64 = package["encrypted_key"]
    ciphertext_b64 = package["ciphertext"]

    encrypted_aes_key = base64.b64decode(enc_key_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    # 2) Decrypt AES key with RSA private key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3) Use AES key (Fernet) to decrypt file
    f = Fernet(aes_key)
    try:
        plaintext = f.decrypt(ciphertext)
    except Exception as e:
        print(f"[-] AES decryption failed: {e}")
        sys.exit(1)

    out_path.write_bytes(plaintext)
    print(f"[+] Decrypted package '{package_path}' as user '{recipient}'")
    print(f"[+] Output file: '{out_path}'")


def main():
    if len(sys.argv) != 4:
        print("Usage: python phase2_decrypt.py <input_package_file> <recipient_username> <output_file>")
        sys.exit(1)

    pkg_file = Path(sys.argv[1])
    recipient = sys.argv[2]
    out_file = Path(sys.argv[3])

    if not pkg_file.exists():
        print(f"[-] Package file '{pkg_file}' does not exist.")
        sys.exit(1)

    decrypt_package(pkg_file, recipient, out_file)


if __name__ == "__main__":
    main()
