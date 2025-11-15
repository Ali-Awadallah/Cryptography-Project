import sys
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key(username: str):
    base_dir = Path(__file__).resolve().parent.parent
    priv_path = base_dir / "keys" / f"{username}_private.pem"

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


def compute_sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def sign_file(input_path: Path, signer: str, sig_path: Path):
    # 1) Load private key of signer
    private_key = load_private_key(signer)

    # 2) Read file content
    data = input_path.read_bytes()

    # 3) Compute SHA-256 hash of file
    file_hash = compute_sha256(data)

    # 4) Sign the hash with RSA-PSS
    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # 5) Build signature package (JSON) with base64 encoding
    package = {
        "signer": signer,
        "original_filename": input_path.name,
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS",
        "file_hash": base64.b64encode(file_hash).decode("utf-8"),
        "signature": base64.b64encode(signature).decode("utf-8"),
    }

    sig_path.write_text(json.dumps(package, indent=2))
    print(f"[+] Signed file '{input_path}' as '{signer}'")
    print(f"[+] Signature saved to '{sig_path}'")


def main():
    if len(sys.argv) != 4:
        print("Usage: python phase3_sign.py <input_file> <signer_username> <output_signature_file>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    signer = sys.argv[2]
    sig_file = Path(sys.argv[3])

    if not input_file.exists():
        print(f"[-] Input file '{input_file}' does not exist.")
        sys.exit(1)

    sign_file(input_file, signer, sig_file)


if __name__ == "__main__":
    main()
