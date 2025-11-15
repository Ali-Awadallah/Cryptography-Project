import sys
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def load_public_key(username: str):
    base_dir = Path(__file__).resolve().parent.parent
    pub_path = base_dir / "keys" / f"{username}_public.pem"

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


def verify_signature(input_path: Path, sig_path: Path, expected_signer: str):
    # 1) Load signature package
    try:
        package = json.loads(sig_path.read_text())
    except Exception as e:
        print(f"[-] Failed to read signature file: {e}")
        sys.exit(1)

    signer_in_sig = package.get("signer")
    if signer_in_sig != expected_signer:
        print(f"[!] Warning: Signature claims signer '{signer_in_sig}', but you expected '{expected_signer}'")

    file_hash_b64 = package.get("file_hash")
    signature_b64 = package.get("signature")

    if not file_hash_b64 or not signature_b64:
        print("[-] Invalid signature file: missing hash or signature fields.")
        sys.exit(1)

    stored_hash = base64.b64decode(file_hash_b64)
    signature = base64.b64decode(signature_b64)

    # 2) Recompute hash of the given file
    data = input_path.read_bytes()
    current_hash = compute_sha256(data)

    if current_hash != stored_hash:
        print("[-] Verification FAILED: file hash does not match the signed hash (file was modified).")
        sys.exit(1)

    # 3) Verify the signature using signer public key
    public_key = load_public_key(signer_in_sig)

    try:
        public_key.verify(
            signature,
            stored_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception as e:
        print(f"[-] Verification FAILED: signature invalid ({e}).")
        sys.exit(1)

    print("[+] Verification SUCCESSFUL.")
    print(f"[+] File '{input_path}' is intact and was signed by '{signer_in_sig}'.")
    print("[+] Hash algorithm: SHA-256, Signature algorithm: RSA-PSS")


def main():
    if len(sys.argv) != 4:
        print("Usage: python phase3_verify.py <input_file> <signature_file> <expected_signer_username>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    sig_file = Path(sys.argv[2])
    expected_signer = sys.argv[3]

    if not input_file.exists():
        print(f"[-] Input file '{input_file}' does not exist.")
        sys.exit(1)
    if not sig_file.exists():
        print(f"[-] Signature file '{sig_file}' does not exist.")
        sys.exit(1)

    verify_signature(input_file, sig_file, expected_signer)


if __name__ == "__main__":
    main()
