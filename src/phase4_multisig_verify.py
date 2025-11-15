import sys
import json
import base64
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


def verify_multisig(input_path: Path, multisig_path: Path):
    if not multisig_path.exists():
        print(f"[-] Multisig file '{multisig_path}' does not exist.")
        sys.exit(1)

    try:
        pkg = json.loads(multisig_path.read_text())
    except Exception as e:
        print(f"[-] Failed to parse multisig file: {e}")
        sys.exit(1)

    original_filename = pkg.get("original_filename")
    stored_hash_b64 = pkg.get("file_hash")
    signatures = pkg.get("signatures", [])

    if not stored_hash_b64 or not signatures:
        print("[-] Invalid multisig file: missing hash or signatures.")
        sys.exit(1)

    print(f"[i] Multisig package refers to original file: '{original_filename}'")
    print(f"[i] Number of signatures: {len(signatures)}")

    stored_hash = base64.b64decode(stored_hash_b64)

    # Recompute hash of the provided file
    current_data = input_path.read_bytes()
    current_hash = compute_sha256(current_data)

    if stored_hash != current_hash:
        print("[-] Verification FAILED: file hash does not match the stored hash (file was modified).")
        sys.exit(1)

    print("[i] File hash matches stored hash. Verifying each signature...")

    all_ok = True

    for sig_entry in signatures:
        signer = sig_entry.get("signer")
        signature_b64 = sig_entry.get("signature")

        if not signer or not signature_b64:
            print("[-] Invalid signature entry in package (missing signer or signature).")
            all_ok = False
            continue

        signature = base64.b64decode(signature_b64)
        public_key = load_public_key(signer)

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
            print(f"[+] Signature VALID for signer '{signer}'.")
        except Exception as e:
            print(f"[-] Signature INVALID for signer '{signer}': {e}")
            all_ok = False

    if all_ok:
        print("\n[✅] ALL signatures are valid and the file is intact.")
    else:
        print("\n[⚠] Some signatures FAILED verification. See details above.")


def main():
    if len(sys.argv) != 3:
        print("Usage: python phase4_multisig_verify.py <input_file> <multisig_file>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    multisig_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"[-] Input file '{input_file}' does not exist.")
        sys.exit(1)

    verify_multisig(input_file, multisig_file)


if __name__ == "__main__":
    main()
