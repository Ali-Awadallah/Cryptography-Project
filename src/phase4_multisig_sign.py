import sys
import json
import base64
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


def create_new_package(input_path: Path, file_hash: bytes, signer: str, signature_b64: str):
    return {
        "original_filename": input_path.name,
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS",
        "file_hash": base64.b64encode(file_hash).decode("utf-8"),
        "signatures": [
            {
                "signer": signer,
                "signature": signature_b64,
            }
        ],
    }


def add_signature_to_package(pkg: dict, signer: str, signature_b64: str):
    # Prevent duplicate signer entries (optional)
    for sig in pkg.get("signatures", []):
        if sig.get("signer") == signer:
            print(f"[!] Warning: signer '{signer}' already has a signature in this package. Adding another anyway.")
            break

    pkg["signatures"].append(
        {
            "signer": signer,
            "signature": signature_b64,
        }
    )


def multisig_sign(input_path: Path, signer: str, multisig_path: Path):
    private_key = load_private_key(signer)
    data = input_path.read_bytes()
    current_hash = compute_sha256(data)

    # If multisig file exists, load and check it
    if multisig_path.exists():
        print(f"[i] Existing multisig file found at '{multisig_path}', appending new signature.")
        try:
            pkg = json.loads(multisig_path.read_text())
        except Exception as e:
            print(f"[-] Failed to read existing multisig file: {e}")
            sys.exit(1)

        stored_hash_b64 = pkg.get("file_hash")
        if not stored_hash_b64:
            print("[-] Invalid multisig file: missing 'file_hash'.")
            sys.exit(1)

        stored_hash = base64.b64decode(stored_hash_b64)

        # Ensure the file hasn't changed compared to the original hash
        if stored_hash != current_hash:
            print("[-] File content does not match the stored hash in the multisig file. Aborting.")
            sys.exit(1)

    else:
        print(f"[i] No existing multisig file. Creating a new one at '{multisig_path}'.")
        pkg = None

    # Sign the current hash
    signature = private_key.sign(
        current_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    # Create or update package
    if pkg is None:
        pkg = create_new_package(input_path, current_hash, signer, signature_b64)
    else:
        add_signature_to_package(pkg, signer, signature_b64)

    multisig_path.write_text(json.dumps(pkg, indent=2))
    print(f"[+] Added signature for signer '{signer}' to '{multisig_path}'.")


def main():
    if len(sys.argv) != 4:
        print("Usage: python phase4_multisig_sign.py <input_file> <signer_username> <multisig_file>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    signer = sys.argv[2]
    multisig_file = Path(sys.argv[3])

    if not input_file.exists():
        print(f"[-] Input file '{input_file}' does not exist.")
        sys.exit(1)

    multisig_sign(input_file, signer, multisig_file)


if __name__ == "__main__":
    main()
