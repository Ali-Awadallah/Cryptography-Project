import sys
import json
import base64
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ---------- Helpers ----------

def base_dir() -> Path:
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

def receive_secure_file(package_path: Path, recipient: str, out_file: Path):
    if not package_path.exists():
        print(f"[-] Package file '{package_path}' does not exist.")
        sys.exit(1)

    # 1) Load JSON package
    try:
        package = json.loads(package_path.read_text())
    except Exception as e:
        print(f"[-] Failed to parse package JSON: {e}")
        sys.exit(1)

    pkg_recipient = package.get("recipient")
    sender = package.get("sender")
    original_filename = package.get("original_filename")
    encrypted_key_b64 = package.get("encrypted_key")
    ciphertext_b64 = package.get("ciphertext")
    file_hash_b64 = package.get("file_hash")
    signatures = package.get("signatures", [])

    print(f"[i] Package sender   : {sender}")
    print(f"[i] Package recipient: {pkg_recipient}")
    print(f"[i] Original filename: {original_filename}")
    print(f"[i] Decrypting as    : {recipient}")

    if pkg_recipient != recipient:
        print(f"[!] Warning: Package recipient is '{pkg_recipient}', but you are '{recipient}'")

    if not encrypted_key_b64 or not ciphertext_b64 or not file_hash_b64:
        print("[-] Invalid package: missing encrypted_key / ciphertext / file_hash.")
        sys.exit(1)

    # 2) Decode base64 fields
    encrypted_key = base64.b64decode(encrypted_key_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    stored_hash = base64.b64decode(file_hash_b64)

    # 3) Decrypt AES key with recipient's private key
    priv_key = load_private_key(recipient)
    try:
        aes_key = priv_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        print(f"[-] Failed to decrypt AES key with recipient private key: {e}")
        sys.exit(1)

    # 4) Decrypt ciphertext with AES key
    f = Fernet(aes_key)
    try:
        plaintext = f.decrypt(ciphertext)
    except Exception as e:
        print(f"[-] AES decryption failed: {e}")
        sys.exit(1)

    # 5) Verify hash of decrypted plaintext
    current_hash = compute_sha256(plaintext)
    if current_hash != stored_hash:
        print("[-] Verification FAILED: decrypted file hash does not match stored hash. (Tampering or corruption)")
        sys.exit(1)

    print("[i] File hash matches stored hash. Verifying signatures...")

    # 6) Verify each signature
    all_ok = True
    for sig_entry in signatures:
        signer = sig_entry.get("signer")
        signature_b64 = sig_entry.get("signature")

        if not signer or not signature_b64:
            print("[-] Invalid signature entry in package (missing signer or signature).")
            all_ok = False
            continue

        signature = base64.b64decode(signature_b64)
        pub_key = load_public_key(signer)

        try:
            pub_key.verify(
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

    # 7) Save plaintext to output file if everything is ok
    if all_ok:
        out_file.write_bytes(plaintext)
        print(f"\n[✅] All signatures valid. File decrypted and saved to '{out_file}'.")
    else:
        print("\n[⚠] Some signatures failed verification. Decrypted file will still be written for inspection.")
        out_file.write_bytes(plaintext)
        print(f"[i] Output file: '{out_file}'")


def main():
    if len(sys.argv) != 4:
        print("Usage: python phase5_receive.py <package_file> <recipient_username> <output_file>")
        sys.exit(1)

    package_file = Path(sys.argv[1])
    recipient = sys.argv[2]
    out_file = Path(sys.argv[3])

    receive_secure_file(package_file, recipient, out_file)


if __name__ == "__main__":
    main()
