# src/crypto_backend.py

from pathlib import Path
import base64
import json

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# ---------- Common helpers ----------

def _base_dir() -> Path:
    # project root = parent of src
    return Path(__file__).resolve().parent.parent


def generate_rsa_keypair(username: str):
    """
    Generate a 2048-bit RSA key pair and save it under keys/<username>_*.pem
    """
    base = _base_dir()
    keys_dir = base / "keys"
    keys_dir.mkdir(exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    priv_path = keys_dir / f"{username}_private.pem"
    pub_path = keys_dir / f"{username}_public.pem"

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)

    return priv_path, pub_path


def _load_private_key(username: str):
    priv_path = _base_dir() / "keys" / f"{username}_private.pem"
    data = priv_path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def _load_public_key(username: str):
    pub_path = _base_dir() / "keys" / f"{username}_public.pem"
    data = pub_path.read_bytes()
    return serialization.load_pem_public_key(data)


def _sha256(data: bytes) -> bytes:
    d = hashes.Hash(hashes.SHA256())
    d.update(data)
    return d.finalize()


# ---------- Integrated send / receive ----------

def send_secure_file(input_file: Path, sender: str, recipient: str, out_package: Path):
    """
    Full Phase 5 send:
      - read plaintext
      - hash with SHA-256
      - encrypt with AES (Fernet)
      - encrypt AES key with recipient RSA (OAEP)
      - sign hash with sender RSA (PSS)
      - write JSON package
    """
    input_file = input_file.resolve()
    plaintext = input_file.read_bytes()

    sender_priv = _load_private_key(sender)
    recipient_pub = _load_public_key(recipient)

    file_hash = _sha256(plaintext)

    # AES key + ciphertext
    aes_key = Fernet.generate_key()
    f = Fernet(aes_key)
    ciphertext = f.encrypt(plaintext)

    # Encrypt AES key with recipient public key
    encrypted_aes_key = recipient_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Sign hash with sender private key
    signature = sender_priv.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    package = {
        "sender": sender,
        "recipient": recipient,
        "original_filename": input_file.name,
        "crypto": {
            "encryption": "AES (Fernet)",
            "key_encryption": "RSA-OAEP",
            "hash_algorithm": "SHA-256",
            "signature_algorithm": "RSA-PSS",
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


def receive_secure_file_detailed(
    package_file: Path, recipient: str, out_file: Path
):
    """
    Detailed receive:
      - read JSON package
      - decrypt AES key with recipient RSA
      - decrypt ciphertext with AES
      - check hash (stored vs recomputed)
      - verify all signatures
      - write plaintext to out_file

    Returns:
      ok: bool
      message: str
      sig_results: list of {signer, valid, error}
      steps: list of step-by-step log messages
      stored_hash_hex: str
      computed_hash_hex: str
    """
    steps = []
    sig_results = []
    stored_hash_hex = ""
    computed_hash_hex = ""

    steps.append(f"Loading package from: {package_file}")
    try:
        package = json.loads(package_file.read_text())
    except Exception as e:
        steps.append(f"Failed to parse JSON: {e}")
        return False, f"Failed to parse package JSON: {e}", sig_results, steps, "", ""

    sender = package.get("sender")
    pkg_recipient = package.get("recipient")
    original_filename = package.get("original_filename")

    steps.append(f"Sender in package    : {sender}")
    steps.append(f"Recipient in package : {pkg_recipient}")
    steps.append(f"Original filename    : {original_filename}")

    encrypted_key_b64 = package.get("encrypted_key")
    ciphertext_b64 = package.get("ciphertext")
    file_hash_b64 = package.get("file_hash")
    signatures = package.get("signatures", [])

    if not (encrypted_key_b64 and ciphertext_b64 and file_hash_b64):
        steps.append("Missing encrypted_key, ciphertext, or file_hash in package.")
        return (
            False,
            "Invalid package: missing encrypted_key / ciphertext / file_hash.",
            sig_results,
            steps,
            "",
            "",
        )

    steps.append("Decoding base64 fields...")
    encrypted_key = base64.b64decode(encrypted_key_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    stored_hash = base64.b64decode(file_hash_b64)
    stored_hash_hex = stored_hash.hex()

    # Decrypt AES key
    steps.append(f"Loading private key for recipient '{recipient}'...")
    try:
        priv = _load_private_key(recipient)
    except Exception as e:
        steps.append(f"Failed to load private key: {e}")
        return False, f"Failed to load recipient private key: {e}", sig_results, steps, stored_hash_hex, ""

    steps.append("Decrypting AES key with RSA-OAEP...")
    try:
        aes_key = priv.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        steps.append(f"Failed to decrypt AES key: {e}")
        return False, f"Failed to decrypt AES key: {e}", sig_results, steps, stored_hash_hex, ""

    # Decrypt ciphertext
    steps.append("Decrypting ciphertext with AES (Fernet)...")
    f = Fernet(aes_key)
    try:
        plaintext = f.decrypt(ciphertext)
    except Exception as e:
        steps.append(f"AES decryption failed: {e}")
        return False, f"AES decryption failed: {e}", sig_results, steps, stored_hash_hex, ""

    # Hash comparison
    steps.append("Computing SHA-256 hash over decrypted plaintext...")
    current_hash = _sha256(plaintext)
    computed_hash_hex = current_hash.hex()

    ok = True
    if current_hash == stored_hash:
        steps.append("File hash matches stored hash. (No tampering detected at hash level.)")
    else:
        steps.append("File hash does NOT match stored hash! (Possible tampering or corruption.)")
        ok = False

    # Verify signatures
    steps.append("Verifying signatures...")
    for sig_entry in signatures:
        signer = sig_entry.get("signer")
        sig_b64 = sig_entry.get("signature")
        if not signer or not sig_b64:
            steps.append("Found invalid signature entry (missing signer or signature).")
            sig_results.append(
                {"signer": signer or "(unknown)", "valid": False, "error": "Malformed signature entry"}
            )
            ok = False
            continue

        try:
            signature = base64.b64decode(sig_b64)
        except Exception as e:
            steps.append(f"Failed to base64-decode signature for '{signer}': {e}")
            sig_results.append({"signer": signer, "valid": False, "error": f"Base64 decode error: {e}"})
            ok = False
            continue

        try:
            pub = _load_public_key(signer)
        except Exception as e:
            steps.append(f"Failed to load public key for signer '{signer}': {e}")
            sig_results.append({"signer": signer, "valid": False, "error": f"Public key load error: {e}"})
            ok = False
            continue

        try:
            pub.verify(
                signature,
                stored_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            steps.append(f"Signature from '{signer}' is VALID.")
            sig_results.append({"signer": signer, "valid": True, "error": ""})
        except Exception as e:
            steps.append(f"Signature from '{signer}' is INVALID: {e}")
            sig_results.append({"signer": signer, "valid": False, "error": str(e)})
            ok = False

    # Write decrypted file
    steps.append(f"Writing decrypted file to: {out_file}")
    try:
        out_file.write_bytes(plaintext)
    except Exception as e:
        steps.append(f"Failed to write decrypted file: {e}")
        return False, f"Failed to write decrypted file: {e}", sig_results, steps, stored_hash_hex, computed_hash_hex

    if ok:
        message = f"Decrypted file from sender '{sender}' saved to '{out_file}'. All hashes and signatures verified."
    else:
        message = (
            f"Decrypted file saved to '{out_file}', but verification failed "
            f"(hash mismatch and/or invalid signatures)."
        )

    return ok, message, sig_results, steps, stored_hash_hex, computed_hash_hex


def receive_secure_file(package_file: Path, recipient: str, out_file: Path):
    """
    Backwards-compatible wrapper for older code that expects (ok, msg).
    """
    ok, msg, sig_results, steps, stored_hex, computed_hex = receive_secure_file_detailed(
        package_file, recipient, out_file
    )
    return ok, msg


def add_signature_to_package(package_file: Path, signer: str):
    """
    Multi-sign:
      - load existing secure JSON package
      - read stored file_hash
      - sign that hash with signer's private key (RSA-PSS)
      - append to signatures[] list
    """
    if not package_file.exists():
        raise FileNotFoundError(f"Package file '{package_file}' not found.")

    package = json.loads(package_file.read_text())

    file_hash_b64 = package.get("file_hash")
    if not file_hash_b64:
        raise ValueError("Invalid package: missing 'file_hash' field.")

    signatures = package.get("signatures")
    if signatures is None:
        signatures = []
        package["signatures"] = signatures

    stored_hash = base64.b64decode(file_hash_b64)

    priv = _load_private_key(signer)
    signature = priv.sign(
        stored_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    sig_entry = {
        "signer": signer,
        "signature": base64.b64encode(signature).decode("utf-8"),
    }
    signatures.append(sig_entry)

    package_file.write_text(json.dumps(package, indent=2))
