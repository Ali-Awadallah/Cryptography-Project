from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_keypair(username: str):
    # Generate a 2048-bit RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Paths
    base_dir = Path(__file__).resolve().parent.parent  # .. (project root)
    keys_dir = base_dir / "keys"
    keys_dir.mkdir(exist_ok=True)

    priv_path = keys_dir / f"{username}_private.pem"
    pub_path = keys_dir / f"{username}_public.pem"

    # Save private key (unencrypted for now – later we can protect it)
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_path.write_bytes(priv_bytes)

    # Save public key
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path.write_bytes(pub_bytes)

    print(f"[+] Generated RSA key pair for user '{username}'")
    print(f"[+] Private key: {priv_path}")
    print(f"[+] Public  key: {pub_path}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python phase2_keygen.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    generate_rsa_keypair(username)


if __name__ == "__main__":
    main()
