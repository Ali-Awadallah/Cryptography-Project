import sys
from cryptography.fernet import Fernet
from pathlib import Path

KEY_FILE = "phase1_secret.key"

def load_key():
    try:
        with open(KEY_FILE, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"[-] Error: Key file '{KEY_FILE}' not found. Run phase1_keygen.py first.")
        sys.exit(1)

def encrypt_file(input_path: Path, output_path: Path):
    key = load_key()
    cipher = Fernet(key)

    # Read file as bytes
    data = input_path.read_bytes()

    # Encrypt file content
    encrypted_data = cipher.encrypt(data)

    # Save encrypted file
    output_path.write_bytes(encrypted_data)
    print(f"[+] Encrypted '{input_path}' → '{output_path}'")

def main():
    if len(sys.argv) != 3:
        print("Usage: python phase1_encrypt.py <input_file> <output_encrypted_file>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"[-] Error: Input file '{input_file}' does not exist.")
        sys.exit(1)

    encrypt_file(input_file, output_file)

if __name__ == "__main__":
    main()
