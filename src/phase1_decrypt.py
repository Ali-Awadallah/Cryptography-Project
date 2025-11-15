import sys
from cryptography.fernet import Fernet
from pathlib import Path

KEY_FILE = "phase1_secret.key"

def load_key():
    try:
        with open(KEY_FILE, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"[-] Error: Key file '{KEY_FILE}' not found. Make sure you have the shared key.")
        sys.exit(1)

def decrypt_file(input_path: Path, output_path: Path):
    key = load_key()
    cipher = Fernet(key)

    # Read encrypted bytes
    encrypted_data = input_path.read_bytes()

    # Decrypt using the symmetric key
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        sys.exit(1)

    # Save decrypted output
    output_path.write_bytes(decrypted_data)
    print(f"[+] Decrypted '{input_path}' → '{output_path}'")

def main():
    if len(sys.argv) != 3:
        print("Usage: python phase1_decrypt.py <input_encrypted_file> <output_decrypted_file>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"[-] Error: Input file '{input_file}' does not exist.")
        sys.exit(1)

    decrypt_file(input_file, output_file)

if __name__ == "__main__":
    main()
