from cryptography.fernet import Fernet

def main():
    # Generate a symmetric AES key (Fernet uses AES-128 + HMAC)
    key = Fernet.generate_key()

    # Save the key to a local file
    with open("phase1_secret.key", "wb") as f:
        f.write(key)

    print("[+] AES shared key generated.")
    print("[+] Saved to phase1_secret.key")
    print("[i] Share this file securely with the receiver.")

if __name__ == "__main__":
    main()
