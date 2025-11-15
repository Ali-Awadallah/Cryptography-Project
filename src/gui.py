# src/gui.py

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import json
import base64
import hashlib

from crypto_backend import (
    generate_rsa_keypair,
    send_secure_file,
    receive_secure_file_detailed,
    add_signature_to_package,
)


class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Digital Document Signing & Encryption System")
        self.geometry("900x550")

        # ----- Basic ttk styling -----
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))

        # ----- Menu bar with About/Help -----
        menubar = tk.Menu(self)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="How it works", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

        # ----- Notebook with tabs -----
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.send_frame = ttk.Frame(notebook)
        self.recv_frame = ttk.Frame(notebook)
        self.keys_frame = ttk.Frame(notebook)
        self.multisig_frame = ttk.Frame(notebook)

        notebook.add(self.send_frame, text="Send Secure File")
        notebook.add(self.recv_frame, text="Receive & Verify")
        notebook.add(self.keys_frame, text="Key Management")
        notebook.add(self.multisig_frame, text="Multi-Sign Package")

        # State for hashes / log / signatures
        self.hash_stored_var = tk.StringVar(value="(no verification yet)")
        self.hash_computed_var = tk.StringVar(value="(no verification yet)")
        self.hash_status_var = tk.StringVar(value="No verification performed yet.")
        self.hash_status_label = None

        self.log_text = None
        self.last_sig_results = []
        self.last_steps_log = []

        self._build_send_tab()
        self._build_receive_tab()
        self._build_keys_tab()
        self._build_multisig_tab()

    # ---------- About / Help ----------

    def _show_about(self):
        msg = (
            "Digital Document Signing & Encryption System\n\n"
            "• Files are encrypted with AES (Fernet) using a fresh random key.\n"
            "• The AES key is encrypted with the recipient's RSA public key (RSA-OAEP).\n"
            "• A SHA-256 hash of the plaintext file is computed.\n"
            "• The hash is signed with the sender's RSA private key (RSA-PSS).\n"
            "• The secure package (JSON) contains: encrypted key, ciphertext, hash, and signatures.\n"
            "• On receive, the app decrypts, recomputes the hash, and verifies all signatures.\n"
            "• If hashes match and all signatures are valid, the file is considered authentic and untampered."
        )
        messagebox.showinfo("About / How it works", msg)

    # ---------- Key Management Tab ----------

    def _build_keys_tab(self):
        frm = self.keys_frame

        ttk.Label(
            frm,
            text="Generate RSA Key Pair",
            style="Header.TLabel",
        ).pack(pady=10)

        row = ttk.Frame(frm)
        row.pack(pady=5, fill="x", padx=20)
        ttk.Label(row, text="Username:").pack(side="left")
        self.key_username = tk.StringVar()
        ttk.Entry(row, textvariable=self.key_username, width=25).pack(
            side="left", padx=5
        )

        ttk.Button(frm, text="Generate Keys", command=self.on_generate_keys).pack(
            pady=10
        )

        info = ttk.LabelFrame(frm, text="Key generation notes")
        info.pack(fill="x", padx=20, pady=10)

        ttk.Label(
            info,
            text=(
                "• Each username gets a 2048-bit RSA key pair.\n"
                "• Private key: used to decrypt AES keys and to sign document hashes.\n"
                "• Public key: used to encrypt AES keys and to verify signatures."
            ),
            justify="left",
            wraplength=840,
        ).pack(anchor="w", padx=10, pady=5)

    def on_generate_keys(self):
        username = self.key_username.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter a username.")
            return
        if " " in username:
            messagebox.showerror("Error", "Usernames must not contain spaces.")
            return

        try:
            priv, pub = generate_rsa_keypair(username)
            messagebox.showinfo(
                "Success",
                f"Generated keys for '{username}'.\n\nPrivate: {priv}\nPublic: {pub}",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys:\n{e}")

    # ---------- Send Tab ----------

    def _build_send_tab(self):
        frm = self.send_frame

        ttk.Label(
            frm,
            text="Send Secure File",
            style="Header.TLabel",
        ).pack(pady=10)

        # File chooser
        file_row = ttk.Frame(frm)
        file_row.pack(fill="x", padx=20, pady=5)
        ttk.Label(file_row, text="Input file:").pack(side="left")
        self.send_input_path = tk.StringVar()
        ttk.Entry(file_row, textvariable=self.send_input_path, width=60).pack(
            side="left", padx=5
        )
        ttk.Button(file_row, text="Browse...", command=self.browse_send_input).pack(
            side="left"
        )

        # Sender
        sender_row = ttk.Frame(frm)
        sender_row.pack(fill="x", padx=20, pady=5)
        ttk.Label(sender_row, text="Sender username:").pack(side="left")
        self.send_sender = tk.StringVar()
        ttk.Entry(sender_row, textvariable=self.send_sender, width=20).pack(
            side="left", padx=5
        )

        # Recipient
        recip_row = ttk.Frame(frm)
        recip_row.pack(fill="x", padx=20, pady=5)
        ttk.Label(recip_row, text="Recipient username:").pack(side="left")
        self.send_recipient = tk.StringVar()
        ttk.Entry(recip_row, textvariable=self.send_recipient, width=20).pack(
            side="left", padx=5
        )

        # Output package
        out_row = ttk.Frame(frm)
        out_row.pack(fill="x", padx=20, pady=5)
        ttk.Label(out_row, text="Output package:").pack(side="left")
        self.send_output_path = tk.StringVar()
        ttk.Entry(out_row, textvariable=self.send_output_path, width=60).pack(
            side="left", padx=5
        )
        ttk.Button(out_row, text="Browse...", command=self.browse_send_output).pack(
            side="left"
        )

        ttk.Button(frm, text="Send Secure", command=self.on_send_secure).pack(pady=15)

        info = ttk.LabelFrame(frm, text="What happens when you click 'Send Secure'")
        info.pack(fill="x", padx=20, pady=10)

        ttk.Label(
            info,
            text=(
                "• The selected file is encrypted with a random AES key (Fernet).\n"
                "• The AES key is encrypted with the recipient's RSA public key (RSA-OAEP).\n"
                "• A SHA-256 hash of the original file is signed with the sender's RSA private key (RSA-PSS).\n"
                "• All of this is stored together in a secure JSON package."
            ),
            justify="left",
            wraplength=840,
        ).pack(anchor="w", padx=10, pady=5)

    def browse_send_input(self):
        path = filedialog.askopenfilename(title="Select file to send")
        if path:
            self.send_input_path.set(path)
            pkg = Path(path).with_suffix(".secure.json")
            self.send_output_path.set(str(pkg))

    def browse_send_output(self):
        path = filedialog.asksaveasfilename(
            title="Save secure package as",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.send_output_path.set(path)

    def on_send_secure(self):
        in_path = self.send_input_path.get().strip()
        sender = self.send_sender.get().strip()
        recipient = self.send_recipient.get().strip()
        out_path = self.send_output_path.get().strip()

        if not (in_path and sender and recipient and out_path):
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if " " in sender or " " in recipient:
            messagebox.showerror("Error", "Usernames must not contain spaces.")
            return

        try:
            send_secure_file(Path(in_path), sender, recipient, Path(out_path))
            messagebox.showinfo("Success", f"Secure package created:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send:\n{e}")

    # ---------- Receive Tab ----------

    def _build_receive_tab(self):
        frm = self.recv_frame

        ttk.Label(
            frm,
            text="Receive & Verify Secure File",
            style="Header.TLabel",
        ).pack(pady=10)

        # Package file
        pkg_row = ttk.Frame(frm)
        pkg_row.pack(fill="x", padx=20, pady=5)
        ttk.Label(pkg_row, text="Package file:").pack(side="left")
        self.recv_pkg_path = tk.StringVar()
        ttk.Entry(pkg_row, textvariable=self.recv_pkg_path, width=60).pack(
            side="left", padx=5
        )
        ttk.Button(pkg_row, text="Browse...", command=self.browse_recv_pkg).pack(
            side="left"
        )

        # Recipient
        rec_row = ttk.Frame(frm)
        rec_row.pack(fill="x", padx=20, pady=5)
        ttk.Label(rec_row, text="Recipient username:").pack(side="left")
        self.recv_username = tk.StringVar()
        ttk.Entry(rec_row, textvariable=self.recv_username, width=20).pack(
            side="left", padx=5
        )

        # Receive button + details
        btn_row = ttk.Frame(frm)
        btn_row.pack(fill="x", padx=20, pady=5)
        ttk.Button(btn_row, text="Receive & Verify", command=self.on_receive_verify).pack(
            side="left"
        )
        self.details_button = ttk.Button(
            btn_row,
            text="Signature Details...",
            command=self.show_signature_details,
            state="disabled",
        )
        self.details_button.pack(side="left", padx=10)

        info = ttk.LabelFrame(frm, text="What 'Receive & Verify' does")
        info.pack(fill="x", padx=20, pady=10)

        ttk.Label(
            info,
            text=(
                "• Decrypts the AES key using the recipient's RSA private key.\n"
                "• Uses AES to decrypt the ciphertext and recover the file.\n"
                "• Recomputes SHA-256 over the plaintext and compares it with the stored hash.\n"
                "• Verifies ALL signatures in the package using each signer's public RSA key.\n"
                "• Only if hash + signatures are valid is the file considered authentic and untampered."
            ),
            justify="left",
            wraplength=840,
        ).pack(anchor="w", padx=10, pady=5)

        # Verification details
        details = ttk.LabelFrame(frm, text="Verification details")
        details.pack(fill="x", padx=20, pady=10)

        row1 = ttk.Frame(details)
        row1.pack(fill="x", padx=10, pady=2)
        ttk.Label(row1, text="Stored SHA-256 hash (from package):").pack(side="left")
        ttk.Label(row1, textvariable=self.hash_stored_var).pack(
            side="left", padx=5
        )

        row2 = ttk.Frame(details)
        row2.pack(fill="x", padx=10, pady=2)
        ttk.Label(row2, text="Recomputed SHA-256 hash (decrypted file):").pack(
            side="left"
        )
        ttk.Label(row2, textvariable=self.hash_computed_var).pack(
            side="left", padx=5
        )

        status_row = ttk.Frame(details)
        status_row.pack(fill="x", padx=10, pady=6)
        ttk.Label(status_row, text="Status:").pack(side="left")
        self.hash_status_label = ttk.Label(status_row, textvariable=self.hash_status_var)
        self.hash_status_label.pack(side="left", padx=5)

        # Log panel
        log_frame = ttk.LabelFrame(frm, text="Verification log")
        log_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.log_text = tk.Text(log_frame, height=8, wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)
        self.log_text.config(state="disabled", bg=self.cget("background"))

    def _set_log(self, lines):
        if not self.log_text:
            return
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        for line in lines:
            self.log_text.insert("end", line + "\n")
        self.log_text.config(state="disabled")

    def browse_recv_pkg(self):
        path = filedialog.askopenfilename(
            title="Select secure package",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.recv_pkg_path.set(path)

    def on_receive_verify(self):
        pkg = self.recv_pkg_path.get().strip()
        recipient = self.recv_username.get().strip()

        # Reset state
        self.hash_stored_var.set("(no verification yet)")
        self.hash_computed_var.set("(no verification yet)")
        self.hash_status_var.set("No verification performed yet.")
        if self.hash_status_label:
            self.hash_status_label.config(foreground="black")
        self._set_log([])
        self.last_sig_results = []
        self.last_steps_log = []
        self.details_button.config(state="disabled")

        if not pkg or not recipient:
            messagebox.showerror(
                "Error", "Please select a package file and enter a recipient username."
            )
            return

        if " " in recipient:
            messagebox.showerror("Error", "Usernames must not contain spaces.")
            return

        pkg_path = Path(pkg)

        # Read original filename for naming the decrypted file
        try:
            data = json.loads(pkg_path.read_text())
            original_name = data.get("original_filename", "decrypted_output")
        except Exception:
            original_name = "decrypted_output"

        # Build decrypted filename: <stem>_decrypted<ext>
        orig = Path(original_name)
        stem = orig.stem or "decrypted_output"
        suffix = orig.suffix or ""
        final_output_path = pkg_path.parent / f"{stem}_decrypted{suffix}"

        try:
            ok, msg, sig_results, steps, stored_hex, computed_hex = (
                receive_secure_file_detailed(pkg_path, recipient, final_output_path)
            )
        except Exception as e:
            self.hash_status_var.set("Error during decryption/verification.")
            if self.hash_status_label:
                self.hash_status_label.config(foreground="red")
            self._set_log([f"Exception: {e}"])
            messagebox.showerror("Error", f"Failed to receive file:\n{e}")
            return

        # Save results
        self.last_sig_results = sig_results
        self.last_steps_log = steps
        self._set_log(steps)

        # Hash display
        if stored_hex:
            self.hash_stored_var.set(stored_hex)
        else:
            try:
                data = json.loads(pkg_path.read_text())
                file_hash_b64 = data.get("file_hash", None)
                if file_hash_b64:
                    stored_bytes = base64.b64decode(file_hash_b64)
                    self.hash_stored_var.set(stored_bytes.hex())
                else:
                    self.hash_stored_var.set("N/A")
            except Exception:
                self.hash_stored_var.set("N/A")

        if computed_hex:
            self.hash_computed_var.set(computed_hex)
        else:
            try:
                decrypted_bytes = final_output_path.read_bytes()
                self.hash_computed_var.set(
                    hashlib.sha256(decrypted_bytes).hexdigest()
                )
            except Exception:
                self.hash_computed_var.set("N/A")

        stored = self.hash_stored_var.get()
        computed = self.hash_computed_var.get()

        if sig_results:
            self.details_button.config(state="normal")

        if ok:
            self.hash_status_var.set(
                "✅ Hashes match and all signatures are VALID – file has NOT been tampered."
            )
            if self.hash_status_label:
                self.hash_status_label.config(foreground="green")
            messagebox.showinfo(
                "Success",
                f"{msg}\n\nDecrypted file saved as:\n{final_output_path}",
            )
        else:
            if stored != "N/A" and computed != "N/A" and stored != computed:
                base_msg = "❌ Hashes DO NOT match – file MAY be tampered."
            else:
                base_msg = (
                    "❌ Verification failed – one or more signatures are INVALID or hash check failed."
                )

            self.hash_status_var.set(base_msg)
            if self.hash_status_label:
                self.hash_status_label.config(foreground="red")
            messagebox.showerror("Verification failed", msg)

    def show_signature_details(self):
        if not self.last_sig_results:
            messagebox.showinfo(
                "Signature details", "No signature verification results available yet."
            )
            return

        win = tk.Toplevel(self)
        win.title("Signature Details")
        win.geometry("450x300")

        ttk.Label(
            win,
            text="Signature verification results:",
            style="Header.TLabel",
        ).pack(pady=10)

        frame = ttk.Frame(win)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        text = tk.Text(frame, wrap="word", height=10)
        text.pack(fill="both", expand=True)

        for res in self.last_sig_results:
            status = "VALID" if res.get("valid") else "INVALID"
            line = f"Signer: {res.get('signer', '(unknown)')}  ->  {status}"
            if res.get("error"):
                line += f"  (Error: {res['error']})"
            text.insert("end", line + "\n")

        text.config(state="disabled")

    # ---------- Multi-Sign Tab ----------

    def _build_multisig_tab(self):
        frm = self.multisig_frame

        ttk.Label(
            frm,
            text="Add Signature to Existing Package",
            style="Header.TLabel",
        ).pack(pady=10)

        pkg_row = ttk.Frame(frm)
        pkg_row.pack(fill="x", padx=20, pady=5)
        ttk.Label(pkg_row, text="Package file:").pack(side="left")
        self.ms_pkg_path = tk.StringVar()
        ttk.Entry(pkg_row, textvariable=self.ms_pkg_path, width=60).pack(
            side="left", padx=5
        )
        ttk.Button(pkg_row, text="Browse...", command=self.browse_ms_pkg).pack(
            side="left"
        )

        signer_row = ttk.Frame(frm)
        signer_row.pack(fill="x", padx=20, pady=5)
        ttk.Label(signer_row, text="Signer username:").pack(side="left")
        self.ms_signer = tk.StringVar()
        ttk.Entry(signer_row, textvariable=self.ms_signer, width=25).pack(
            side="left", padx=5
        )

        ttk.Button(frm, text="Add Signature", command=self.on_ms_add_signature).pack(
            pady=15
        )

        info = ttk.LabelFrame(frm, text="What multi-signing does")
        info.pack(fill="x", padx=20, pady=10)

        ttk.Label(
            info,
            text=(
                "• Uses the stored SHA-256 hash inside the package (not the ciphertext).\n"
                "• The selected signer signs this hash with their RSA private key (RSA-PSS).\n"
                "• Their signature is appended to signatures[] in the JSON package.\n"
                "• The Receive & Verify tab will validate all of these signatures."
            ),
            justify="left",
            wraplength=840,
        ).pack(anchor="w", padx=10, pady=5)

    def browse_ms_pkg(self):
        path = filedialog.askopenfilename(
            title="Select secure package",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.ms_pkg_path.set(path)

    def on_ms_add_signature(self):
        pkg_path = self.ms_pkg_path.get().strip()
        signer = self.ms_signer.get().strip()

        if not pkg_path or not signer:
            messagebox.showerror(
                "Error", "Please select a package file and enter a signer username."
            )
            return

        if " " in signer:
            messagebox.showerror("Error", "Usernames must not contain spaces.")
            return

        try:
            add_signature_to_package(Path(pkg_path), signer)
            messagebox.showinfo("Success", f"Signature added for signer '{signer}'.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add signature:\n{e}")


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
