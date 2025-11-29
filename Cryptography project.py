# -*- coding: utf-8 -*-


import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, filedialog
import json
import os
import hashlib
import base64
import time
from datetime import datetime

# Attempt to import cryptography (RSA)
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    missing = True
    crypto_import_error = str(e)
else:
    missing = False

CHAIN_FILE = "chain.json"
PRIVATE_PEM = "private_key.pem"
PUBLIC_PEM = "public_key.pem"

# ----------------- Utilities -----------------
def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# ----------------- RSA Key Handling -----------------
def generate_rsa_keypair(bits=2048):
    if missing:
        raise RuntimeError("cryptography library missing: " + crypto_import_error)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PRIVATE_PEM, "wb") as f:
        f.write(priv_pem)
    with open(PUBLIC_PEM, "wb") as f:
        f.write(pub_pem)
    return priv_pem.decode(), pub_pem.decode()

def load_private_key():
    if missing:
        raise RuntimeError("cryptography library missing: " + crypto_import_error)
    if not os.path.exists(PRIVATE_PEM):
        return None
    with open(PRIVATE_PEM, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key():
    if missing:
        raise RuntimeError("cryptography library missing: " + crypto_import_error)
    if not os.path.exists(PUBLIC_PEM):
        return None
    with open(PUBLIC_PEM, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def pubkey_fingerprint(pub_pem_bytes: bytes) -> str:
    # quick fingerprint: sha256 of public PEM
    return sha256_hex(pub_pem_bytes.decode())[:16]

# ----------------- Blockchain Core -----------------
def default_genesis():
    return [{
        "index": 0,
        "timestamp": now_iso(),
        "prev_hash": "0" * 64,
        "nonce": 0,
        "transactions": [],
        "hash": sha256_hex("genesis"),
        "difficulty": 3
    }]

def load_chain():
    if not os.path.exists(CHAIN_FILE):
        return default_genesis()
    with open(CHAIN_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_chain(chain):
    with open(CHAIN_FILE, "w", encoding="utf-8") as f:
        json.dump(chain, f, indent=2)

def compute_block_hash(index, timestamp, prev_hash, nonce, transactions, difficulty):
    block_string = json.dumps({
        "index": index, "timestamp": timestamp, "prev_hash": prev_hash,
        "nonce": nonce, "transactions": transactions, "difficulty": difficulty
    }, sort_keys=True, separators=(',', ':'))
    return sha256_hex(block_string)

def valid_proof(hash_hex, difficulty):
    return hash_hex.startswith("0" * difficulty)

# ----------------- GUI App -----------------
class LightweightBlockchainApp:
    def __init__(self, master):
        self.master = master
        master.title("📦 Lightweight Blockchain Demo — PoW + RSA")
        master.geometry("880x700")
        master.config(bg="#f2f2f2")

        # Load state
        try:
            self.chain = load_chain()
        except Exception as e:
            self.chain = default_genesis()
        self.difficulty = tk.IntVar(value=self.chain[-1].get("difficulty", 3))
        self.tx_pool = []  # unsigned transactions
        self.signed_pool = []  # signed txs ready to be mined

        # Layout
        tk.Label(master, text="Design & Implementation: Lightweight Blockchain (PoW + RSA)",
                 font=("Arial", 16, "bold"), bg="#f2f2f2").pack(pady=8)

        # Keyframe
        key_frame = tk.Frame(master, bg="#f2f2f2")
        key_frame.pack(fill="x", padx=12)
        tk.Button(key_frame, text="Generate RSA Keypair 🔐", command=self.generate_keys,
                  bg="#4CAF50", fg="white", width=20).pack(side="left", padx=6)
        tk.Button(key_frame, text="Load Keys 📂", command=self.load_keys,
                  bg="#2196F3", fg="white", width=12).pack(side="left", padx=6)
        tk.Button(key_frame, text="Show Public Key 🗝️", command=self.show_public_key,
                  bg="#FF9800", fg="white", width=14).pack(side="left", padx=6)
        tk.Button(key_frame, text="Export Chain ⤓", command=self.export_chain,
                  bg="#9C27B0", fg="white", width=14).pack(side="left", padx=6)

        # Transaction frame
        tx_frame = tk.LabelFrame(master, text="Create & Sign Transaction", bg="#f2f2f2", font=("Arial", 12, "bold"))
        tx_frame.pack(fill="x", padx=12, pady=8)

        tk.Label(tx_frame, text="Recipient (string):", bg="#f2f2f2").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.recipient_entry = tk.Entry(tx_frame, width=40)
        self.recipient_entry.grid(row=0, column=1, padx=6, pady=4)
        tk.Label(tx_frame, text="Amount:", bg="#f2f2f2").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        self.amount_entry = tk.Entry(tx_frame, width=20)
        self.amount_entry.grid(row=1, column=1, sticky="w", padx=6, pady=4)
        tk.Label(tx_frame, text="Message (optional):", bg="#f2f2f2").grid(row=2, column=0, sticky="nw", padx=6, pady=4)
        self.msg_entry = scrolledtext.ScrolledText(tx_frame, width=56, height=4)
        self.msg_entry.grid(row=2, column=1, padx=6, pady=4)

        btn_tx_frame = tk.Frame(tx_frame, bg="#f2f2f2")
        btn_tx_frame.grid(row=3, column=1, pady=6, sticky="w")
        tk.Button(btn_tx_frame, text="Create Transaction ➕", command=self.create_transaction,
                  bg="#4CAF50", fg="white", width=18).pack(side="left", padx=6)
        tk.Button(btn_tx_frame, text="Sign Pending with Private Key ✍️", command=self.sign_pending,
                  bg="#2196F3", fg="white", width=26).pack(side="left", padx=6)
        tk.Button(btn_tx_frame, text="Clear Pending", command=self.clear_pending,
                  bg="#f44336", fg="white", width=12).pack(side="left", padx=6)

        # Mining frame
        mine_frame = tk.LabelFrame(master, text="Mining / Chain Controls", bg="#f2f2f2", font=("Arial", 12, "bold"))
        mine_frame.pack(fill="x", padx=12, pady=8)

        tk.Label(mine_frame, text="Difficulty (leading zeros):", bg="#f2f2f2").pack(side="left", padx=6)
        tk.Spinbox(mine_frame, from_=1, to=6, textvariable=self.difficulty, width=5).pack(side="left", padx=6)
        tk.Button(mine_frame, text="Mine Block ⛏️", command=self.mine_block,
                  bg="#FF9800", fg="white", width=18).pack(side="left", padx=8)
        tk.Button(mine_frame, text="List Chain 📜", command=self.list_chain,
                  bg="#9C27B0", fg="white", width=12).pack(side="left", padx=6)
        tk.Button(mine_frame, text="Verify Chain ✅/❌", command=self.verify_chain,
                  bg="#4CAF50", fg="white", width=14).pack(side="left", padx=6)
        tk.Button(mine_frame, text="Reset Chain 🗑️", command=self.reset_chain,
                  bg="#f44336", fg="white", width=12).pack(side="left", padx=6)

        # Output area
        tk.Label(master, text="Output / Log:", bg="#f2f2f2").pack(anchor="w", padx=14)
        self.output_box = scrolledtext.ScrolledText(master, width=100, height=18, font=("Courier", 10))
        self.output_box.pack(padx=12, pady=6)
        self.output_box.insert(tk.END, "Welcome. Chain loaded with {} blocks.\n".format(len(self.chain)))
        self.output_box.config(state='disabled')

        # Try to auto-load keys for UX
        self.priv_key_obj = None
        self.pub_key_obj = None
        self.pub_pem_bytes = None
        self.try_auto_load_keys()

    # ---------- Key operations ----------
    def try_auto_load_keys(self):
        try:
            if os.path.exists(PRIVATE_PEM) and os.path.exists(PUBLIC_PEM) and not missing:
                self.priv_key_obj = load_private_key()
                self.pub_key_obj = load_public_key()
                with open(PUBLIC_PEM, "rb") as f:
                    self.pub_pem_bytes = f.read()
                self.log("Auto-loaded keys from disk.")
        except Exception as e:
            self.log("Auto-load keys failed: " + str(e))

    def generate_keys(self):
        if missing:
            messagebox.showerror("Missing Dependency", "cryptography is required. Install: pip install cryptography")
            return
        try:
            priv_pem, pub_pem = generate_rsa_keypair()
            self.priv_key_obj = load_private_key()
            self.pub_key_obj = load_public_key()
            self.pub_pem_bytes = pub_pem.encode()
            self.log("RSA keypair generated and saved to '{}' and '{}'.".format(PRIVATE_PEM, PUBLIC_PEM))
            messagebox.showinfo("Keys Generated", "RSA keypair created successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")

    def load_keys(self):
        if missing:
            messagebox.showerror("Missing Dependency", "cryptography is required. Install: pip install cryptography")
            return
        try:
            if not os.path.exists(PRIVATE_PEM) or not os.path.exists(PUBLIC_PEM):
                messagebox.showwarning("Keys Not Found", "No key files found (private_key.pem / public_key.pem).")
                return
            self.priv_key_obj = load_private_key()
            self.pub_key_obj = load_public_key()
            with open(PUBLIC_PEM, "rb") as f:
                self.pub_pem_bytes = f.read()
            self.log("Keys loaded successfully.")
            messagebox.showinfo("Loaded", "Keys loaded from disk.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load keys: {e}")

    def show_public_key(self):
        if not self.pub_pem_bytes:
            messagebox.showwarning("No Public Key", "Public key not loaded. Generate or load keys first.")
            return
        top = tk.Toplevel(self.master)
        top.title("Public Key (PEM)")
        text = scrolledtext.ScrolledText(top, width=80, height=20)
        text.pack(padx=8, pady=8)
        text.insert(tk.END, self.pub_pem_bytes.decode())
        text.config(state='disabled')

    # ---------- Transactions ----------
    def create_transaction(self):
        recipient = self.recipient_entry.get().strip()
        amount = self.amount_entry.get().strip()
        message = self.msg_entry.get("1.0", tk.END).strip()
        if not recipient or not amount:
            messagebox.showwarning("Missing Fields", "Please provide recipient and amount.")
            return
        try:
            amount_val = float(amount)
        except ValueError:
            messagebox.showwarning("Invalid", "Amount must be numeric.")
            return
        # Create a basic transaction structure
        sender_fp = pubkey_fingerprint(self.pub_pem_bytes) if self.pub_pem_bytes else "UNKNOWN"
        tx = {
            "sender_fp": sender_fp,
            "recipient": recipient,
            "amount": amount_val,
            "message": message,
            "timestamp": now_iso()
        }
        self.tx_pool.append(tx)
        self.log("Transaction created and added to pending pool.")
        self.clear_tx_inputs()

    def clear_tx_inputs(self):
        self.recipient_entry.delete(0, tk.END)
        self.amount_entry.delete(0, tk.END)
        self.msg_entry.delete("1.0", tk.END)

    def sign_pending(self):
        if missing:
            messagebox.showerror("Missing Dependency", "cryptography is required for signing.")
            return
        if not self.priv_key_obj:
            messagebox.showwarning("No Private Key", "Load or generate the private key first.")
            return
        if not self.tx_pool:
            messagebox.showwarning("No Pending", "No pending transactions to sign.")
            return
        for tx in self.tx_pool:
            # canonical serialization of transaction
            payload = json.dumps(tx, sort_keys=True, separators=(',', ':')).encode('utf-8')
            signature = sign_message(self.priv_key_obj, payload)
            tx_signed = dict(tx)  # copy
            tx_signed["signature"] = base64.b64encode(signature).decode('utf-8')
            tx_signed["pub_pem_fp"] = pubkey_fingerprint(self.pub_pem_bytes) if self.pub_pem_bytes else "UNKNOWN"
            self.signed_pool.append(tx_signed)
        self.tx_pool.clear()
        self.log(f"Signed {len(self.signed_pool)} transaction(s) and moved to signed pool ready for mining.")

    def clear_pending(self):
        self.tx_pool.clear()
        self.signed_pool.clear()
        self.log("Cleared pending and signed pools.")

    # ---------- Mining ----------
    def mine_block(self):
        if not self.signed_pool:
            messagebox.showwarning("No Transactions", "There are no signed transactions to include in a block.")
            return
        difficulty = int(self.difficulty.get())
        last_block = self.chain[-1]
        index = last_block["index"] + 1
        timestamp = now_iso()
        prev_hash = last_block["hash"]
        transactions = list(self.signed_pool)  # snapshot
        nonce = 0
        start = time.time()
        self.log(f"Mining block #{index} with difficulty {difficulty}... (this may take a few seconds)")
        # Simple PoW
        while True:
            hash_hex = compute_block_hash(index, timestamp, prev_hash, nonce, transactions, difficulty)
            if valid_proof(hash_hex, difficulty):
                break
            nonce += 1
            # let UI breathe occasionally
            if nonce % 50000 == 0:
                self.master.update()
        block = {
            "index": index,
            "timestamp": timestamp,
            "prev_hash": prev_hash,
            "nonce": nonce,
            "transactions": transactions,
            "difficulty": difficulty,
            "hash": hash_hex
        }
        self.chain.append(block)
        save_chain(self.chain)
        elapsed = time.time() - start
        self.signed_pool.clear()
        self.log(f"Mined block #{index} in {elapsed:.2f}s — nonce={nonce} hash={hash_hex}")
        messagebox.showinfo("Mined", f"Block #{index} mined in {elapsed:.2f} seconds.")

    # ---------- Chain & Verification ----------
    def list_chain(self):
        self.output_box.config(state='normal')
        self.output_box.delete("1.0", tk.END)
        for b in self.chain:
            self.output_box.insert(tk.END, json.dumps(b, indent=2) + "\n\n")
        self.output_box.config(state='disabled')
        self.log("Chain listed in output box.")

    def verify_chain(self):
        if missing:
            messagebox.showerror("Missing Dependency", "cryptography is required for signature verification.")
            return
        problems = []
        for i in range(1, len(self.chain)):
            prev = self.chain[i-1]
            cur = self.chain[i]
            # check prev_hash link
            if cur["prev_hash"] != prev["hash"]:
                problems.append(f"Broken link at block {cur['index']}: prev_hash mismatch.")
            # recompute hash and POW
            recomputed = compute_block_hash(cur["index"], cur["timestamp"], cur["prev_hash"], cur["nonce"], cur["transactions"], cur.get("difficulty", 3))
            if recomputed != cur["hash"]:
                problems.append(f"Hash mismatch at block {cur['index']}.")
            if not valid_proof(cur["hash"], cur.get("difficulty", 3)):
                problems.append(f"Invalid PoW at block {cur['index']}.")
            # verify transactions signatures
            for tx in cur["transactions"]:
                sig_b64 = tx.get("signature")
                if not sig_b64:
                    problems.append(f"Unsigned tx in block {cur['index']}.")
                    continue
                try:
                    sig = base64.b64decode(sig_b64.encode('utf-8'))
                    # tx payload is transaction without signature fields
                    tx_copy = dict(tx)
                    tx_copy.pop("signature", None)
                    tx_copy.pop("pub_pem_fp", None)
                    payload = json.dumps(tx_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
                    # We can't extract the exact public key from fingerprint alone. For demo, attempt verification using current loaded public key if fingerprint matches.
                    verified = False
                    if self.pub_pem_bytes and tx.get("pub_pem_fp") == pubkey_fingerprint(self.pub_pem_bytes):
                        verified = verify_signature(self.pub_key_obj, payload, sig)
                    else:
                        # signature verification not possible unless user provided public key for each tx
                        verified = False
                    if not verified:
                        problems.append(f"Signature verification failed for tx in block {cur['index']}.")
                except Exception as e:
                    problems.append(f"Signature parse error in block {cur['index']}: {e}")
        ok = not problems
        if ok:
            messagebox.showinfo("Chain Verified", "Chain and signatures appear VALID (with current public key).")
            self.log("Chain verification passed.")
        else:
            messagebox.showwarning("Chain Issues", "Problems detected — check output.")
            self.log("Chain verification found problems:\n" + "\n".join(problems))

    def reset_chain(self):
        confirm = messagebox.askyesno("Confirm Reset", "Delete entire chain file and start fresh (genesis only)?")
        if not confirm:
            return
        self.chain = default_genesis()
        save_chain(self.chain)
        self.log("Chain reset to genesis block.")
        messagebox.showinfo("Reset", "Chain reset to genesis.")

    def export_chain(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.chain, f, indent=2)
        messagebox.showinfo("Exported", f"Chain exported to {path}")

    # ---------- Logging ----------
    def log(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.output_box.config(state='normal')
        self.output_box.insert(tk.END, f"[{ts}] {message}\n")
        self.output_box.see(tk.END)
        self.output_box.config(state='disabled')


# ----------------- Run App -----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = LightweightBlockchainApp(root)
    root.mainloop()
