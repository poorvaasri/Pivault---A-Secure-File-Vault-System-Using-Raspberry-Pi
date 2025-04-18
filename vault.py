# ---------------- IMPORTS ----------------
import os, hashlib, csv
from tkinter import *
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from ttkthemes import ThemedTk
from cryptography.fernet import Fernet
from datetime import datetime

# ---------------- CONFIG PATHS ----------------
KEY_FILE = "key.key"
LOG_FILE = "log.csv"
VAULT_DIR = "vault/"
PASSWORD_HASH_FILE = "password.hash"

# ---------------- SETUP ON FIRST RUN ----------------
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    print("[+] Key generated.")

def load_key():
    return open(KEY_FILE, "rb").read()

def setup():
    if not os.path.exists(KEY_FILE):
        generate_key()
    if not os.path.exists(PASSWORD_HASH_FILE):
        root = Tk()
        root.withdraw()
        pwd = simpledialog.askstring("Setup", "Set your vault password:", show='*')
        root.destroy()
        with open(PASSWORD_HASH_FILE, "w") as f:
            f.write(hashlib.sha256(pwd.encode()).hexdigest())
        print("[+] Password set.")
    if not os.path.exists(VAULT_DIR):
        os.makedirs(VAULT_DIR)
        print("[+] Vault directory created.")

# ---------------- AUTH SYSTEM ----------------
def verify_password(input_pwd):
    with open(PASSWORD_HASH_FILE, "r") as f:
        stored_hash = f.read()
    return hashlib.sha256(input_pwd.encode()).hexdigest() == stored_hash

# ---------------- ENCRYPTION / DECRYPTION ----------------
def encrypt_file(path):
    key = load_key()
    f = Fernet(key)
    with open(path, "rb") as file:
        data = file.read()
    encrypted = f.encrypt(data)
    with open(path, "wb") as file:
        file.write(encrypted)
    log_event(f"Encrypted: {os.path.basename(path)}")
    print(f"[+] Encrypted {os.path.basename(path)}")

def decrypt_file(encrypted_path, restore_path):
    key = load_key()
    f = Fernet(key)
    with open(encrypted_path, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(restore_path, "wb") as file:
        file.write(decrypted_data)
    os.remove(encrypted_path)
    log_event(f"Decrypted & Restored: {os.path.basename(restore_path)}")
    print(f"[+] Decryption complete. File restored to {restore_path}")
    print(f"[-] Removed from vault: {os.path.basename(encrypted_path)}")

# ---------------- LOGGING ----------------
def log_event(event):
    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event])

# ---------------- GUI ----------------
def open_vault():
    root = ThemedTk(theme="arc")
    root.title("🔐 PiVault Secure Vault")
    root.attributes('-fullscreen', True)

    style = ttk.Style()
    style.configure("TButton", font=("Segoe UI", 12), padding=10)
    style.configure("TLabel", font=("Segoe UI", 14))

    main_frame = Frame(root, bg="#1f1f2e")
    main_frame.pack(fill=BOTH, expand=True)

    header = Label(main_frame, text="🔐 PiVault - Advanced Secure File Vault", font=("Segoe UI", 28, "bold"), bg="#1f1f2e", fg="#F0DB4F")
    header.pack(pady=30)

    btn_frame = Frame(main_frame, bg="#1f1f2e")
    btn_frame.pack(pady=20)

    def upload_file():
        path = filedialog.askopenfilename()
        if path:
            filename = os.path.basename(path)
            vault_path = os.path.join(VAULT_DIR, filename)
            with open(path, "rb") as src, open(vault_path, "wb") as dst:
                dst.write(src.read())
            encrypt_file(vault_path)
            try:
                with open(path, "w") as original:
                    original.write("ACCESS DENIED: FILE ENCRYPTED BY PIVAULT 🔐\n")
                    original.write("".join([chr((i % 95) + 32) for i in range(1000)]))
                print(f"[~] Original file overwritten: {path}")
            except Exception as e:
                print(f"[!] Could not overwrite original file: {e}")
            messagebox.showinfo("Upload", "File uploaded and encrypted successfully.")
            log_event(f"Uploaded: {filename}")
            update_logs()

    def browse_vault():
        files = os.listdir(VAULT_DIR)
        visible_files = [f for f in files if not f.startswith('.')]
        msg = "\n".join(visible_files) if visible_files else "Vault is empty."
        messagebox.showinfo("Vault Contents", msg)
        print("[*] Vault contents listed.")

    def decrypt_selected_file():
        encrypted_file = filedialog.askopenfilename(initialdir=VAULT_DIR, title="Select Encrypted File")
        if encrypted_file:
            filename = os.path.basename(encrypted_file)
            restore_path = filedialog.asksaveasfilename(title="Restore Decrypted File As", initialfile=filename)
            if restore_path:
                try:
                    decrypt_file(encrypted_file, restore_path)
                    messagebox.showinfo("Decryption", f"File decrypted and restored to:\n{restore_path}")
                    update_logs()
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")
                    print(f"[!] Decryption error: {e}")

    def logout():
        messagebox.showinfo("Logout", "Session ended.")
        print("[x] Logged out.")
        root.destroy()

    def update_logs():
        log_text.config(state=NORMAL)
        log_text.delete(1.0, END)
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                reader = csv.reader(f)
                for row in reader:
                    log_text.insert(END, f"{row[0]} - {row[1]}\n")
        log_text.config(state=DISABLED)

    Button(btn_frame, text="📤 Upload & Encrypt File", width=30, command=upload_file).grid(row=0, column=0, padx=20, pady=10)
    Button(btn_frame, text="📁 Content", width=30, command=browse_vault).grid(row=0, column=1, padx=20, pady=10)
    Button(btn_frame, text="🔓 Decrypt", width=30, command=decrypt_selected_file).grid(row=1, column=0, padx=20, pady=10)

    Label(main_frame, text="Activity Log:", font=("Segoe UI", 16, "bold"), bg="#1f1f2e", fg="#F0DB4F").pack(pady=(30, 5))
    log_text = Text(main_frame, height=15, width=100, bg="#1f1f2e", fg="white", insertbackground="white", font=("Consolas", 11), state=DISABLED, borderwidth=2, relief=GROOVE)
    log_text.pack(pady=(0, 10))
    update_logs()

    Button(main_frame, text="🚪 Logout", command=logout, width=20).pack(pady=(10, 30))

    print("[*] Vault interface ready.")
    root.mainloop()

# ---------------- LOGIN SCREEN ----------------
def login_screen():
    login = ThemedTk(theme="arc")
    login.title("Login to PiVault")
    login.geometry("400x250")
    login.configure(bg="#2e2e3a")

    Label(login, text="🔐 Enter Vault Password", font=("Segoe UI", 16, "bold"), bg="#2e2e3a", fg="white").pack(pady=25)
    pwd_entry = Entry(login, show='*', width=30, font=("Segoe UI", 12))
    pwd_entry.pack(pady=10)

    def check_login():
        if verify_password(pwd_entry.get()):
            print("[+] Login successful.")
            login.destroy()
            open_vault()
        else:
            print("[!] Wrong password.")
            messagebox.showerror("Access Denied", "Wrong password.")

    Button(login, text="Login", command=check_login, width=20).pack(pady=20)
    print("[*] Login screen displayed.")
    login.mainloop()

# ---------------- MAIN ----------------
if __name__ == "__main__":
    setup()
    print("[*] PiVault starting...")
    login_screen()
