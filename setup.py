# setup.py - First-time setup for SecureLock (Final Clean Version)
import os, sys, hashlib, random, string
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import win32com.client, time, re

APP_NAME = "SecureLock"
APPDATA = os.path.join(os.environ["APPDATA"], APP_NAME)
CONFIG = os.path.join(APPDATA, "config.ini")
PASSFILE = os.path.join(APPDATA, "secure.dat")
WATCHDOG = "watchdog_service.exe"  # Name of your watchdog file

os.makedirs(APPDATA, exist_ok=True)

def create_config():
    key = Fernet.generate_key().decode()
    with open(CONFIG, "w") as f:
        f.write("MAX_RETRY_ATTEMPTS = 3\n")
        f.write("ENCRYPTED_DATA = False\n")
        f.write(f"ENCRYPTION_KEY = {key}\n")

def is_strong_password(password: str) -> bool:
    """
    Validates password strength.
    Returns (True) if strong.
    Otherwise returns (False, reason).
    """

    # Minimum length requirement
    if len(password) < 8:
        return False

    # At least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return False

    # At least one lowercase letter
    if not re.search(r"[a-z]", password):
        return False

    # At least one digit
    if not re.search(r"[0-9]", password):
        return False

    # At least one special character
    if not re.search(r"[!@#$%^&*()\-_=+{}\[\]:;\"'<>,.?/]", password):
        return False

    # No spaces allowed
    if " " in password:
        return False

    # Prevent 3 identical characters in a row
    if re.search(r"(.)\1\1", password):
        return False

    # Common weak passwords blacklist
    weak_list = ["password", "123456", "qwerty", "admin", "letmein"]
    if password.lower() in weak_list:
        return False

    return True

def set_password_and_recovery():
    # Main setup window - same style as securelock.py
    setup = tk.Tk()
    setup.title("SecureLock - First Time Setup")
    setup.configure(bg="#0d1b2a")
    setup.geometry("560x680")
    setup.resizable(False, False)

    # Center on screen
    setup.update_idletasks()
    x = (setup.winfo_screenwidth() // 2) - (560 // 2)
    y = (setup.winfo_screenheight() // 2) - (680 // 2)
    setup.geometry(f"+{x}+{y}")

    # Title
    tk.Label(setup, text="SecureLock", font=("Arial", 34, "bold"), fg="#00ff9d", bg="#0d1b2a").pack(pady=20)
    tk.Label(setup, text="Protect Your Desktop", font=("Arial", 16), fg="#aaaaaa", bg="#0d1b2a").pack(pady=5)

    # Password Section
    tk.Label(setup, text="Choose a strong password", font=("Arial", 12), fg="#dddddd", bg="#0d1b2a").pack(pady=(30, 10))

    pw1 = tk.Entry(setup, show="*", font=("Arial", 18), justify="center", width=28, bg="#1b263b", fg="white", relief="flat", highlightthickness=2, highlightcolor="#00ff9d", insertbackground="white")
    pw1.pack(pady=8)
    pw1.focus()

    pw2 = tk.Entry(setup, show="*", font=("Arial", 18), justify="center", width=28, bg="#1b263b", fg="white", relief="flat", highlightthickness=2, highlightcolor="#00ff9d", insertbackground="white")
    pw2.pack(pady=8)

    # Recovery Code Section
    recovery_var = tk.StringVar(value="Click button to generate")

    def generate_recovery():
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
        recovery_var.set(code)
        msg = tk.Toplevel(setup)
        msg.title("RECOVERY CODE - SAVE NOW")
        msg.configure(bg="#0d1b2a")
        msg.geometry("600x300")
        msg.transient(setup)
        msg.grab_set()

        tk.Label(msg, text="YOUR RECOVERY CODE", font=("Arial", 18, "bold"), fg="#ff4444", bg="#0d1b2a").pack(pady=20)
        tk.Label(msg, text=code, font=("Courier", 20, "bold"), fg="#00ff9d", bg="#0d1b2a", relief="sunken", padx=20, pady=10).pack(pady=10)
        tk.Label(msg, text="Write this down!\nYou will NOT see it again!", font=("Arial", 12), fg="#ffffff", bg="#0d1b2a").pack(pady=10)

        def save_to_file():
            save_path = filedialog.askdirectory(title="Save Recovery Code")
            if save_path:
                with open(os.path.join(save_path, "SecureLock_Recovery_Code.txt"), "w") as f:
                    f.write(f"SecureLock Recovery Code\nGenerated: {time.strftime('%Y-%m-%d %H:%M')}\n\nCode: {code}\n\nKeep this safe!")
                messagebox.showinfo("Saved", f"Recovery code saved to:\n{save_path}")

        tk.Button(msg, text="Save to File", command=save_to_file, bg="#00ff9d", fg="black", font=("Arial", 12, "bold")).pack(pady=10)
        msg.geometry(f"+{setup.winfo_rootx() + 50}+{setup.winfo_rooty() + 100}")

    tk.Label(setup, text="Recovery Code (in case you forget password)", font=("Arial", 11), fg="#bbbbbb", bg="#0d1b2a").pack(pady=(30, 5))
    tk.Label(setup, textvariable=recovery_var, font=("Courier", 16), fg="#00ff9d", bg="#0d1b2a", relief="groove", padx=15, pady=10).pack(pady=10)

    tk.Button(setup, text="Generate Recovery Code", command=generate_recovery, bg="#334466", fg="white", font=("Arial", 11, "bold"), width=24).pack(pady=5)

    status = tk.Label(setup, text="", fg="#ff6666", bg="#0d1b2a", font=("Arial", 11))

    def finalize_setup():
        password = pw1.get()
        confirm = pw2.get()
        recovery = recovery_var.get()

        if not is_strong_password(password=password):
            status.config(text="Minimum 8 characters.\nAt least 1 uppercase.\nAt least 1 lowercase.\nAt least 1 number.\nAt least 1 special character.\nNo spaces allowed.\nNo repeated characters more than 3 times.\nMust not match common weak passwords.")
            return
        if not password or len(password) < 4:
            status.config(text="Password too short!")
            return
        if password != confirm:
            status.config(text="Passwords do not match!")
            return
        if recovery == "Click button to generate" or len(recovery) != 16:
            status.config(text="Generate a valid recovery code first!")
            return

        # Save encrypted password + recovery hashes (same as original)
        key = None
        with open(CONFIG, "r") as f:
            for line in f:
                if line.startswith("ENCRYPTION_KEY"):
                    key = line.split(" = ", 1)[1].strip().encode()
                    break
        fernet = Fernet(key)
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        rec_hash = hashlib.sha256(recovery.encode()).hexdigest()
        encrypted = fernet.encrypt(f"{pw_hash}\n{rec_hash}".encode())
        with open(PASSFILE, "wb") as f:
            f.write(encrypted)

        messagebox.showinfo("Setup Complete", "SecureLock is now active!\n\nReboot to test the lock screen.", parent=setup)
        setup.destroy()

    status.pack(pady=5)
    tk.Button(setup, text="Finish Setup", command=finalize_setup, bg="#00ff9d", fg="black", font=("Arial", 16, "bold"), width=20, height=2).pack(pady=1)

    setup.mainloop()
    # setup.destroy()

def add_to_startup():
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folder = scheduler.GetFolder("\\")
        task = scheduler.NewTask(0)

        task.RegistrationInfo.Description = "SecureLock Watchdog"
        task.Principal.RunLevel = 1  # Highest
        task.Settings.Enabled = True
        task.Settings.Hidden = False
        task.Settings.StartWhenAvailable = True
        task.Settings.AllowHardTerminate = False   # ← this one always works
        task.Settings.RunOnlyIfIdle = False
        task.Settings.DisallowStartIfOnBatteries = False
        task.Settings.StopIfGoingOnBatteries = False
        task.Settings.RunOnlyIfNetworkAvailable = False

        trigger = task.Triggers.Create(9)  # Logon trigger

        action = task.Actions.Create(0)
        action.Path = WATCHDOG
        action.WorkingDirectory = APPDATA

        folder.RegisterTaskDefinition(
            "SecureLock_Watchdog",
            task,
            6, "", "",
            3  # Interactive logon
        )
        messagebox.showinfo("Startup", "SecureLock will now start automatically on login!")
    except Exception as e:
        messagebox.showerror("Task Failed", f"Could not add to startup:\n{e}")

# ===================== MAIN =====================
if __name__ == "__main__":
    if os.path.exists(PASSFILE):
        if messagebox.askyesno("Already Setup", "SecureLock is already configured.\nRe-run setup anyway? (will overwrite)"):
            os.remove(PASSFILE)
        else:
            sys.exit()

    create_config()
    set_password_and_recovery()
    add_to_startup()

    messagebox.showinfo("Setup Complete", 
        "SecureLock is ready!\n\n"
        "→ Reboot your PC now.\n"
        "→ The lock screen will appear on startup.\n"
        "→ 3 wrong attempts = all files encrypted.\n"
        "→ Only your recovery code can save you.")