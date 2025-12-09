# watchDog.py - Real-Time Malware Dropper Protector (2025 Edition)
# Monitors Downloads, Desktop, Documents, Temp → Quarantines real threats instantly

import os
import json
import hashlib
import shutil
import struct
import math
import time
import getpass
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading

# ============================================================
# PATH SETUP (Works as script AND compiled .exe)
# ============================================================
if getattr(sys, 'frozen', False):
    APP_DIR = Path(sys.executable).parent
else:
    # When running as script, check if dist folder exists and use that
    script_dir = Path(__file__).parent
    dist_dir = script_dir / "dist"
    if dist_dir.exists() and (dist_dir / "quarantine").exists():
        APP_DIR = dist_dir
    else:
        APP_DIR = script_dir

LOG_FILE = APP_DIR / "watchdog.log"
QUARANTINE_FOLDER = APP_DIR / "quarantine"
BAD_HASHES_FILE = APP_DIR / "bad_hashes.json"

# Create required folders
QUARANTINE_FOLDER.mkdir(parents=True, exist_ok=True)

# ============================================================
# LOGGING
# ============================================================
def log_detection(path: Path, reason: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] DETECTED → {path} | Reason: {reason} | Quarantined to: {QUARANTINE_FOLDER}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
        print(entry.strip())  # Real-time console feedback
    except:
        pass

def debug_log(message: str):
    """Log debug messages to help troubleshoot"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] DEBUG: {message}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except:
        pass

# ============================================================
# CONFIG & SIGNATURES
# ============================================================
# Files that are ALWAYS quarantined immediately (highest risk)
AUTO_QUARANTINE_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs",
    ".jar", ".msi", ".hta", ".cpl", ".reg"
}

# Files that trigger deeper analysis
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".msi", ".lnk", ".reg", ".hta", ".cpl", ".msc", ".app"
}

IGNORE_EXTENSIONS = {".crdownload", ".tmp", ".part", ".partial"}

EICAR_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
}

MALWARE_API_CALLS = [
    b"CreateRemoteThread", b"WriteProcessMemory", b"VirtualAllocEx",
    b"ResumeThread", b"NtUnmapViewOfSection", b"ZwUnmapViewOfSection",
    b"SetWindowsHookEx", b"GetAsyncKeyState", b"IsDebuggerPresent"
]

MALWARE_STRINGS = [
    b"powershell.exe -w hidden", b"-ep bypass", b"-EncodedCommand",
    b"Invoke-Expression", b"DownloadString", b"WebClient", b"FromBase64String",
    b"SeDebugPrivilege", b"mimikatz", b"procdump", b"wallet.dat", b".onion"
]

PACKER_SIGNATURES = [b"UPX!", b"UPX0", b"UPX1", b"MZ\x90\x00", b"Themida", b"VMProtect", b".nsp"]

SUSPICIOUS_KEYWORDS = [
    "crack", "keygen", "patch", "loader", "injector", "hack", "exploit",
    "trojan", "virus", "ransomware", "backdoor", "mimikatz", "lazagne"
]

# ============================================================
# LOAD BAD HASHES
# ============================================================
if BAD_HASHES_FILE.exists():
    try:
        with open(BAD_HASHES_FILE, "r") as f:
            BAD_HASHES = set(json.load(f).get("sha256", []))
    except:
        BAD_HASHES = set()
else:
    BAD_HASHES = set()

# ============================================================
# CORE DETECTION FUNCTIONS
# ============================================================
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return ""

def file_entropy(path: Path) -> float:
    try:
        data = path.read_bytes()[:131072]  # First 128KB is enough
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        for count in freq:
            if count:
                p = count / len(data)
                entropy -= p * math.log2(p)
        return entropy
    except:
        return 0.0

def has_pe_header(path: Path) -> bool:
    try:
        return path.read_bytes(2) == b"MZ"
    except:
        return False

def is_packed(path: Path) -> bool:
    try:
        data = path.read_bytes(8192)
        if any(sig in data for sig in PACKER_SIGNATURES):
            return True
        if path.suffix.lower() in {".exe", ".dll"} and file_entropy(path) > 7.8:
            return True
    except:
        pass
    return False

def has_rtlo_spoof(path: Path) -> bool:
    return "\u202E" in path.name  # Right-to-Left Override

def has_double_extension_trick(path: Path) -> bool:
    name = path.name.lower()
    if name.count(".") < 2:
        return False
    
    parts = name.split(".")
    if len(parts) < 3:
        return False
        
    last_ext = "." + parts[-1]      # .exe
    prev_ext = "." + parts[-2]      # .pdf
    
    dangerous = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".lnk"}
    innocent = {".pdf", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".zip", ".rar", ".txt", ".docm"}
    
    return last_ext in dangerous and prev_ext in innocent

def is_malicious_lnk(path: Path) -> bool:
    if path.suffix.lower() != ".lnk":
        return False
    try:
        data = path.read_bytes(1024)
        suspicious = [b"powershell", b"cmd.exe", b"mshta", b"regsvr32", b"rundll32", b"certutil"]
        return any(s in data.lower() for s in suspicious)
    except:
        return False

def has_suspicious_script_patterns(path: Path) -> bool:
    if path.suffix.lower() not in {".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta"}:
        return False
    try:
        content = path.read_text(errors="ignore").lower()
        high_risk = ["invoke-expression", "iex(", "downloadstring", "downloadfile", "-encodedcommand", "frombase64string"]
        return any(p in content for p in high_risk)
    except:
        return False

def has_malicious_office_macro(path: Path) -> bool:
    if path.suffix.lower() not in {".doc", ".docx", ".xls", ".xlsx", ".rtf"}:
        return False
    try:
        text = path.read_text(errors="ignore").lower()
        return any(kw in text for kw in ["autoopen", "document_open", "workbook_open", "wscript.shell", "shell("])
    except:
        return False

def heuristic_score(path: Path) -> int:
    score = 0
    name_low = path.name.lower()

    # RTLO spoofing
    if has_rtlo_spoof(path):
        return 20

    # Double extension
    if has_double_extension_trick(path):
        score += 12

    # Suspicious keywords in name
    if any(kw in name_low for kw in SUSPICIOUS_KEYWORDS):
        score += 10

    # Tiny or huge executable
    try:
        size = path.stat().st_size
        if path.suffix.lower() in {".exe", ".dll", ".scr"} and 0 < size < 15_000:
            score += 10
        if size > 200_000_000:
            score += 5
    except:
        pass

    # High entropy / packed
    if is_packed(path):
        score += 10

    # Dangerous APIs or strings
    try:
        data = path.read_bytes(1048576)  # First 1MB
        if sum(api in data for api in MALWARE_API_CALLS) >= 3:
            score += 12
        if sum(s in data for s in MALWARE_STRINGS) >= 2:
            score += 10
    except:
        pass

    return score

# ============================================================
# QUARANTINE WITH FEEDBACK
# ============================================================
def move_to_quarantine(path: Path):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        counter = 1
        target_name = f"{timestamp}_{path.name}"
        target = QUARANTINE_FOLDER / target_name

        while target.exists():
            target_name = f"{timestamp}_{counter}_{path.name}"
            target = QUARANTINE_FOLDER / target_name
            counter += 1

        shutil.move(str(path), str(target))
        log_detection(path, f"QUARANTINED → {target_name}")
        return True
    except Exception as e:
        try:
            path.rename(path.with_suffix(path.suffix + ".BLOCKED"))
        except:
            pass
        return False

# ============================================================
# MAIN ANALYSIS
# ============================================================
def analyze_file(path: Path):
    try:
        if not path.exists() or not path.is_file():
            return

        # Skip temp download files
        if path.suffix.lower() in IGNORE_EXTENSIONS:
            return
        
        # === INSTANT BLOCK: HIGH-RISK FILE TYPES (Phishing Protection) ===
        if path.suffix.lower() in AUTO_QUARANTINE_EXTENSIONS:
            # Wait briefly for file to finish writing
            time.sleep(1)
            if not path.exists():
                return
            
            file_type = path.suffix.upper()
            debug_log(f"HIGH-RISK FILE TYPE DETECTED: {file_type} - {path.name}")
            log_detection(path, f"{file_type} FILE - Auto-quarantined for security (Phishing Protection)")
            move_to_quarantine(path)
            return
        
        # For other files, wait for completion before analyzing
        max_wait = 10
        for attempt in range(max_wait):
            try:
                before = path.stat().st_size
                time.sleep(0.5)
                if not path.exists():
                    return
                after = path.stat().st_size
                if before == after and before > 0:
                    break
            except Exception:
                return
    except Exception as e:
        debug_log(f"Error in analyze_file: {path} - {e}")

    # === Instant Block Rules (Fast) ===
    if has_rtlo_spoof(path):
        move_to_quarantine(path)
        return

    if has_double_extension_trick(path):
        move_to_quarantine(path)
        return

    if is_malicious_lnk(path):
        move_to_quarantine(path)
        return

    if has_suspicious_script_patterns(path):
        move_to_quarantine(path)
        return

    if has_malicious_office_macro(path):
        move_to_quarantine(path)
        return

    # === Hash & EICAR ===
    file_hash = sha256_file(path)
    if file_hash in BAD_HASHES or file_hash in EICAR_HASHES:
        move_to_quarantine(path)
        return

    # === Heuristic Scoring ===
    score = heuristic_score(path)
    if score >= 12:
        log_detection(path, f"HEURISTIC DETECTION (Score: {score})")
        move_to_quarantine(path)
        return

# ============================================================
# WATCHDOG HANDLER
# ============================================================
class WatchDogHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        debug_log(f"File created event: {path.name}")
        # Use thread to avoid blocking the observer
        threading.Thread(target=analyze_file, args=(path,), daemon=True).start()

    def on_modified(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        debug_log(f"File modified event: {path.name}")
        # Only analyze dangerous file types on modification
        if path.suffix.lower() in DANGEROUS_EXTENSIONS:
            threading.Thread(target=analyze_file, args=(path,), daemon=True).start()

    def on_moved(self, event):
        """Catch files that are moved/renamed (common with browser downloads)"""
        if event.is_directory:
            return
        path = Path(event.dest_path)
        debug_log(f"File moved/renamed event: {path.name}")
        # Use thread to avoid blocking the observer
        threading.Thread(target=analyze_file, args=(path,), daemon=True).start()

# ============================================================
# GUI FOR QUARANTINE MANAGEMENT
# ============================================================
class QuarantineGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WatchDog - Quarantine Manager")
        self.root.geometry("900x600")
        self.root.configure(bg="#2b2b2b")
        
        # Header
        header = tk.Frame(root, bg="#1e1e1e", height=60)
        header.pack(fill=tk.X, pady=(0, 10))
        
        title = tk.Label(header, text="🛡️ Quarantine Manager", 
                        font=("Segoe UI", 18, "bold"), 
                        bg="#1e1e1e", fg="#ffffff")
        title.pack(pady=15)
        
        # Info Frame
        info_frame = tk.Frame(root, bg="#2b2b2b")
        info_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        self.count_label = tk.Label(info_frame, text="", 
                                    font=("Segoe UI", 10), 
                                    bg="#2b2b2b", fg="#cccccc")
        self.count_label.pack(side=tk.LEFT)
        
        self.path_label = tk.Label(info_frame, 
                                   text=f"Location: {QUARANTINE_FOLDER.absolute()}", 
                                   font=("Segoe UI", 9), 
                                   bg="#2b2b2b", fg="#888888")
        self.path_label.pack(side=tk.RIGHT)
        
        # Treeview Frame
        tree_frame = tk.Frame(root, bg="#2b2b2b")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        # Treeview
        self.tree = ttk.Treeview(tree_frame, 
                                columns=("filename", "original_name", "size", "date"), 
                                show="headings",
                                yscrollcommand=vsb.set,
                                xscrollcommand=hsb.set)
        
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        # Column headings
        self.tree.heading("filename", text="Quarantine Filename")
        self.tree.heading("original_name", text="Original Name")
        self.tree.heading("size", text="Size")
        self.tree.heading("date", text="Quarantine Date")
        
        # Column widths
        self.tree.column("filename", width=250)
        self.tree.column("original_name", width=200)
        self.tree.column("size", width=100)
        self.tree.column("date", width=150)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                       background="#1e1e1e",
                       foreground="#ffffff",
                       fieldbackground="#1e1e1e",
                       borderwidth=0)
        style.configure("Treeview.Heading",
                       background="#333333",
                       foreground="#ffffff",
                       relief="flat")
        style.map("Treeview",
                 background=[("selected", "#0078d4")])
        
        # Button Frame
        btn_frame = tk.Frame(root, bg="#2b2b2b")
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        # Buttons
        btn_style = {"font": ("Segoe UI", 10), "width": 15, "height": 2}
        
        self.refresh_btn = tk.Button(btn_frame, text="🔄 Refresh", 
                                     bg="#0078d4", fg="white",
                                     command=self.load_files, **btn_style)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        self.restore_btn = tk.Button(btn_frame, text="↩️ Restore File", 
                                     bg="#107c10", fg="white",
                                     command=self.restore_file, **btn_style)
        self.restore_btn.pack(side=tk.LEFT, padx=5)
        
        self.delete_btn = tk.Button(btn_frame, text="🗑️ Delete File", 
                                    bg="#d13438", fg="white",
                                    command=self.delete_file, **btn_style)
        self.delete_btn.pack(side=tk.LEFT, padx=5)
        
        self.delete_all_btn = tk.Button(btn_frame, text="🗑️ Delete All", 
                                       bg="#8b0000", fg="white",
                                       command=self.delete_all_files, **btn_style)
        self.delete_all_btn.pack(side=tk.LEFT, padx=5)
        
        self.info_btn = tk.Button(btn_frame, text="ℹ️ File Info", 
                                 bg="#5a5a5a", fg="white",
                                 command=self.show_file_info, **btn_style)
        self.info_btn.pack(side=tk.LEFT, padx=5)
        
        # Load files
        self.load_files()
    
    def load_files(self):
        """Load all quarantined files into the treeview"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Ensure quarantine folder exists
        QUARANTINE_FOLDER.mkdir(parents=True, exist_ok=True)
        
        if not QUARANTINE_FOLDER.exists():
            self.count_label.config(text="Quarantined Files: 0")
            return
        
        files = list(QUARANTINE_FOLDER.glob("*"))
        files = [f for f in files if f.is_file()]
        
        for file_path in sorted(files, key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                # Get file info
                stat = file_path.stat()
                size = self.format_size(stat.st_size)
                mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                
                # Extract original name from quarantine name
                # Format: YYYYMMDD_HHMMSS_originalname or YYYYMMDD_HHMMSS_counter_originalname
                parts = file_path.name.split("_", 3)
                if len(parts) >= 3:
                    original_name = parts[-1]
                else:
                    original_name = file_path.name
                
                self.tree.insert("", "end", values=(
                    file_path.name,
                    original_name,
                    size,
                    mtime
                ))
            except Exception as e:
                print(f"Error loading file {file_path}: {e}")
        
        self.count_label.config(text=f"Quarantined Files: {len(files)}")
    
    def format_size(self, bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024.0:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.1f} TB"
    
    def get_selected_file(self):
        """Get the selected file path"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file first.")
            return None
        
        item = self.tree.item(selection[0])
        filename = item['values'][0]
        return QUARANTINE_FOLDER / filename
    
    def restore_file(self):
        """Restore a quarantined file to Desktop"""
        file_path = self.get_selected_file()
        if not file_path:
            return
        
        # Ask for confirmation
        response = messagebox.askyesno(
            "Restore File",
            f"Restore '{file_path.name}' to Desktop?\n\n⚠️ WARNING: This file was quarantined as potentially malicious!"
        )
        
        if not response:
            return
        
        try:
            username = getpass.getuser()
            desktop = Path(f"C:/Users/{username}/Desktop")
            
            # Extract original name
            parts = file_path.name.split("_", 3)
            original_name = parts[-1] if len(parts) >= 3 else file_path.name
            
            target = desktop / original_name
            counter = 1
            while target.exists():
                name_part = target.stem
                ext_part = target.suffix
                target = desktop / f"{name_part}_{counter}{ext_part}"
                counter += 1
            
            shutil.move(str(file_path), str(target))
            messagebox.showinfo("Success", f"File restored to:\n{target}")
            self.load_files()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore file:\n{e}")
    
    def delete_file(self):
        """Permanently delete a quarantined file"""
        file_path = self.get_selected_file()
        if not file_path:
            return
        
        response = messagebox.askyesno(
            "Delete File",
            f"Permanently delete '{file_path.name}'?\n\nThis action cannot be undone!"
        )
        
        if not response:
            return
        
        try:
            file_path.unlink()
            messagebox.showinfo("Success", "File deleted successfully.")
            self.load_files()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete file:\n{e}")
    
    def delete_all_files(self):
        """Delete all quarantined files"""
        files = list(QUARANTINE_FOLDER.glob("*"))
        files = [f for f in files if f.is_file()]
        
        if not files:
            messagebox.showinfo("Info", "No files to delete.")
            return
        
        response = messagebox.askyesno(
            "Delete All Files",
            f"Permanently delete ALL {len(files)} quarantined files?\n\n⚠️ This action cannot be undone!"
        )
        
        if not response:
            return
        
        try:
            deleted = 0
            for file_path in files:
                try:
                    file_path.unlink()
                    deleted += 1
                except:
                    pass
            
            messagebox.showinfo("Success", f"Deleted {deleted} file(s).")
            self.load_files()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete files:\n{e}")
    
    def show_file_info(self):
        """Show detailed information about selected file"""
        file_path = self.get_selected_file()
        if not file_path:
            return
        
        try:
            stat = file_path.stat()
            file_hash = sha256_file(file_path)
            entropy = file_entropy(file_path)
            
            info = f"""File Information:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Name: {file_path.name}
Size: {self.format_size(stat.st_size)} ({stat.st_size:,} bytes)
Quarantined: {datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")}
SHA-256: {file_hash}
Entropy: {entropy:.2f}
Extension: {file_path.suffix}
Path: {file_path}
"""
            
            # Create info window
            info_window = tk.Toplevel(self.root)
            info_window.title("File Information")
            info_window.geometry("600x400")
            info_window.configure(bg="#2b2b2b")
            
            text_widget = scrolledtext.ScrolledText(
                info_window,
                wrap=tk.WORD,
                font=("Consolas", 10),
                bg="#1e1e1e",
                fg="#ffffff",
                insertbackground="#ffffff"
            )
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_widget.insert("1.0", info)
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get file info:\n{e}")

def open_quarantine_gui():
    """Open the quarantine GUI"""
    root = tk.Tk()
    app = QuarantineGUI(root)
    root.mainloop()

# ============================================================
# START MONITORING
# ============================================================
def scan_existing_files(paths):
    """Scan all existing files in monitored folders on startup"""
    scanned = 0
    quarantined = 0
    
    for folder in paths:
        if not folder.exists():
            continue
        
        try:
            # Scan all files in the folder (including subdirectories)
            for file_path in folder.rglob("*"):
                if file_path.is_file():
                    try:
                        analyze_file(file_path)
                        scanned += 1
                        # Check if file was quarantined (no longer exists)
                        if not file_path.exists():
                            quarantined += 1
                    except Exception as e:
                        pass
        except Exception as e:
            pass

def start_watcher():
    username = getpass.getuser()
    base = Path(f"C:/Users/{username}")

    watch_paths = [
        base / "Downloads",
        base / "Desktop",
        base / "Documents",
        base / "AppData/Local/Temp",
    ]

    debug_log(f"WatchDog Starting - User: {username}")
    debug_log(f"Quarantine folder: {QUARANTINE_FOLDER}")

    observer = Observer()
    handler = WatchDogHandler()
    
    # Perform initial scan of existing files (in background thread to not block)
    debug_log("Starting initial scan in background...")
    threading.Thread(target=scan_existing_files, args=(watch_paths,), daemon=True).start()

    for path in watch_paths:
        if path.exists():
            observer.schedule(handler, str(path), recursive=True)
            debug_log(f"Monitoring: {path}")

    observer.start()
    debug_log("Real-time monitoring started - WatchDog is now active")
    
    try:
        while observer.is_alive():
            observer.join(1)
    except KeyboardInterrupt:
        debug_log("WatchDog stopped by user")
    except Exception as e:
        debug_log(f"WatchDog error: {e}")
    finally:
        observer.stop()
        observer.join()
        debug_log("WatchDog stopped")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="WatchDog - Real-Time Malware Protector")
    parser.add_argument("--gui", action="store_true", help="Open Quarantine Manager GUI")
    args = parser.parse_args()
    
    if args.gui:
        open_quarantine_gui()
    else:
        start_watcher()
