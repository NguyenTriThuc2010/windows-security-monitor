"""
File Monitor - Giám sát file system
Phát hiện: file malware mới tạo, thay đổi file hệ thống, ransomware behavior
"""

import os
import time
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from typing import Callable, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# Thư mục nhạy cảm cần giám sát
MONITORED_DIRS = [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    os.path.join(os.environ.get("APPDATA", ""), "Roaming") if os.environ.get("APPDATA") else "",
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp") if os.environ.get("LOCALAPPDATA") else "",
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\ProgramData",
]

# Extension file thực thi - đáng ngờ nếu xuất hiện ở thư mục thường
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jar", ".com", ".scr", ".pif", ".hta", ".wsf", ".msi",
    ".reg", ".inf", ".sys", ".drv",
}

# Extension file bị ransomware mã hóa
RANSOMWARE_EXTENSIONS = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypto",
    ".vault", ".ecc", ".ezz", ".exx", ".zzz", ".aaa", ".abc",
    ".locky", ".zepto", ".odin", ".shit", ".thor", ".aesir",
    ".wnry", ".wncry", ".wannacry", ".cerber", ".cerber2",
    ".dharma", ".phobos", ".stop", ".djvu", ".rumba",
}

# File quan trọng không nên thay đổi
PROTECTED_SYSTEM_FILES = [
    "C:\\Windows\\System32\\ntoskrnl.exe",
    "C:\\Windows\\System32\\lsass.exe",
    "C:\\Windows\\System32\\csrss.exe",
    "C:\\Windows\\System32\\winlogon.exe",
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\smss.exe",
    "C:\\Windows\\System32\\userinit.exe",
]

# Hash của các file hệ thống bình thường đã biết (MD5)
KNOWN_MALWARE_HASHES = {
    # Thêm hash malware vào đây khi cần
    # "d41d8cd98f00b204e9800998ecf8427e": "Empty file (placeholder)",
}


def get_file_hash(filepath: str, algo="md5") -> str:
    """Tính hash của file"""
    try:
        h = hashlib.new(algo)
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except:
        return ""


class SuspiciousFileHandler(FileSystemEventHandler):
    """Handler phát hiện file bất thường"""

    def __init__(self, alert_callback: Callable, logger, alerted_files: Set):
        super().__init__()
        self.alert_callback = alert_callback
        self.logger = logger
        self.alerted_files = alerted_files
        self.recent_changes = {}  # path -> list of timestamps
        self.lock = threading.Lock()

    def on_created(self, event):
        if event.is_directory:
            return
        self._check_new_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._check_modified_file(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self._check_renamed_file(event.src_path, event.dest_path)

    def _check_new_file(self, filepath: str):
        """Kiểm tra file mới tạo"""
        if filepath in self.alerted_files:
            return

        ext = Path(filepath).suffix.lower()

        # File thực thi mới ở thư mục không phải program files
        if ext in SUSPICIOUS_EXTENSIONS:
            is_suspicious_location = True
            trusted = ["C:\\Program Files", "C:\\Program Files (x86)", "C:\\Windows"]
            for trusted_path in trusted:
                if filepath.lower().startswith(trusted_path.lower()):
                    is_suspicious_location = False
                    break

            if is_suspicious_location:
                self.alerted_files.add(filepath)

                # Kiểm tra hash malware
                file_hash = get_file_hash(filepath)
                hash_info = ""
                if file_hash and file_hash in KNOWN_MALWARE_HASHES:
                    hash_info = f" [KNOWN MALWARE: {KNOWN_MALWARE_HASHES[file_hash]}]"

                self.alert_callback({
                    "module": "FileMonitor",
                    "severity": "HIGH" if not hash_info else "CRITICAL",
                    "type": "SUSPICIOUS_FILE_CREATED",
                    "message": f"File thực thi mới tạo ở vị trí đáng ngờ{hash_info}:\n{filepath}",
                    "file": filepath
                })

        # Extension ransomware
        if ext in RANSOMWARE_EXTENSIONS:
            self.alerted_files.add(filepath)
            self.alert_callback({
                "module": "FileMonitor",
                "severity": "CRITICAL",
                "type": "RANSOMWARE_DETECTED",
                "message": f"🚨 RANSOMWARE! File với extension mã hóa được tạo: {filepath}",
                "file": filepath
            })

    def _check_modified_file(self, filepath: str):
        """Kiểm tra file bị thay đổi"""
        # Theo dõi tần suất thay đổi file (ransomware thay đổi nhiều file liên tục)
        with self.lock:
            now = time.time()
            if filepath not in self.recent_changes:
                self.recent_changes[filepath] = []
            self.recent_changes[filepath].append(now)

            # Giữ chỉ 60 giây gần nhất
            self.recent_changes[filepath] = [
                t for t in self.recent_changes[filepath] if now - t < 60
            ]

        # Kiểm tra file hệ thống bị thay đổi
        for protected in PROTECTED_SYSTEM_FILES:
            if filepath.lower() == protected.lower():
                self.alert_callback({
                    "module": "FileMonitor",
                    "severity": "CRITICAL",
                    "type": "SYSTEM_FILE_MODIFIED",
                    "message": f"🚨 File hệ thống QUAN TRỌNG bị thay đổi: {filepath}",
                    "file": filepath
                })

    def _check_renamed_file(self, src: str, dst: str):
        """Kiểm tra file bị đổi tên (ransomware behavior)"""
        dst_ext = Path(dst).suffix.lower()

        if dst_ext in RANSOMWARE_EXTENSIONS:
            self.alert_callback({
                "module": "FileMonitor",
                "severity": "CRITICAL",
                "type": "RANSOMWARE_RENAME",
                "message": f"🚨 RANSOMWARE! File bị đổi sang extension mã hóa:\n{src} -> {dst}",
                "file": dst
            })

    def detect_mass_encryption(self):
        """Phát hiện mã hóa hàng loạt (ransomware)"""
        with self.lock:
            now = time.time()
            # Đếm số file thay đổi trong 60 giây
            recent_count = sum(
                1 for changes in self.recent_changes.values()
                if any(now - t < 60 for t in changes)
            )
            return recent_count


class FileMonitor:
    """Monitor giám sát file system"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.observer = None
        self.alerted_files: Set[str] = set()
        self.stats = {
            "files_monitored": 0,
            "suspicious_files": 0,
            "ransomware_alerts": 0,
            "last_scan": None
        }
        self.recent_events = []

    def scan_existing_suspicious_files(self):
        """Quét file đáng ngờ đang tồn tại"""
        scan_dirs = [
            os.environ.get("TEMP", ""),
            os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
            os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
            "C:\\ProgramData",
        ]

        for scan_dir in scan_dirs:
            if not scan_dir or not os.path.isdir(scan_dir):
                continue

            try:
                for root, dirs, files in os.walk(scan_dir):
                    # Skip quá sâu
                    depth = root[len(scan_dir):].count(os.sep)
                    if depth > 3:
                        dirs.clear()
                        continue

                    for fname in files:
                        fpath = os.path.join(root, fname)
                        ext = Path(fpath).suffix.lower()

                        self.stats["files_monitored"] += 1

                        # Kiểm tra ransomware extension
                        if ext in RANSOMWARE_EXTENSIONS:
                            self.stats["ransomware_alerts"] += 1
                            self.alert_callback({
                                "module": "FileMonitor",
                                "severity": "CRITICAL",
                                "type": "RANSOMWARE_FILE_FOUND",
                                "message": f"File ransomware được tìm thấy: {fpath}",
                                "file": fpath
                            })

                        # Kiểm tra hash malware
                        if ext in SUSPICIOUS_EXTENSIONS:
                            file_hash = get_file_hash(fpath)
                            if file_hash and file_hash in KNOWN_MALWARE_HASHES:
                                self.alert_callback({
                                    "module": "FileMonitor",
                                    "severity": "CRITICAL",
                                    "type": "KNOWN_MALWARE_HASH",
                                    "message": f"File khớp hash malware đã biết: {fpath}\nHash: {file_hash}",
                                    "file": fpath
                                })

            except PermissionError:
                continue

        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        """Bắt đầu giám sát file system"""
        self.running = True
        self.logger.info("FileMonitor started")

        # Quét file hiện tại trước
        self.scan_existing_suspicious_files()

        # Setup watchdog observer
        self.event_handler = SuspiciousFileHandler(
            self.alert_callback,
            self.logger,
            self.alerted_files
        )
        self.observer = Observer()

        for watch_dir in MONITORED_DIRS:
            if watch_dir and os.path.isdir(watch_dir):
                try:
                    self.observer.schedule(
                        self.event_handler,
                        watch_dir,
                        recursive=True
                    )
                except Exception as e:
                    self.logger.warning(f"Cannot watch {watch_dir}: {e}")

        try:
            self.observer.start()
        except Exception as e:
            self.logger.error(f"FileMonitor observer error: {e}")

        # Monitor loop - kiểm tra mass encryption
        while self.running:
            try:
                if hasattr(self, 'event_handler'):
                    mass_count = self.event_handler.detect_mass_encryption()
                    if mass_count > 20:  # >20 file thay đổi trong 60 giây
                        self.alert_callback({
                            "module": "FileMonitor",
                            "severity": "CRITICAL",
                            "type": "MASS_FILE_ENCRYPTION",
                            "message": f"🚨 CÓ THỂ RANSOMWARE! {mass_count} file bị thay đổi trong 60 giây gần đây!"
                        })
                time.sleep(30)
            except Exception as e:
                self.logger.error(f"FileMonitor loop error: {e}")
                time.sleep(30)

    def stop(self):
        self.running = False
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=5)
            except:
                pass
