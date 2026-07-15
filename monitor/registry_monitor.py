"""
Registry Monitor - Giám sát Windows Registry
Phát hiện: persistence mechanisms, malware autorun, rootkit registry tampering
"""

import threading
import time
from datetime import datetime
from typing import Callable, Dict, Set

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# Registry keys quan trọng cần giám sát (persistence locations)
MONITORED_REGISTRY_KEYS = {
    # Autorun locations
    "HKLM_RUN": (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    "HKCU_RUN": (winreg.HKEY_CURRENT_USER if HAS_WINREG else None,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    "HKLM_RUNONCE": (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    "HKCU_RUNONCE": (winreg.HKEY_CURRENT_USER if HAS_WINREG else None,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),

    # Services
    "SERVICES": (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
                 r"SYSTEM\CurrentControlSet\Services"),

    # Browser extensions hijacking
    "CHROME_EXT": (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
                   r"SOFTWARE\Google\Chrome\Extensions"),

    # Winlogon (thường bị malware hijack)
    "WINLOGON": (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
                 r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),

    # AppInit_DLLs (DLL injection via registry)
    "APPINIT": (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),

    # Image File Execution Options (IFEO - debugger hijacking)
    "IFEO": (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),

    # Shell folders
    "SHELL": (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
              r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),

    # Scheduled tasks registry
    "TASKS": (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
              r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"),

    # Boot execute
    "BOOTEXEC": (winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
                 r"SYSTEM\CurrentControlSet\Control\Session Manager"),
}

# Values nguy hiểm cụ thể cần theo dõi
CRITICAL_VALUES = {
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon": {
        "Userinit": r"C:\Windows\system32\userinit.exe,",  # Giá trị bình thường
        "Shell": "explorer.exe",  # Giá trị bình thường
    }
}

# Paths tin cậy cho autorun entries
TRUSTED_AUTORUN_PATHS = [
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
]


class RegistryMonitor:
    """Monitor giám sát Windows Registry"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.baseline: Dict[str, dict] = {}
        self.alerted_keys: Set[str] = set()
        self.scan_interval = 30  # seconds
        self.stats = {
            "keys_monitored": 0,
            "changes_detected": 0,
            "threats_found": 0,
            "last_scan": None
        }

    def read_registry_key(self, hive, key_path: str) -> dict:
        """Đọc tất cả values của một registry key"""
        values = {}
        if not HAS_WINREG or hive is None:
            return values

        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, data, data_type = winreg.EnumValue(key, i)
                        values[name] = {
                            "data": str(data)[:500],  # Giới hạn độ dài
                            "type": data_type
                        }
                        i += 1
                    except OSError:
                        break
        except (FileNotFoundError, PermissionError, OSError):
            pass

        return values

    def build_baseline(self):
        """Xây dựng baseline ban đầu"""
        self.logger.info("Building registry baseline...")
        for key_name, (hive, path) in MONITORED_REGISTRY_KEYS.items():
            values = self.read_registry_key(hive, path)
            self.baseline[key_name] = values
            self.stats["keys_monitored"] += len(values)

    def check_autorun_entries(self, key_name: str, values: dict):
        """Kiểm tra entries autorun đáng ngờ"""
        flags = []

        for value_name, value_data in values.items():
            data_str = value_data.get("data", "").lower()

            # Kiểm tra path đáng ngờ
            is_trusted = False
            for trusted in TRUSTED_AUTORUN_PATHS:
                if data_str.startswith(trusted.lower()):
                    is_trusted = True
                    break

            # Autorun từ temp/appdata đáng ngờ
            suspicious_locs = [
                "%temp%", "\\temp\\", "\\tmp\\", "%appdata%",
                "\\downloads\\", "\\recycle", "c:\\users\\public"
            ]

            for loc in suspicious_locs:
                if loc in data_str:
                    alert_key = f"autorun:{key_name}:{value_name}"
                    if alert_key not in self.alerted_keys:
                        self.alerted_keys.add(alert_key)
                        flags.append({
                            "type": "SUSPICIOUS_AUTORUN",
                            "severity": "HIGH",
                            "detail": f"Autorun entry đáng ngờ trong '{key_name}':\n"
                                     f"Name: {value_name}\nPath: {value_data['data']}"
                        })

            # Kiểm tra PowerShell encoded trong autorun
            if "powershell" in data_str and ("-enc" in data_str or "-encoded" in data_str):
                alert_key = f"ps-enc:{key_name}:{value_name}"
                if alert_key not in self.alerted_keys:
                    self.alerted_keys.add(alert_key)
                    flags.append({
                        "type": "ENCODED_AUTORUN",
                        "severity": "CRITICAL",
                        "detail": f"PowerShell Encoded Command trong autorun '{key_name}':\n{value_name}: {value_data['data'][:200]}"
                    })

        return flags

    def check_winlogon_hijacking(self, values: dict):
        """Kiểm tra Winlogon hijacking"""
        flags = []
        expected = CRITICAL_VALUES.get(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", {}
        )

        for val_name, expected_val in expected.items():
            if val_name in values:
                actual = values[val_name].get("data", "")
                if actual.lower() != expected_val.lower():
                    alert_key = f"winlogon:{val_name}"
                    if alert_key not in self.alerted_keys:
                        self.alerted_keys.add(alert_key)
                        flags.append({
                            "type": "WINLOGON_HIJACK",
                            "severity": "CRITICAL",
                            "detail": f"🚨 Winlogon '{val_name}' bị thay đổi!\n"
                                     f"Expected: {expected_val}\n"
                                     f"Actual: {actual}"
                        })

        return flags

    def check_appinit_dlls(self, values: dict):
        """Kiểm tra AppInit_DLLs (DLL injection mechanism)"""
        flags = []

        if "AppInit_DLLs" in values:
            dll_list = values["AppInit_DLLs"].get("data", "")
            if dll_list and dll_list.strip():
                # AppInit_DLLs có value là dấu hiệu cực kỳ đáng ngờ
                alert_key = f"appinit:{dll_list[:50]}"
                if alert_key not in self.alerted_keys:
                    self.alerted_keys.add(alert_key)
                    flags.append({
                        "type": "APPINIT_DLL_INJECTION",
                        "severity": "CRITICAL",
                        "detail": f"🚨 AppInit_DLLs được set! Đây là kỹ thuật DLL injection:\n{dll_list}"
                    })

        return flags

    def check_ifeo_debugger(self, values: dict, key_name: str):
        """Kiểm tra Image File Execution Options debugger hijacking"""
        flags = []

        if "Debugger" in values:
            debugger = values["Debugger"].get("data", "")
            # Debugger không phải công cụ debug thực sự -> malware persistence
            legit_debuggers = ["windbg", "cdb.exe", "ntsd.exe", "devenv.exe"]
            is_legit = any(d in debugger.lower() for d in legit_debuggers)

            if not is_legit and debugger:
                alert_key = f"ifeo:{key_name}:{debugger[:30]}"
                if alert_key not in self.alerted_keys:
                    self.alerted_keys.add(alert_key)
                    flags.append({
                        "type": "IFEO_HIJACKING",
                        "severity": "HIGH",
                        "detail": f"IFEO Debugger hijacking detected!\n"
                                 f"Process: {key_name}\nDebugger: {debugger}"
                    })

        return flags

    def compare_with_baseline(self, key_name: str, current: dict) -> list:
        """So sánh với baseline để phát hiện thay đổi"""
        flags = []
        baseline = self.baseline.get(key_name, {})

        # Tìm values mới được thêm
        for val_name in current:
            if val_name not in baseline:
                if "RUN" in key_name.upper():
                    self.stats["changes_detected"] += 1
                    alert_key = f"new-run:{key_name}:{val_name}"
                    if alert_key not in self.alerted_keys:
                        self.alerted_keys.add(alert_key)
                        flags.append({
                            "type": "NEW_REGISTRY_ENTRY",
                            "severity": "MEDIUM",
                            "detail": f"Registry entry MỚI trong '{key_name}':\n"
                                     f"{val_name} = {current[val_name].get('data', '')[:200]}"
                        })

        return flags

    def scan(self):
        """Quét toàn bộ registry keys được giám sát"""
        for key_name, (hive, path) in MONITORED_REGISTRY_KEYS.items():
            try:
                current_values = self.read_registry_key(hive, path)
                all_flags = []

                # Kiểm tra autorun entries
                if "RUN" in key_name:
                    all_flags.extend(self.check_autorun_entries(key_name, current_values))

                # Kiểm tra winlogon
                if "WINLOGON" in key_name:
                    all_flags.extend(self.check_winlogon_hijacking(current_values))

                # Kiểm tra AppInit_DLLs
                if "APPINIT" in key_name:
                    all_flags.extend(self.check_appinit_dlls(current_values))

                # So sánh với baseline
                all_flags.extend(self.compare_with_baseline(key_name, current_values))

                # Gửi cảnh báo
                for flag in all_flags:
                    self.stats["threats_found"] += 1
                    self.alert_callback({
                        "module": "RegistryMonitor",
                        "severity": flag.get("severity", "MEDIUM"),
                        "type": flag["type"],
                        "message": flag["detail"],
                        "registry_key": f"{key_name}\\{path}"
                    })

                # Cập nhật baseline
                self.baseline[key_name] = current_values

            except Exception as e:
                self.logger.warning(f"Registry scan error for {key_name}: {e}")

        self.stats["last_scan"] = datetime.now().isoformat()

    def get_autorun_list(self) -> list:
        """Lấy danh sách autorun entries (cho dashboard)"""
        autoruns = []
        for key_name in ["HKLM_RUN", "HKCU_RUN"]:
            hive, path = MONITORED_REGISTRY_KEYS.get(key_name, (None, ""))
            if hive:
                values = self.read_registry_key(hive, path)
                for name, data in values.items():
                    autoruns.append({
                        "key": key_name,
                        "name": name,
                        "path": data.get("data", "")[:80]
                    })
        return autoruns

    def start(self):
        """Bắt đầu giám sát registry"""
        self.running = True
        self.logger.info("RegistryMonitor started")

        # Xây dựng baseline
        self.build_baseline()

        while self.running:
            try:
                self.scan()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"RegistryMonitor error: {e}")
                time.sleep(30)

    def stop(self):
        self.running = False
