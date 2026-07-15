"""
Kernel Module Scanner - Liệt kê và kiểm tra toàn bộ driver (.sys) trong Kernel
Phát hiện rootkit driver bằng cách:
  1. Gọi NtQuerySystemInformation để lấy danh sách module Kernel
  2. Kiểm tra chữ ký số của từng driver
  3. So sánh với danh sách driver Windows hợp lệ

Yêu cầu: Quyền Administrator
"""

import ctypes
import ctypes.wintypes as wintypes
import os
import subprocess
import time
from datetime import datetime
from typing import Callable, Set
from pathlib import Path

# ── Windows Constants ─────────────────────────────────
SYSTEM_MODULE_INFORMATION = 11  # SystemModuleInformation class

# NtQuerySystemInformation return structure
class SYSTEM_MODULE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Section",            ctypes.c_void_p),
        ("MappedBase",         ctypes.c_void_p),
        ("ImageBase",          ctypes.c_void_p),
        ("ImageSize",          ctypes.c_ulong),
        ("Flags",              ctypes.c_ulong),
        ("LoadOrderIndex",     ctypes.c_ushort),
        ("InitOrderIndex",     ctypes.c_ushort),
        ("LoadCount",          ctypes.c_ushort),
        ("OffsetToFileName",   ctypes.c_ushort),
        ("FullPathName",       ctypes.c_char * 256),
    ]

class SYSTEM_MODULE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ("ModulesCount", ctypes.c_ulong),
        ("Modules",      SYSTEM_MODULE_ENTRY * 1),  # Variable-length array
    ]

# Danh sach cac duong dan driver hop le cua Windows
LEGITIMATE_DRIVER_PATHS = {
    "\\systemroot\\system32\\drivers",
    "\\systemroot\\system32",
    "\\??\\c:\\windows\\system32\\drivers",
    "c:\\windows\\system32\\drivers",
}

# Cac driver Windows he thong khong can kiem tra
KNOWN_SYSTEM_DRIVERS = {
    "ntoskrnl.exe", "hal.dll", "ci.dll", "clfs.sys", "tm.sys",
    "ntfs.sys", "fltmgr.sys", "ksecdd.sys", "tcpip.sys",
    "ndis.sys", "wdf01000.sys", "wdfldr.sys", "acpi.sys",
    "pci.sys", "volmgrx.sys", "mountmgr.sys", "disk.sys",
    "classpnp.sys", "fvevol.sys", "volsnap.sys",
}


class KernelModuleScanner:
    """Quet va kiem tra driver dang chay trong Windows Kernel"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scan_interval = 600  # Driver kernel rat it thay doi, quet moi 10 phut la du

        self._known_drivers = set()   # Cache driver đã biết
        self._alerted = set()

        self.stats = {
            "drivers_scanned": 0,
            "unsigned_drivers": 0,
            "suspicious_drivers": 0,
            "last_scan": None,
        }

    def enumerate_kernel_modules_ntapi(self) -> list:
        """
        Gọi NtQuerySystemInformation (Ring 0 API) để lấy danh sách
        toàn bộ module đang load trong Kernel space.
        """
        modules = []
        if not self.is_admin:
            return modules

        try:
            ntdll = ctypes.WinDLL("ntdll")
            NtQuerySystemInformation = ntdll.NtQuerySystemInformation

            # Bước 1: Hỏi kích thước buffer cần thiết
            buf_size = ctypes.c_ulong(0)
            NtQuerySystemInformation(
                SYSTEM_MODULE_INFORMATION,
                None,
                0,
                ctypes.byref(buf_size)
            )

            # Bước 2: Cấp phát buffer và gọi lại
            buf = ctypes.create_string_buffer(buf_size.value)
            status = NtQuerySystemInformation(
                SYSTEM_MODULE_INFORMATION,
                buf,
                buf_size.value,
                ctypes.byref(buf_size)
            )

            if status != 0:
                return modules

            # Bước 3: Parse kết quả
            count = ctypes.c_ulong.from_buffer_copy(buf, 0).value

            entry_size = ctypes.sizeof(SYSTEM_MODULE_ENTRY)
            offset = ctypes.sizeof(ctypes.c_ulong)  # Skip ModulesCount

            for i in range(min(count, 500)):  # Giới hạn 500 driver
                try:
                    entry = SYSTEM_MODULE_ENTRY.from_buffer_copy(buf, offset)
                    full_path = entry.FullPathName.decode("utf-8", errors="ignore").strip('\x00')
                    file_name_offset = entry.OffsetToFileName
                    driver_name = full_path[file_name_offset:] if file_name_offset < len(full_path) else full_path

                    modules.append({
                        "name": driver_name.lower(),
                        "full_path": full_path.lower(),
                        "image_base": hex(entry.ImageBase) if entry.ImageBase else "0x0",
                        "image_size": entry.ImageSize,
                        "load_order": entry.LoadOrderIndex,
                    })
                    offset += entry_size
                except Exception:
                    break

            self.stats["drivers_scanned"] = len(modules)

        except Exception as e:
            self.logger.warning(f"[KernelModuleScanner] NtQuerySystemInformation error: {e}")

        return modules

    def enumerate_kernel_modules_powershell(self) -> list:
        """Backup: Dùng PowerShell nếu NT API bị chặn"""
        modules = []
        try:
            ps_cmd = (
                "Get-CimInstance Win32_SystemDriver | "
                "Where-Object {$_.State -eq 'Running'} | "
                "Select-Object Name, DisplayName, PathName, Started, State | "
                "ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for d in data:
                    modules.append({
                        "name": (d.get("Name", "") or "").lower() + ".sys",
                        "full_path": (d.get("PathName", "") or "").lower(),
                        "display_name": d.get("DisplayName", ""),
                    })
        except Exception as e:
            self.logger.warning(f"[KernelModuleScanner] PowerShell fallback error: {e}")

        return modules

    def check_driver_signature(self, driver_path: str) -> bool:
        """Kiểm tra chữ ký số của driver file"""
        try:
            # Chuyển đổi đường dẫn kernel sang đường dẫn Windows
            real_path = driver_path
            if real_path.startswith("\\systemroot\\"):
                real_path = real_path.replace("\\systemroot\\", "C:\\Windows\\", 1)
            elif real_path.startswith("\\??\\"):
                real_path = real_path[4:]

            if not os.path.exists(real_path):
                return True  # Không tìm thấy file -> bỏ qua

            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-Command", f"(Get-AuthenticodeSignature '{real_path}').Status"],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip() == "Valid"
        except Exception:
            return True  # Lỗi -> không báo nhầm

    def analyze_drivers(self, modules: list):
        """Phân tích danh sách driver tìm driver đáng ngờ"""
        for mod in modules:
            name = mod.get("name", "")
            full_path = mod.get("full_path", "")

            # Bỏ qua driver hệ thống đã biết
            if name in KNOWN_SYSTEM_DRIVERS:
                self._known_drivers.add(name)
                continue

            # Kiểm tra đường dẫn bất thường
            is_legitimate_path = any(
                full_path.startswith(legit) or legit in full_path
                for legit in LEGITIMATE_DRIVER_PATHS
            )

            if not is_legitimate_path and full_path:
                alert_key = f"driver_path:{name}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self.stats["suspicious_drivers"] += 1

                    self.alert_callback({
                        "module": "KernelModuleScanner",
                        "severity": "CRITICAL",
                        "type": "SUSPICIOUS_KERNEL_DRIVER",
                        "message": (
                            f"🔴 KERNEL DRIVER DANG NGO!\n"
                            f"Driver: {name}\n"
                            f"Duong dan: {full_path}\n"
                            f"Dia chi nap: {mod.get('image_base', '?')}\n"
                            f"Driver nay KHONG nam trong thu muc Windows/System32/drivers.\n"
                            f"Co the la Rootkit driver dang chay o Ring 0!"
                        ),
                    })

            # Kiểm tra chữ ký (chỉ với driver chưa kiểm tra)
            if name not in self._known_drivers:
                self._known_drivers.add(name)
                is_signed = self.check_driver_signature(full_path)
                if not is_signed:
                    self.stats["unsigned_drivers"] += 1
                    alert_key = f"driver_unsigned:{name}"
                    if alert_key not in self._alerted:
                        self._alerted.add(alert_key)

                        self.alert_callback({
                            "module": "KernelModuleScanner",
                            "severity": "HIGH",
                            "type": "UNSIGNED_KERNEL_DRIVER",
                            "message": (
                                f"⚠️ DRIVER KHONG CO CHU KY SO!\n"
                                f"Driver: {name}\n"
                                f"Duong dan: {full_path}\n"
                                f"Driver nay khong co chu ky dien tu hop le.\n"
                                f"Tren Windows hien dai, moi driver hop phap deu PHAI co chu ky.\n"
                                f"Day co the la rootkit hoac driver bi chinh sua."
                            ),
                        })

    def scan(self):
        # Ưu tiên NT API (chính xác nhất, truy cập trực tiếp Kernel)
        modules = self.enumerate_kernel_modules_ntapi()
        if not modules:
            # Fallback sang PowerShell
            modules = self.enumerate_kernel_modules_powershell()

        if modules:
            self.analyze_drivers(modules)

        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        self.running = True
        self.logger.info("KernelModuleScanner started")

        while self.running:
            try:
                self.scan()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"KernelModuleScanner error: {e}")
                time.sleep(30)

    def stop(self):
        self.running = False
