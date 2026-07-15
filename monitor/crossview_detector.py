"""
Cross-View Rootkit Detection
Phát hiện tiến trình bị rootkit giấu bằng cách so sánh chéo
danh sách process từ 3 nguồn khác nhau:
  1. psutil (CreateToolhelp32Snapshot - User API)
  2. NtQuerySystemInformation (NT Kernel API)
  3. WMI (Win32_Process - COM layer)

Nếu một PID tồn tại ở nguồn 2 (Kernel) nhưng biến mất
ở nguồn 1 (User) -> Đó là tiến trình bị rootkit giấu!

Yêu cầu: Quyền Administrator
"""

import ctypes
import ctypes.wintypes as wintypes
import subprocess
import time
import psutil
from datetime import datetime
from typing import Callable, Set, Dict

# ── NtQuerySystemInformation constants ────────────────
SYSTEM_PROCESS_INFORMATION = 5

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length",        ctypes.c_ushort),
        ("MaximumLength", ctypes.c_ushort),
        ("Buffer",       ctypes.c_wchar_p),
    ]

# Simplified SYSTEM_PROCESS_INFORMATION structure
# We only need PID and ImageName
class SYSTEM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset",              ctypes.c_ulong),
        ("NumberOfThreads",              ctypes.c_ulong),
        ("WorkingSetPrivateSize",        ctypes.c_int64),
        ("HardFaultCount",               ctypes.c_ulong),
        ("NumberOfThreadsHighWatermark", ctypes.c_ulong),
        ("CycleTime",                    ctypes.c_uint64),
        ("CreateTime",                   ctypes.c_int64),
        ("UserTime",                     ctypes.c_int64),
        ("KernelTime",                   ctypes.c_int64),
        ("ImageName",                    UNICODE_STRING),
        ("BasePriority",                 ctypes.c_long),
        ("UniqueProcessId",              ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]


class CrossViewDetector:
    """Phát hiện rootkit bằng so sánh chéo danh sách tiến trình"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scan_interval = 120  # Quan trong: WMI rat cham, quet moi 2 phut la du

        self._alerted_hidden = set()

        self.stats = {
            "scans_completed": 0,
            "hidden_processes_found": 0,
            "source1_count": 0,  # psutil
            "source2_count": 0,  # NT API
            "source3_count": 0,  # WMI
            "last_scan": None,
        }

    # ── NGUỒN 1: psutil (User-level API) ─────────────
    def get_pids_psutil(self) -> Dict[int, str]:
        """Lấy danh sách PID bằng psutil (CreateToolhelp32Snapshot)"""
        result = {}
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                info = proc.info
                result[info['pid']] = info.get('name', '') or ''
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return result

    # ── NGUỒN 2: NtQuerySystemInformation (Kernel API) ──
    def get_pids_ntapi(self) -> Dict[int, str]:
        """Lấy danh sách PID bằng NT Kernel API trực tiếp"""
        result = {}
        try:
            ntdll = ctypes.WinDLL("ntdll")
            NtQuerySystemInformation = ntdll.NtQuerySystemInformation

            # Bước 1: Lấy kích thước buffer
            buf_size = ctypes.c_ulong(0)
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION,
                None,
                0,
                ctypes.byref(buf_size)
            )

            # Thêm buffer dự phòng
            buf_size.value += 65536
            buf = ctypes.create_string_buffer(buf_size.value)

            status = NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION,
                buf,
                buf_size.value,
                ctypes.byref(buf_size)
            )

            if status != 0:
                return result

            # Bước 2: Duyệt linked-list các process
            offset = 0
            while True:
                try:
                    proc_info = SYSTEM_PROCESS_INFO.from_buffer_copy(buf, offset)
                    pid = proc_info.UniqueProcessId or 0
                    if isinstance(pid, int):
                        pass
                    else:
                        pid = ctypes.cast(proc_info.UniqueProcessId, ctypes.c_void_p).value or 0

                    name = ""
                    if proc_info.ImageName.Buffer:
                        try:
                            name = proc_info.ImageName.Buffer[:proc_info.ImageName.Length // 2]
                        except Exception:
                            name = ""

                    result[pid] = str(name)

                    if proc_info.NextEntryOffset == 0:
                        break
                    offset += proc_info.NextEntryOffset
                except Exception:
                    break

        except Exception as e:
            self.logger.warning(f"[CrossView] NT API enumeration error: {e}")

        return result

    # ── NGUỒN 3: WMI (COM layer) ─────────────────────
    def get_pids_wmi(self) -> Dict[int, str]:
        """Lấy danh sách PID bằng WMI"""
        result = {}
        try:
            ps_cmd = (
                "Get-CimInstance Win32_Process | "
                "Select-Object ProcessId, Name | "
                "ConvertTo-Json -Compress"
            )
            proc_result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=10
            )
            if proc_result.returncode == 0 and proc_result.stdout.strip():
                import json
                data = json.loads(proc_result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    pid = item.get("ProcessId", 0)
                    name = item.get("Name", "")
                    if pid:
                        result[int(pid)] = str(name)
        except Exception as e:
            self.logger.warning(f"[CrossView] WMI enumeration error: {e}")

        return result

    # ── SO SÁNH CHÉO ─────────────────────────────────
    def cross_view_compare(self):
        """
        So sánh 3 nguồn để tìm tiến trình ẩn.
        Logic: Nếu PID có mặt ở NT API (nguồn Kernel) nhưng KHÔNG
        có ở psutil hoặc WMI -> Rootkit đang giấu tiến trình đó!
        """
        # Thu thập từ 3 nguồn
        pids_psutil = self.get_pids_psutil()
        pids_ntapi  = self.get_pids_ntapi()
        pids_wmi    = self.get_pids_wmi()

        self.stats["source1_count"] = len(pids_psutil)
        self.stats["source2_count"] = len(pids_ntapi)
        self.stats["source3_count"] = len(pids_wmi)

        if not pids_ntapi:
            return  # NT API không khả dụng

        # Tìm PID ẩn: có trong NT API nhưng không có trong psutil
        hidden_from_psutil = set(pids_ntapi.keys()) - set(pids_psutil.keys())
        # Bỏ qua PID 0 (System Idle)
        hidden_from_psutil.discard(0)

        for hidden_pid in hidden_from_psutil:
            name = pids_ntapi.get(hidden_pid, "Unknown")
            # Xác nhận thêm bằng WMI
            also_hidden_from_wmi = hidden_pid not in pids_wmi

            if also_hidden_from_wmi:
                # PID ẩn khỏi CẢ psutil VÀ WMI -> gần như chắc chắn là rootkit
                severity = "CRITICAL"
                confidence = "RAT CAO"
            else:
                # Chỉ ẩn khỏi psutil -> có thể là race condition hoặc rootkit nhẹ
                severity = "HIGH"
                confidence = "TRUNG BINH"

            alert_key = f"hidden_pid:{hidden_pid}"
            if alert_key not in self._alerted_hidden:
                self._alerted_hidden.add(alert_key)
                self.stats["hidden_processes_found"] += 1

                self.alert_callback({
                    "module": "CrossViewDetector",
                    "severity": severity,
                    "type": "ROOTKIT_HIDDEN_PROCESS",
                    "message": (
                        f"👻 PHAT HIEN ROOTKIT! Tien trinh bi giau khoi he thong!\n"
                        f"PID: {hidden_pid}\n"
                        f"Ten: {name}\n"
                        f"Do tin cay: {confidence}\n"
                        f"Chi tiet:\n"
                        f"  - NT Kernel API: CO thay tien trinh nay\n"
                        f"  - psutil (User API): KHONG thay\n"
                        f"  - WMI: {'KHONG thay' if also_hidden_from_wmi else 'CO thay'}\n"
                        f"Tien trinh nay bi che giau khoi cac cong cu thong thuong.\n"
                        f"Day la dau hieu dien hinh cua kernel-level rootkit!"
                    ),
                    "process": {"pid": hidden_pid, "name": name}
                })

        # Kiểm tra ngược: PID có trong psutil nhưng không có trong NT API
        # (hiếm, nhưng có thể là DKOM rootkit sửa Kernel structures)
        phantom_pids = set(pids_psutil.keys()) - set(pids_ntapi.keys())
        phantom_pids.discard(0)

        for phantom_pid in phantom_pids:
            name = pids_psutil.get(phantom_pid, "Unknown")
            alert_key = f"phantom_pid:{phantom_pid}"
            if alert_key not in self._alerted_hidden and phantom_pid > 8:
                self._alerted_hidden.add(alert_key)

                self.alert_callback({
                    "module": "CrossViewDetector",
                    "severity": "HIGH",
                    "type": "PHANTOM_PROCESS_DETECTED",
                    "message": (
                        f"🔮 TIEN TRINH MA (Phantom Process)!\n"
                        f"PID: {phantom_pid} ({name})\n"
                        f"Tien trinh nay xuat hien o User-mode nhung KHONG co o Kernel.\n"
                        f"Co the la DKOM rootkit dang thao tung cau truc du lieu Kernel."
                    ),
                    "process": {"pid": phantom_pid, "name": name}
                })

    def scan(self):
        self.cross_view_compare()
        self.stats["scans_completed"] += 1
        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        self.running = True
        self.logger.info("CrossViewDetector started")

        while self.running:
            try:
                self.scan()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"CrossView error: {e}")
                time.sleep(15)

    def stop(self):
        self.running = False
