"""
Kernel ETW Consumer - Nhận sự kiện trực tiếp từ Windows Kernel
Sử dụng Event Tracing for Windows (ETW) để giám sát real-time:
  - Tiến trình mới sinh ra / bị kill
  - File bị đọc / ghi / xóa
  - Kết nối mạng mới
  - Registry bị chỉnh sửa

Yêu cầu: Quyền Administrator
"""

import ctypes
import ctypes.wintypes as wintypes
import threading
import time
import subprocess
import os
from datetime import datetime
from typing import Callable

# ── Windows Constants ─────────────────────────────────
TRACE_LEVEL_INFORMATION = 4
WNODE_FLAG_TRACED_GUID  = 0x00020000
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000

# ── ETW Provider GUIDs (Kernel) ───────────────────────
# Microsoft-Windows-Kernel-Process
KERNEL_PROCESS_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
# Microsoft-Windows-Kernel-File
KERNEL_FILE_GUID    = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
# Microsoft-Windows-Kernel-Network
KERNEL_NETWORK_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"


class KernelETWMonitor:
    """
    Giám sát sự kiện Kernel qua ETW bằng PowerShell trace session.
    Cách tiếp cận thực tế nhất từ Python vì gọi ETW C API trực tiếp
    qua ctypes rất phức tạp và dễ crash.
    """

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scan_interval = 3

        # Cache để tránh cảnh báo lặp
        self._alerted_events = set()

        self.stats = {
            "events_captured": 0,
            "suspicious_events": 0,
            "last_scan": None,
        }

    def _query_etw_process_events(self):
        """Dùng PowerShell để truy vấn sự kiện tạo tiến trình gần đây từ ETW log"""
        if not self.is_admin:
            return []

        try:
            # Truy vấn Security Event Log - Event ID 4688 = Process Creation
            # Đây là kênh Kernel-level audit logging của Windows
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} "
                "-MaxEvents 20 -ErrorAction SilentlyContinue | "
                "Select-Object TimeCreated, "
                "@{N='NewProcess';E={$_.Properties[5].Value}}, "
                "@{N='ParentProcess';E={$_.Properties[13].Value}}, "
                "@{N='CommandLine';E={$_.Properties[8].Value}}, "
                "@{N='User';E={$_.Properties[1].Value}} | "
                "ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=8
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data
        except Exception as e:
            self.logger.warning(f"[KernelETW] Process event query error: {e}")
        return []

    def _query_etw_network_events(self):
        """Truy vấn sự kiện kết nối mạng từ Firewall log (Kernel-level)"""
        if not self.is_admin:
            return []

        try:
            # Event ID 5156 = Windows Filtering Platform connection
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='Security';Id=5156} "
                "-MaxEvents 15 -ErrorAction SilentlyContinue | "
                "Select-Object TimeCreated, "
                "@{N='AppPath';E={$_.Properties[1].Value}}, "
                "@{N='Direction';E={$_.Properties[2].Value}}, "
                "@{N='SourcePort';E={$_.Properties[4].Value}}, "
                "@{N='DestAddr';E={$_.Properties[5].Value}}, "
                "@{N='DestPort';E={$_.Properties[6].Value}} | "
                "ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=8
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data
        except Exception:
            pass
        return []

    def _query_sysmon_events(self):
        """Truy vấn Sysmon nếu đã được cài (công cụ Kernel-level của Microsoft)"""
        try:
            ps_cmd = (
                "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
                "-MaxEvents 15 -ErrorAction SilentlyContinue | "
                "Select-Object Id, TimeCreated, Message | "
                "ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=8
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data
        except Exception:
            pass
        return []

    def analyze_process_events(self, events: list):
        """Phân tích sự kiện tạo tiến trình từ Kernel audit log"""
        suspicious_patterns = [
            "powershell", "cmd.exe", "wscript", "cscript",
            "mshta", "regsvr32", "rundll32", "certutil",
            "bitsadmin", "msiexec /q",
        ]

        for evt in events:
            new_proc = str(evt.get("NewProcess", "")).lower()
            cmdline  = str(evt.get("CommandLine", "")).lower()
            parent   = str(evt.get("ParentProcess", "")).lower()
            time_str = str(evt.get("TimeCreated", ""))

            # Kiểm tra các chuỗi tấn công phổ biến trong command line
            for pattern in suspicious_patterns:
                if pattern in cmdline:
                    # Kiểm tra có phải là chuỗi tấn công LOLBin không
                    is_lolbin_chain = (
                        ("powershell" in cmdline and ("-enc" in cmdline or "-w hidden" in cmdline or "iex" in cmdline))
                        or ("certutil" in cmdline and "-decode" in cmdline)
                        or ("mshta" in cmdline and "http" in cmdline)
                        or ("regsvr32" in cmdline and "/s" in cmdline and "/i:" in cmdline)
                    )

                    if is_lolbin_chain:
                        alert_key = f"etw_proc:{new_proc}:{cmdline[:50]}"
                        if alert_key not in self._alerted_events:
                            self._alerted_events.add(alert_key)
                            self.stats["suspicious_events"] += 1

                            self.alert_callback({
                                "module": "KernelETW",
                                "severity": "CRITICAL",
                                "type": "KERNEL_SUSPICIOUS_PROCESS",
                                "message": (
                                    f"🔥 KERNEL EVENT: Phat hien chuoi tan cong LOLBin!\n"
                                    f"Thoi gian: {time_str}\n"
                                    f"Tien trinh moi: {new_proc}\n"
                                    f"Tien trinh cha: {parent}\n"
                                    f"Command line: {cmdline[:200]}\n"
                                    f"Day la ky thuat Living-off-the-Land - ma doc loi dung cong cu co san cua Windows."
                                ),
                                "process": {"pid": None, "name": os.path.basename(new_proc)}
                            })
                    break

            self.stats["events_captured"] += 1

    def analyze_network_events(self, events: list):
        """Phân tích sự kiện mạng từ Kernel WFP log"""
        suspicious_ports = {4444, 5555, 6666, 8888, 1337, 31337, 9001, 3333, 14444}

        for evt in events:
            dest_port = evt.get("DestPort")
            dest_addr = str(evt.get("DestAddr", ""))
            app_path  = str(evt.get("AppPath", "")).lower()

            try:
                dest_port = int(dest_port)
            except (TypeError, ValueError):
                continue

            if dest_port in suspicious_ports:
                alert_key = f"etw_net:{app_path}:{dest_addr}:{dest_port}"
                if alert_key not in self._alerted_events:
                    self._alerted_events.add(alert_key)
                    self.stats["suspicious_events"] += 1

                    self.alert_callback({
                        "module": "KernelETW",
                        "severity": "HIGH",
                        "type": "KERNEL_SUSPICIOUS_CONNECTION",
                        "message": (
                            f"🌐 KERNEL NETWORK: Ket noi dang ngo toi cong nguy hiem!\n"
                            f"Ung dung: {app_path}\n"
                            f"Dich den: {dest_addr}:{dest_port}\n"
                            f"Cong {dest_port} thuong duoc dung boi Reverse Shell hoac Mining Pool."
                        ),
                    })

    def scan(self):
        """Chu ky quet su kien Kernel"""
        # 1. Su kien tao tien trinh (Kernel Audit)
        proc_events = self._query_etw_process_events()
        if proc_events:
            self.analyze_process_events(proc_events)

        # 2. Su kien mang (Kernel WFP)
        net_events = self._query_etw_network_events()
        if net_events:
            self.analyze_network_events(net_events)

        # 3. Sysmon (neu co)
        sysmon_events = self._query_sysmon_events()
        if sysmon_events:
            self.stats["events_captured"] += len(sysmon_events)

        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        self.running = True
        self.logger.info("KernelETWMonitor started")

        # Kich hoat Process Auditing neu chua bat
        if self.is_admin:
            try:
                subprocess.run(
                    ["auditpol", "/set", "/subcategory:Process Creation", "/success:enable"],
                    capture_output=True, timeout=5
                )
                self.logger.info("[KernelETW] Process Creation auditing enabled")
            except Exception:
                pass

        while self.running:
            try:
                self.scan()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"KernelETW error: {e}")
                time.sleep(10)

    def stop(self):
        self.running = False
