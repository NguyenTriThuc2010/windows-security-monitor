"""
Process Monitor - Giám sát tiến trình hệ thống
Phát hiện: process lạ, giả mạo, rootkit, privilege escalation
"""

import psutil
import os
import hashlib
import time
import threading
import json
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional

# Tên process hệ thống Windows hợp lệ
SYSTEM_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "explorer.exe", "svchost.exe",
    "spoolsv.exe", "taskhostw.exe", "dwm.exe", "ctfmon.exe",
    "dllhost.exe", "conhost.exe", "taskeng.exe", "msiexec.exe",
    "wuauclt.exe", "SearchIndexer.exe", "audiodg.exe", "fontdrvhost.exe",
    "RuntimeBroker.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
    "SecurityHealthSystray.exe", "MsMpEng.exe", "NisSrv.exe",
    "WmiPrvSE.exe", "unsecapp.exe", "WUDFHost.exe", "igfxCUIService.exe",
    "LsaIso.exe", "Registry", "Idle", "System",
}

# Locations tin cậy của Windows
TRUSTED_PATHS = [
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
]

# Process nguy hiểm đã biết (mẫu tên)
SUSPICIOUS_NAMES = [
    "mimikatz", "meterpreter", "netcat", "nc.exe", "ncat",
    "pwdump", "fgdump", "procdump", "wce.exe", "gsecdump",
    "quarks", "lsadump", "secretsdump", "bloodhound",
    "cobalt", "covenant", "havoc", "sliver",
]

# Process system chỉ nên chạy từ System32
CRITICAL_SYSTEM_PROCS = {
    "lsass.exe": "C:\\Windows\\System32\\lsass.exe",
    "csrss.exe": "C:\\Windows\\System32\\csrss.exe",
    "winlogon.exe": "C:\\Windows\\System32\\winlogon.exe",
    "services.exe": "C:\\Windows\\System32\\services.exe",
    "smss.exe": "C:\\Windows\\System32\\smss.exe",
    "wininit.exe": "C:\\Windows\\System32\\wininit.exe",
    "svchost.exe": "C:\\Windows\\System32\\svchost.exe",
}


class ProcessMonitor:
    """Monitor giám sát các tiến trình đang chạy"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.known_pids = set()
        self.process_cache = {}
        self.scan_interval = 5  # seconds
        self.stats = {
            "total_scanned": 0,
            "threats_found": 0,
            "suspicious_count": 0,
            "last_scan": None
        }

    def get_process_info(self, proc) -> Optional[dict]:
        """Lấy thông tin chi tiết của một process"""
        try:
            with proc.oneshot():
                info = {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "exe": "",
                    "cmdline": "",
                    "username": "",
                    "ppid": proc.ppid(),
                    "status": proc.status(),
                    "create_time": proc.create_time(),
                    "cpu_percent": 0,
                    "memory_mb": 0,
                    "connections": [],
                    "suspicious_flags": []
                }

                try:
                    info["exe"] = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    info["exe"] = "ACCESS_DENIED"

                try:
                    info["cmdline"] = " ".join(proc.cmdline())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    info["cmdline"] = "ACCESS_DENIED"

                try:
                    info["username"] = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    info["username"] = "UNKNOWN"

                try:
                    info["memory_mb"] = proc.memory_info().rss / 1024 / 1024
                except:
                    pass

                try:
                    # Chỉnh interval=0 để không bị block tiến trình quét
                    info["cpu_percent"] = proc.cpu_percent(interval=0)
                except:
                    pass

                return info
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None

    def check_process_impersonation(self, proc_info: dict) -> list:
        """Kiểm tra process giả mạo tên hệ thống"""
        flags = []
        name_lower = proc_info["name"].lower()
        exe = proc_info["exe"].lower()

        # Kiểm tra process critical system từ đúng đường dẫn
        for sys_name, expected_path in CRITICAL_SYSTEM_PROCS.items():
            if name_lower == sys_name.lower():
                if exe and exe != "access_denied":
                    if not exe.lower().startswith(expected_path.lower()[:20]):
                        flags.append({
                            "type": "PROCESS_IMPERSONATION",
                            "severity": "CRITICAL",
                            "detail": f"'{proc_info['name']}' chạy từ đường dẫn bất thường: {exe}"
                        })

        # Kiểm tra tên giả mạo (unicode trick, typosquatting)
        common_tricks = {
            "svch0st": "svchost", "svchost32": "svchost",
            "Iexplore": "iexplore", "expiorer": "explorer",
            "csrss32": "csrss", "Isass": "lsass",  # chữ I hoa thay l
        }
        for fake, real in common_tricks.items():
            if fake.lower() in name_lower:
                flags.append({
                    "type": "PROCESS_NAME_TRICK",
                    "severity": "HIGH",
                    "detail": f"Process tên đáng ngờ '{proc_info['name']}' có thể giả mạo '{real}'"
                })

        return flags

    def check_suspicious_location(self, proc_info: dict) -> list:
        """Kiểm tra process từ vị trí đáng ngờ"""
        flags = []
        exe = proc_info["exe"]

        if not exe or exe == "ACCESS_DENIED":
            return flags

        exe_lower = exe.lower()
        suspicious_locations = [
            ("%temp%", os.environ.get("TEMP", "").lower()),
            ("%appdata%", os.environ.get("APPDATA", "").lower()),
            ("downloads", "\\downloads\\"),
            ("recycle", "\\$recycle"),
            ("tmp", "\\tmp\\"),
            ("public", "\\users\\public\\"),
        ]

        for label, path in suspicious_locations:
            if path and path in exe_lower:
                flags.append({
                    "type": "SUSPICIOUS_LOCATION",
                    "severity": "HIGH",
                    "detail": f"Process chạy từ thư mục đáng ngờ ({label}): {exe}"
                })

        return flags

    def check_known_malware_names(self, proc_info: dict) -> list:
        """Kiểm tra tên malware đã biết"""
        flags = []
        name_lower = proc_info["name"].lower()
        cmdline_lower = proc_info["cmdline"].lower()

        for malware in SUSPICIOUS_NAMES:
            if malware in name_lower or malware in cmdline_lower:
                flags.append({
                    "type": "KNOWN_MALWARE_NAME",
                    "severity": "CRITICAL",
                    "detail": f"Process khớp tên malware đã biết: '{malware}' trong '{proc_info['name']}'"
                })

        return flags

    def check_hidden_process(self, proc_info: dict) -> list:
        """Phát hiện dấu hiệu process ẩn"""
        flags = []

        # Process không có exe nhưng không phải system idle cũng không phải
        # các worker thread ẩn của Windows (PID 4 = System, PID 0 = Idle)
        # Chỉ cảnh báo 1 lần mỗi PID và chỉ khi tên process không thuộc whitelist
        if not proc_info["exe"] or proc_info["exe"] == "ACCESS_DENIED":
            pid = proc_info["pid"]
            name_lower = proc_info["name"].lower()
            # Bỏ qua: system, idle, và các process kernel mode không có exe
            kernel_procs = {"system", "idle", "registry", "memory compression",
                            "secure system", "system idle process", ""}
            if pid > 8 and name_lower not in kernel_procs:
                # Chỉ báo lần đầu tiên thấy PID này
                alert_key = f"hidden:{pid}"
                if alert_key not in self.known_pids:
                    flags.append({
                        "type": "HIDDEN_EXECUTABLE",
                        "severity": "MEDIUM",
                        "detail": f"Process '{proc_info['name']}' (PID {proc_info['pid']}) không có đường dẫn exe"
                    })

        return flags

    def check_suspicious_cmdline(self, proc_info: dict) -> list:
        """Kiểm tra command line đáng ngờ"""
        flags = []
        cmdline = proc_info["cmdline"].lower()

        # Các pattern đáng ngờ trong command line
        suspicious_patterns = [
            ("powershell.*-enc", "PowerShell encoded command - thường dùng để bypass detection"),
            ("powershell.*-w.*hidden", "PowerShell chạy ẩn"),
            (r"cmd.*/c.*powershell", "CMD gọi PowerShell"),
            ("certutil.*-decode", "certutil decode - thường dùng download malware"),
            ("bitsadmin.*transfer", "BITS transfer - thường dùng download malware"),
            ("regsvr32.*scrobj", "Regsvr32 với scrobj - COM scriptlet attack"),
            (r"wscript.*/e:jscript", "WSScript JScript execution"),
            ("mshta.*http", "MSHTA loading remote content"),
            ("wmic.*process.*call.*create", "WMIC process creation"),
            (r"net.*user.*/add", "Tạo user mới"),
            ("net.*localgroup.*administrators", "Thêm vào nhóm Administrators"),
            ("vssadmin.*delete.*shadows", "Xóa shadow copies - ransomware behavior"),
            ("bcdedit.*recoveryenabled.*no", "Tắt recovery - ransomware behavior"),
            ("taskkill.*antivirus", "Kill antivirus process"),
        ]

        import re
        for pattern, description in suspicious_patterns:
            if re.search(pattern, cmdline):
                flags.append({
                    "type": "SUSPICIOUS_CMDLINE",
                    "severity": "HIGH",
                    "detail": f"Command line đáng ngờ: {description}\nCMD: {proc_info['cmdline'][:200]}"
                })

        return flags

    def check_parent_child_relationship(self, proc_info: dict) -> list:
        """Kiểm tra quan hệ parent-child bất thường"""
        flags = []
        name_lower = proc_info["name"].lower()
        ppid = proc_info["ppid"]

        try:
            parent = psutil.Process(ppid)
            parent_name = parent.name().lower()

            # Office apps không nên spawn command shells
            office_apps = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"]
            shell_procs = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]

            if parent_name in office_apps and name_lower in shell_procs:
                flags.append({
                    "type": "SUSPICIOUS_PARENT_CHILD",
                    "severity": "CRITICAL",
                    "detail": f"Office '{parent_name}' spawn shell '{proc_info['name']}' - dấu hiệu macro virus!"
                })

            # Browser không nên spawn cmd/powershell
            browsers = ["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe"]
            if parent_name in browsers and name_lower in ["cmd.exe", "powershell.exe"]:
                flags.append({
                    "type": "SUSPICIOUS_PARENT_CHILD",
                    "severity": "HIGH",
                    "detail": f"Browser '{parent_name}' spawn shell '{proc_info['name']}' - có thể bị exploit!"
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return flags

    def check_high_resources(self, proc_info: dict) -> list:
        """Phát hiện tiến trình ngốn tài nguyên (nghi ngờ đào coin)"""
        flags = []
        cpu = proc_info.get("cpu_percent", 0)
        mem = proc_info.get("memory_mb", 0)
        name = proc_info["name"].lower()
        
        # Bỏ qua System Idle
        if "idle" in name or name == "system":
            return flags
            
        # Nếu CPU > 85% (Dấu hiệu rõ nhất của Cryptominer)
        if cpu > 85:
            flags.append({
                "type": "HIGH_CPU_MINER",
                "severity": "HIGH",
                "detail": f"🔥 CẢNH BÁO TÀI NGUYÊN: Process '{proc_info['name']}' đang vắt kiệt {cpu:.1f}% CPU máy tính!\n"
                           f"Đây là dấu hiệu rất phổ biến của mã độc đào tiền ảo (Cryptominer) đang chạy ngầm."
            })
            
        # Nếu RAM > 3000 MB (Trừ trình duyệt/game hợp lệ)
        legit_heavy_apps = ["chrome.exe", "msedge.exe", "devenv.exe", "vmmem", "java.exe", "sqlservr.exe"]
        if mem > 3000 and name not in legit_heavy_apps:
            flags.append({
                "type": "HIGH_RAM_USAGE",
                "severity": "MEDIUM",
                "detail": f"⚠️ Process '{proc_info['name']}' đang ngốn lượng RAM khổng lồ ({mem:.1f} MB).\n"
                           f"Có thể do rò rỉ bộ nhớ hoặc phần mềm gián điệp thu thập lượng lớn dữ liệu."
            })
            
        return flags

    def analyze_process(self, proc_info: dict) -> list:
        """Phân tích toàn diện một process"""
        all_flags = []
        all_flags.extend(self.check_process_impersonation(proc_info))
        all_flags.extend(self.check_suspicious_location(proc_info))
        all_flags.extend(self.check_known_malware_names(proc_info))
        all_flags.extend(self.check_hidden_process(proc_info))
        all_flags.extend(self.check_suspicious_cmdline(proc_info))
        all_flags.extend(self.check_parent_child_relationship(proc_info))
        return all_flags

    def scan_all_processes(self):
        """Quét toàn bộ process đang chạy"""
        current_pids = set()
        new_processes = []

        for proc in psutil.process_iter():
            try:
                info = self.get_process_info(proc)
                if not info:
                    continue

                current_pids.add(info["pid"])
                self.stats["total_scanned"] += 1

                # Kiểm tra process mới
                if info["pid"] not in self.known_pids:
                    new_processes.append(info)
                    self.known_pids.add(info["pid"])

                # Phân tích process
                flags = self.analyze_process(info)
                if flags:
                    for flag in flags:
                        severity = flag.get("severity", "MEDIUM")
                        self.stats["threats_found"] += 1

                        self.alert_callback({
                            "module": "ProcessMonitor",
                            "severity": severity,
                            "type": flag["type"],
                            "message": flag["detail"],
                            "process": {
                                "pid": info["pid"],
                                "name": info["name"],
                                "exe": info["exe"],
                                "user": info["username"]
                            }
                        })

            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue

        # Loại bỏ PID đã kết thúc
        self.known_pids &= current_pids
        self.stats["last_scan"] = datetime.now().isoformat()

        return new_processes

    def get_running_processes(self) -> list:
        """Lấy danh sách process đang chạy (cho dashboard)"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
            try:
                pinfo = proc.info
                processes.append({
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "cpu": pinfo['cpu_percent'] or 0,
                    "memory_mb": (pinfo['memory_info'].rss / 1024 / 1024) if pinfo['memory_info'] else 0,
                    "status": pinfo['status']
                })
            except:
                continue
        return sorted(processes, key=lambda x: x['cpu'], reverse=True)[:20]

    def start(self):
        """Bắt đầu giám sát process"""
        self.running = True
        self.logger.info("ProcessMonitor started")

        # Scan lần đầu để lấy baseline
        self.scan_all_processes()

        while self.running:
            try:
                new_procs = self.scan_all_processes()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"ProcessMonitor error: {e}")
                time.sleep(10)

    def stop(self):
        self.running = False
