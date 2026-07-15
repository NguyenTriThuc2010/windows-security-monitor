"""
Network Monitor - Giám sát kết nối mạng
Phát hiện: C2 communication, data exfiltration, reverse shell, port scanning
"""

import psutil
import socket
import threading
import time
import re
import ipaddress
from datetime import datetime
from typing import Callable, Dict, List, Set
from collections import defaultdict


# Các port thường dùng cho malware
SUSPICIOUS_PORTS = {
    # Remote Access / RAT ports
    1337, 4444, 4445, 4446, 5555, 6666, 7777, 8888, 9999,
    31337, 31338, 54321, 65000, 65535,
    # Common backdoor ports
    1234, 2345, 3456, 7890, 8765, 9876,
    # Metasploit defaults
    4444,
}

# Port hợp lệ phổ biến
KNOWN_GOOD_PORTS = {
    80, 443, 8080, 8443,  # HTTP/HTTPS
    53, 853,              # DNS
    25, 465, 587, 993, 995,  # Email
    21, 22, 23,           # FTP, SSH, Telnet
    3389,                 # RDP
    3306, 5432, 1433,     # DB ports
    67, 68,              # DHCP
    123,                 # NTP
}

# Private IP ranges (không cần lo lắng nhiều)
PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]

# Các process không nên tạo kết nối mạng
NO_NETWORK_PROCS = [
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe",
    "snippingtool.exe", "magnify.exe", "narrator.exe",
]


def is_private_ip(ip_str: str) -> bool:
    """Kiểm tra IP có phải private không"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in PRIVATE_RANGES)
    except:
        return False


class NetworkMonitor:
    """Monitor giám sát kết nối mạng"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scan_interval = 10  # seconds
        self.connection_history: Dict[str, list] = defaultdict(list)
        self.bytes_history: Dict[int, dict] = {}  # pid -> {sent, recv, timestamp}
        self.alerted_connections: Set[str] = set()
        self.stats = {
            "total_connections": 0,
            "suspicious_connections": 0,
            "blocked_ips": set(),
            "last_scan": None,
            "upload_mb": 0,
            "download_mb": 0
        }
        self.current_connections = []

    def get_all_connections(self) -> list:
        """Lấy tất cả kết nối mạng hiện tại"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='all'):
                try:
                    conn_info = {
                        "pid": conn.pid,
                        "process": "",
                        "family": str(conn.family.name) if conn.family else "?",
                        "type": str(conn.type.name) if conn.type else "?",
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "remote_ip": conn.raddr.ip if conn.raddr else "",
                        "remote_port": conn.raddr.port if conn.raddr else 0,
                        "status": conn.status,
                        "suspicious_flags": []
                    }

                    # Lấy tên process
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            conn_info["process"] = proc.name()
                        except:
                            conn_info["process"] = f"PID-{conn.pid}"

                    connections.append(conn_info)
                except:
                    continue
        except (psutil.AccessDenied, Exception) as e:
            self.logger.warning(f"NetMonitor get_connections: {e}")

        return connections

    def check_suspicious_port(self, conn: dict) -> list:
        """Kiểm tra kết nối đến port đáng ngờ"""
        flags = []
        remote_port = conn["remote_port"]

        if remote_port in SUSPICIOUS_PORTS and conn["status"] == "ESTABLISHED":
            conn_key = f"{conn['remote_ip']}:{remote_port}:{conn['pid']}"
            if conn_key not in self.alerted_connections:
                self.alerted_connections.add(conn_key)
                flags.append({
                    "type": "SUSPICIOUS_PORT",
                    "severity": "HIGH",
                    "detail": f"Kết nối đến port đáng ngờ {remote_port} "
                              f"bởi '{conn['process']}' "
                              f"-> {conn['remote_ip']}:{remote_port}"
                })

        return flags

    def check_no_network_process(self, conn: dict) -> list:
        """Kiểm tra process không nên có kết nối mạng"""
        flags = []
        proc_name = conn["process"].lower()

        if proc_name in [p.lower() for p in NO_NETWORK_PROCS]:
            if conn["remote_ip"] and not is_private_ip(conn["remote_ip"]):
                conn_key = f"no-net:{conn['pid']}:{conn['remote_ip']}"
                if conn_key not in self.alerted_connections:
                    self.alerted_connections.add(conn_key)
                    flags.append({
                        "type": "UNEXPECTED_NETWORK",
                        "severity": "HIGH",
                        "detail": f"Process '{conn['process']}' (không nên có mạng) kết nối đến {conn['remote_ip']}:{conn['remote_port']}"
                    })

        return flags

    def check_reverse_shell_patterns(self, conn: dict) -> list:
        """Phát hiện reverse shell connections"""
        flags = []
        proc_name = conn["process"].lower()
        remote_port = conn["remote_port"]

        # Shell procs kết nối ra ngoài
        shell_procs = ["cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe"]

        if proc_name in shell_procs and conn["status"] == "ESTABLISHED":
            if conn["remote_ip"] and not is_private_ip(conn["remote_ip"]):
                conn_key = f"rshell:{conn['pid']}:{conn['remote_ip']}"
                if conn_key not in self.alerted_connections:
                    self.alerted_connections.add(conn_key)
                    flags.append({
                        "type": "REVERSE_SHELL",
                        "severity": "CRITICAL",
                        "detail": f"🚨 REVERSE SHELL DETECTED! '{conn['process']}' kết nối đến {conn['remote_ip']}:{remote_port}"
                    })

        return flags

    def check_high_connection_count(self) -> list:
        """Phát hiện process có quá nhiều kết nối (port scanning, botnet)"""
        flags = []
        proc_connections = defaultdict(list)

        for conn in self.current_connections:
            if conn["pid"]:
                proc_connections[conn["pid"]].append(conn)

        for pid, conns in proc_connections.items():
            if len(conns) > 50:  # Ngưỡng đáng ngờ
                proc_name = conns[0]["process"]
                conn_key = f"highconn:{pid}"
                if conn_key not in self.alerted_connections:
                    self.alerted_connections.add(conn_key)
                    flags.append({
                        "pid": pid,
                        "type": "HIGH_CONNECTION_COUNT",
                        "severity": "MEDIUM",
                        "detail": f"'{proc_name}' (PID {pid}) có {len(conns)} kết nối - có thể là port scanner hoặc botnet"
                    })

        return flags

    def check_data_exfiltration(self) -> list:
        """Phát hiện data exfiltration qua theo dõi lưu lượng mạng"""
        flags = []
        try:
            current_io = psutil.net_io_counters(pernic=False)
            current_time = time.time()

            if hasattr(self, '_last_io'):
                elapsed = current_time - self._last_time
                if elapsed > 0:
                    sent_rate = (current_io.bytes_sent - self._last_io.bytes_sent) / elapsed / 1024  # KB/s
                    self.stats["upload_mb"] = current_io.bytes_sent / 1024 / 1024

                    # Cảnh báo nếu upload > 10MB/s liên tục (data exfiltration)
                    if sent_rate > 10240:  # 10 MB/s
                        if "exfil_high" not in self.alerted_connections:
                            self.alerted_connections.add("exfil_high")
                            flags.append({
                                "type": "DATA_EXFILTRATION",
                                "severity": "HIGH",
                                "detail": f"🔺 Upload bất thường cao: {sent_rate/1024:.1f} MB/s - có thể đang đánh cắp dữ liệu!"
                            })
                    else:
                        self.alerted_connections.discard("exfil_high")

            self._last_io = current_io
            self._last_time = current_time

        except Exception as e:
            pass

        return flags

    def check_dns_over_non_standard(self, conn: dict) -> list:
        """Phát hiện DNS tunneling (DNS qua port lạ)"""
        flags = []
        remote_port = conn["remote_port"]

        # DNS thường dùng port 53
        # Nếu có kết nối UDP đến port 53 từ process lạ
        # hoặc TCP port 53 với lượng data lớn -> có thể DNS tunneling
        if remote_port == 53 and conn["type"] == "SOCK_STREAM":  # TCP DNS bất thường
            conn_key = f"dns-tcp:{conn['remote_ip']}"
            if conn_key not in self.alerted_connections:
                self.alerted_connections.add(conn_key)
                flags.append({
                    "type": "DNS_TUNNELING_SUSPECT",
                    "severity": "MEDIUM",
                    "detail": f"DNS qua TCP từ '{conn['process']}' -> {conn['remote_ip']} (có thể DNS tunneling)"
                })

        return flags

    def scan_connections(self):
        """Quét và phân tích tất cả kết nối"""
        connections = self.get_all_connections()
        self.current_connections = connections
        self.stats["total_connections"] = len(connections)
        self.stats["last_scan"] = datetime.now().isoformat()

        all_flags = []

        for conn in connections:
            if not conn["remote_ip"]:
                continue

            flags = []
            flags.extend(self.check_suspicious_port(conn))
            flags.extend(self.check_no_network_process(conn))
            flags.extend(self.check_reverse_shell_patterns(conn))
            flags.extend(self.check_dns_over_non_standard(conn))

            for flag in flags:
                self.stats["suspicious_connections"] += 1
                self.alert_callback({
                    "module": "NetworkMonitor",
                    "severity": flag.get("severity", "MEDIUM"),
                    "type": flag["type"],
                    "message": flag["detail"],
                    "connection": {
                        "process": conn["process"],
                        "pid": conn["pid"],
                        "remote": conn["remote_addr"],
                        "status": conn["status"]
                    }
                })

        # Kiểm tra high connection count
        hcc_flags = self.check_high_connection_count()
        for flag in hcc_flags:
            self.alert_callback({
                "module": "NetworkMonitor",
                "severity": flag.get("severity", "MEDIUM"),
                "type": flag["type"],
                "message": flag["detail"]
            })

        # Kiểm tra data exfiltration
        exfil_flags = self.check_data_exfiltration()
        for flag in exfil_flags:
            self.alert_callback({
                "module": "NetworkMonitor",
                "severity": flag.get("severity", "HIGH"),
                "type": flag["type"],
                "message": flag["detail"]
            })

    def get_active_connections(self) -> list:
        """Lấy danh sách kết nối active (cho dashboard)"""
        return [c for c in self.current_connections
                if c["status"] == "ESTABLISHED" and c["remote_ip"]][:20]

    def start(self):
        """Bắt đầu giám sát mạng"""
        self.running = True
        self._last_io = psutil.net_io_counters()
        self._last_time = time.time()
        self.logger.info("NetworkMonitor started")

        while self.running:
            try:
                self.scan_connections()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"NetworkMonitor error: {e}")
                time.sleep(15)

    def stop(self):
        self.running = False
