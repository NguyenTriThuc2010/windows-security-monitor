"""
Infostealer Detector & Network Sniffer
Phát hiện mã độc chuyên ăn cắp tài khoản (Browser Infostealers) 
bằng cách giám sát việc đọc lén file Cookie/Password và bắt gói tin mạng gửi đi.
"""

import psutil
import socket
import time
import threading
import ipaddress
from datetime import datetime
from typing import Callable, Set

# Danh sách các tiến trình hợp lệ được phép đọc dữ liệu trình duyệt
LEGITIMATE_BROWSERS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "vivaldi.exe", "iexplore.exe", "dllhost.exe", "explorer.exe",
    # Thêm các ứng dụng IDE/dev hợp lệ không nên bị cảnh báo
    "antigravity.exe", "code.exe", "cursor.exe", "windsurf.exe",
    "devenv.exe", "idea64.exe", "pycharm64.exe", "webstorm64.exe",
    "node.exe", "python.exe", "python3.exe", "pythonw.exe",
}

# Tên các file nhạy cảm chứa Cookie và Mật khẩu của trình duyệt
SENSITIVE_FILES = [
    "Cookies", "Login Data", "Web Data", "Local State", 
    "key4.db", "logins.json", "places.sqlite"
]

# Các endpoint thường bị mã độc lợi dụng để gửi dữ liệu đánh cắp (Data Exfiltration)
# Infostealers thường lười dựng server riêng mà dùng Telegram Bot hoặc Discord Webhook.
SUSPICIOUS_ENDPOINTS = [
    "api.telegram.org",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "pastebin.com/raw",
]


class InfostealerDetector:
    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scan_interval = 5  # Quét liên tục mỗi 5s vì việc đánh cắp diễn ra rất nhanh
        self.alerted_events: Set[str] = set()
        
        # Cache IP của các endpoint đáng ngờ để check nhanh
        self.suspicious_ips = set()
        self.resolve_endpoints()
        
        self.stats = {
            "files_checked": 0,
            "threats_found": 0,
            "last_scan": None
        }

    def resolve_endpoints(self):
        """Phân giải tên miền thành IP, loại bỏ IP nội bộ/localhost"""
        PRIVATE_RANGES = [
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("::1/128"),
        ]

        def is_private(ip_str):
            try:
                ip = ipaddress.ip_address(ip_str)
                return any(ip in net for net in PRIVATE_RANGES)
            except Exception:
                return True  # Không parse được -> bỏ qua cho an toàn

        for domain in SUSPICIOUS_ENDPOINTS:
            try:
                host = domain.split('/')[0]
                _, _, ip_list = socket.gethostbyname_ex(host)
                for ip in ip_list:
                    if not is_private(ip):  # Chỉ thêm IP công cộng
                        self.suspicious_ips.add(ip)
            except Exception:
                pass

    def check_file_access(self):
        """Kiểm tra xem có process lạ nào đang đọc trộm file Cookie không"""
        if not self.is_admin:
            return

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pinfo = proc.info
                pname = (pinfo['name'] or "").lower()
                pid = pinfo['pid']

                # Bỏ qua system processes và browsers
                if pid <= 4 or pname in LEGITIMATE_BROWSERS:
                    continue

                open_files = proc.open_files()
                for f in open_files:
                    filepath = f.path
                    filename = filepath.split('\\')[-1]

                    # Nếu process lạ mở file Login Data hoặc Cookies
                    if filename in SENSITIVE_FILES and ("User Data" in filepath or "Profiles" in filepath):
                        alert_key = f"file_theft:{pid}:{filename}"
                        if alert_key not in self.alerted_events:
                            self.alerted_events.add(alert_key)
                            self.stats["threats_found"] += 1
                            
                            self.alert_callback({
                                "module": "InfostealerDetector",
                                "severity": "CRITICAL",
                                "type": "BROWSER_DATA_THEFT",
                                "message": f"🚨 Phát hiện INFOSTEALER! Một phần mềm đang lén lút đọc dữ liệu trình duyệt.\n"
                                           f"Process: '{pname}' (PID: {pid})\n"
                                           f"Đang đánh cắp file: {filepath}\n"
                                           f"Hành động này sẽ làm lộ Mật khẩu và Cookie phiên đăng nhập của bạn!"
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def check_network_exfiltration(self):
        """Giám sát kết nối mạng để tìm hành vi gửi dữ liệu ra ngoài qua Telegram/Discord"""
        try:
            # Refresh IP cache định kỳ
            if int(time.time()) % 300 == 0:
                self.resolve_endpoints()

            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    
                    if remote_ip in self.suspicious_ips:
                        pid = conn.pid
                        if not pid:
                            continue
                            
                        try:
                            proc = psutil.Process(pid)
                            pname = proc.name().lower()
                        except:
                            pname = "Unknown"

                        # Browser có thể kết nối Telegram hợp lệ, nhưng process khác thì không
                        if pname not in LEGITIMATE_BROWSERS:
                            alert_key = f"net_exfil:{pid}:{remote_ip}"
                            if alert_key not in self.alerted_events:
                                self.alerted_events.add(alert_key)
                                self.stats["threats_found"] += 1
                                
                                self.alert_callback({
                                    "module": "InfostealerDetector",
                                    "severity": "CRITICAL",
                                    "type": "DATA_EXFILTRATION_DETECTED",
                                    "message": f"🚨 CẢNH BÁO BỊ LỘ DỮ LIỆU! Process '{pname}' đang gửi dữ liệu ngầm ra ngoài.\n"
                                               f"Đích đến: {remote_ip} (Nghi ngờ là Telegram API/Discord Webhook)\n"
                                               f"Mã độc Infostealer thường dùng cách này để tẩu tán mật khẩu/cookie vừa trộm được."
                                })
        except Exception as e:
            pass

    def scan(self):
        self.check_file_access()
        self.check_network_exfiltration()
        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        self.running = True
        self.logger.info("InfostealerDetector started")
        
        while self.running:
            try:
                self.scan()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"InfostealerDetector error: {e}")
                time.sleep(10)

    def stop(self):
        self.running = False
