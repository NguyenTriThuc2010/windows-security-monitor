"""
Web Threat Protector (Lá chắn Web & Tiện ích)
Quét tiện ích mở rộng Chrome/Edge và giám sát file tải xuống an toàn.
"""

import os
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Callable, Set

class WebProtector:
    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scan_interval = 60  # Quét extension mỗi 1 phút
        
        self.alerted_extensions = set()
        self.alerted_downloads = set()
        
        self.stats = {
            "extensions_checked": 0,
            "downloads_checked": 0,
            "threats_found": 0,
            "last_scan": None
        }

    def get_browser_extension_paths(self):
        """Lấy danh sách đường dẫn chứa Extensions của các trình duyệt"""
        paths = []
        local_app_data = os.environ.get('LOCALAPPDATA', '')
        if not local_app_data:
            return paths
            
        browsers = [
            ("Chrome", r"Google\Chrome\User Data\Default\Extensions"),
            ("Edge", r"Microsoft\Edge\User Data\Default\Extensions"),
            ("Brave", r"BraveSoftware\Brave-Browser\User Data\Default\Extensions")
        ]
        
        for name, subpath in browsers:
            full_path = os.path.join(local_app_data, subpath)
            if os.path.exists(full_path):
                paths.append((name, full_path))
                
        return paths

    def scan_extensions(self):
        """Quét tìm Extension độc hại qua manifest.json"""
        ext_paths = self.get_browser_extension_paths()
        
        # Các quyền nhạy cảm thường bị lợi dụng để trộm dữ liệu
        dangerous_permissions = {
            "cookies": "Quyền đọc trộm Cookie",
            "webRequest": "Quyền theo dõi mọi kết nối Web",
            "webRequestBlocking": "Quyền chặn/thay đổi trang web",
            "tabs": "Quyền đọc tiêu đề và URL các tab đang mở",
            "<all_urls>": "Quyền can thiệp vào MỌI trang web",
            "history": "Quyền đọc lịch sử duyệt web",
            "desktopCapture": "Quyền quay màn hình"
        }

        for browser_name, ext_folder in ext_paths:
            try:
                for ext_id in os.listdir(ext_folder):
                    ext_dir = os.path.join(ext_folder, ext_id)
                    if not os.path.isdir(ext_dir):
                        continue
                        
                    # Extension thường có version folders bên trong
                    for version in os.listdir(ext_dir):
                        ver_dir = os.path.join(ext_dir, version)
                        manifest_path = os.path.join(ver_dir, "manifest.json")
                        
                        if os.path.exists(manifest_path):
                            self.stats["extensions_checked"] += 1
                            try:
                                with open(manifest_path, 'r', encoding='utf-8') as f:
                                    manifest = json.load(f)
                                    
                                ext_name = manifest.get("name", "Unknown")
                                permissions = manifest.get("permissions", [])
                                host_permissions = manifest.get("host_permissions", [])
                                
                                # Gộp tất cả permission để check
                                all_perms = permissions + host_permissions
                                
                                found_dangers = []
                                for perm in all_perms:
                                    if perm in dangerous_permissions:
                                        found_dangers.append(f"{perm} ({dangerous_permissions[perm]})")
                                        
                                # Nếu phát hiện Extension đòi quá nhiều quyền nhạy cảm (>= 2 quyền)
                                if len(found_dangers) >= 2:
                                    alert_key = f"ext:{ext_id}:{version}"
                                    if alert_key not in self.alerted_extensions:
                                        self.alerted_extensions.add(alert_key)
                                        self.stats["threats_found"] += 1
                                        
                                        self.alert_callback({
                                            "module": "WebProtector",
                                            "severity": "HIGH",
                                            "type": "SUSPICIOUS_EXTENSION",
                                            "message": f"🛡️ TRÌNH DUYỆT ({browser_name}): Tiện ích mở rộng đáng ngờ đang được cài!\n"
                                                       f"Tên: {ext_name} (ID: {ext_id})\n"
                                                       f"Cảnh báo: Tiện ích này yêu cầu các quyền quá nguy hiểm: {', '.join(found_dangers)}.\n"
                                                       f"Nó có khả năng ăn cắp Cookie và Mật khẩu của bạn. Hãy gỡ bỏ nếu không tin tưởng."
                                        })
                            except json.JSONDecodeError:
                                pass
            except Exception:
                continue

    def scan_downloads(self):
        """Giám sát thư mục Downloads để cảnh báo file cài đặt lạ"""
        user_profile = os.environ.get('USERPROFILE', '')
        if not user_profile:
            return
            
        downloads_dir = os.path.join(user_profile, "Downloads")
        if not os.path.exists(downloads_dir):
            return
            
        try:
            # Chỉ check các file được tạo trong vòng 2 phút qua
            current_time = time.time()
            
            for file in os.listdir(downloads_dir):
                if file.endswith(('.exe', '.msi', '.vbs', '.bat', '.ps1', '.js')):
                    filepath = os.path.join(downloads_dir, file)
                    
                    if not os.path.isfile(filepath):
                        continue
                        
                    # Lấy thời gian tạo hoặc chỉnh sửa file
                    mtime = os.path.getmtime(filepath)
                    if current_time - mtime < 120:  # Mới tải xuống trong 2 phút
                        if filepath not in self.alerted_downloads:
                            self.alerted_downloads.add(filepath)
                            self.stats["downloads_checked"] += 1
                            
                            self.alert_callback({
                                "module": "WebProtector",
                                "severity": "MEDIUM",
                                "type": "DANGEROUS_DOWNLOAD",
                                "message": f"📥 TẢI XUỐNG: Bạn vừa tải một file thực thi nguy hiểm!\n"
                                           f"File: {filepath}\n"
                                           f"Lưu ý: Nếu bạn vô tình click vào file này khi lướt web, nó có thể là ClickFix hoặc Malware. Đừng chạy nếu không rõ nguồn gốc."
                            })
        except Exception:
            pass

    def scan(self):
        self.scan_extensions()
        self.scan_downloads()
        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        self.running = True
        self.logger.info("WebProtector started")
        
        while self.running:
            try:
                self.scan()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"WebProtector error: {e}")
                time.sleep(20)

    def stop(self):
        self.running = False
