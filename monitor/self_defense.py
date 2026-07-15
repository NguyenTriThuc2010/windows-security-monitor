"""
Self Defense & Integrity Monitor
Bảo vệ phần mềm giám sát khỏi bị tin tặc tắt hoặc chỉnh sửa mã nguồn.
Module này liên tục kiểm tra mã băm (Hash) của tất cả các file mã nguồn (.py)
"""

import os
import hashlib
import time
from pathlib import Path
from datetime import datetime
from typing import Callable, Dict

class SelfDefenseMonitor:
    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scan_interval = 10  # Quét liên tục mỗi 10 giây
        
        # Đường dẫn gốc của ứng dụng (d:\virus)
        self.base_dir = Path(__file__).parent.parent
        self.file_hashes: Dict[str, str] = {}
        
        self.stats = {
            "files_protected": 0,
            "tamper_attempts": 0,
            "last_scan": None
        }

    def get_file_hash(self, filepath: str) -> str:
        """Tính mã băm SHA-256 của file để phát hiện sự thay đổi dù là nhỏ nhất"""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def build_baseline(self):
        """Khởi tạo danh sách chữ ký số cho mã nguồn"""
        self.logger.info("Đang tính toán mã băm để bảo vệ tính toàn vẹn (Self-Defense)...")
        self.file_hashes.clear()
        
        for root, dirs, files in os.walk(self.base_dir):
            # Bỏ qua các thư mục không cần thiết
            if "__pycache__" in root or ".git" in root or "logs" in root:
                continue
                
            for file in files:
                if file.endswith(".py") or file.endswith(".json") or file.endswith(".txt"):
                    filepath = os.path.join(root, file)
                    file_hash = self.get_file_hash(filepath)
                    if file_hash:
                        self.file_hashes[filepath] = file_hash
        
        self.stats["files_protected"] = len(self.file_hashes)

    def scan_integrity(self):
        """Quét và so sánh chữ ký số hiện tại với chữ ký gốc"""
        if not self.file_hashes:
            self.build_baseline()
            
        current_files = set()
        
        for root, dirs, files in os.walk(self.base_dir):
            if "__pycache__" in root or ".git" in root or "logs" in root:
                continue
                
            for file in files:
                if file.endswith(".py") or file.endswith(".json") or file.endswith(".txt"):
                    filepath = os.path.join(root, file)
                    current_files.add(filepath)
                    
                    current_hash = self.get_file_hash(filepath)
                    
                    # File bị thay đổi mã nguồn
                    if filepath in self.file_hashes and current_hash != self.file_hashes[filepath]:
                        self.stats["tamper_attempts"] += 1
                        self.alert_callback({
                            "module": "SelfDefense",
                            "severity": "CRITICAL",
                            "type": "SOURCE_CODE_TAMPERING",
                            "message": f"🚨 TỰ VỆ: Mã nguồn của hệ thống giám sát đã bị can thiệp!\n"
                                       f"File: {filepath}\n"
                                       f"Có kẻ đang cố gắng làm mù hệ thống bằng cách sửa code."
                        })
                        # Cập nhật lại hash để không báo liên tục cho 1 lần sửa
                        self.file_hashes[filepath] = current_hash
                        
                    # File mới được nhét vào
                    elif filepath not in self.file_hashes:
                        self.stats["tamper_attempts"] += 1
                        self.alert_callback({
                            "module": "SelfDefense",
                            "severity": "HIGH",
                            "type": "UNAUTHORIZED_FILE_INJECTION",
                            "message": f"🚨 TỰ VỆ: Một file lạ vừa được chèn vào thư mục gốc của phần mềm giám sát!\n"
                                       f"File: {filepath}"
                        })
                        self.file_hashes[filepath] = current_hash
                        
        # Kiểm tra file bị xóa
        for original_file in list(self.file_hashes.keys()):
            if original_file not in current_files:
                self.stats["tamper_attempts"] += 1
                self.alert_callback({
                    "module": "SelfDefense",
                    "severity": "CRITICAL",
                    "type": "SECURITY_MODULE_DELETED",
                    "message": f"🚨 TỰ VỆ: Một module bảo vệ đã BỊ XÓA khỏi hệ thống!\n"
                               f"File: {original_file}\n"
                               f"Tin tặc đang cố vô hiệu hóa phần mềm!"
                })
                del self.file_hashes[original_file]

        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        self.running = True
        self.logger.info("SelfDefenseMonitor started")
        
        while self.running:
            try:
                self.scan_integrity()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"SelfDefense error: {e}")
                time.sleep(10)

    def stop(self):
        self.running = False
