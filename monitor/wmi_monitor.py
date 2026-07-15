"""
WMI Persistence Monitor
Phát hiện mã độc ẩn mình trong WMI (Windows Management Instrumentation)
Fileless malware thường tạo EventFilter và CommandLineEventConsumer để tự động chạy.
"""

import time
from datetime import datetime
from typing import Callable, Set

try:
    import wmi
    import pythoncom
    HAS_WMI = True
except ImportError:
    HAS_WMI = False


class WMIMonitor:
    """Giám sát sự tồn tại (Persistence) trong WMI"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scan_interval = 300  # 5 phút/lần vì WMI ít đổi
        self.alerted_items: Set[str] = set()
        self.stats = {
            "filters_checked": 0,
            "consumers_checked": 0,
            "threats_found": 0,
            "last_scan": None
        }

    def scan_wmi(self):
        """Quét các thành phần WMI thường bị lợi dụng"""
        if not HAS_WMI:
            self.logger.warning("Thư viện WMI chưa được cài đặt. Bỏ qua WMI Scan.")
            return

        if not self.is_admin:
            self.logger.warning("WMI Scan yêu cầu quyền Administrator.")
            return

        try:
            # Khởi tạo COM object cho thread này
            pythoncom.CoInitialize()
            
            # Kết nối đến namespace root\subscription (nơi chứa Event Filters)
            c = wmi.WMI(namespace=r"root\subscription")
            
            # 1. Quét __EventFilter
            filters = c.query("SELECT * FROM __EventFilter")
            self.stats["filters_checked"] = len(filters)
            
            for f in filters:
                name = getattr(f, "Name", "")
                query = getattr(f, "Query", "").lower()
                
                # Bỏ qua các filter hợp lệ của hệ thống (ví dụ: SCM Event Log Filter)
                if "scmeventlog" in name.lower() or "bthserv" in name.lower():
                    continue
                    
                if "powershell" in query or "cmd" in query or "wscript" in query:
                    alert_key = f"filter:{name}"
                    if alert_key not in self.alerted_items:
                        self.alerted_items.add(alert_key)
                        self.stats["threats_found"] += 1
                        
                        self.alert_callback({
                            "module": "WMIMonitor",
                            "severity": "CRITICAL",
                            "type": "WMI_EVENT_FILTER_MALWARE",
                            "message": f"🚨 Phát hiện WMI Event Filter đáng ngờ (Fileless Persistence)!\nTên: {name}\nTruy vấn: {query}"
                        })

            # 2. Quét CommandLineEventConsumer
            consumers = c.query("SELECT * FROM CommandLineEventConsumer")
            self.stats["consumers_checked"] = len(consumers)
            
            for cons in consumers:
                name = getattr(cons, "Name", "")
                cmd = getattr(cons, "CommandLineTemplate", "").lower()
                
                if not cmd:
                    continue
                
                # Các pattern của mã độc thường dùng
                suspicious_patterns = [
                    "powershell", "pwsh", "-enc", "-encodedcommand", 
                    "mshta", "regsvr32", "certutil", "bitsadmin", "wscript"
                ]
                
                is_suspicious = any(p in cmd for p in suspicious_patterns)
                
                if is_suspicious:
                    alert_key = f"consumer:{name}"
                    if alert_key not in self.alerted_items:
                        self.alerted_items.add(alert_key)
                        self.stats["threats_found"] += 1
                        
                        self.alert_callback({
                            "module": "WMIMonitor",
                            "severity": "CRITICAL",
                            "type": "WMI_EVENT_CONSUMER_MALWARE",
                            "message": f"🚨 Phát hiện WMI Event Consumer gọi dòng lệnh đáng ngờ!\nTên: {name}\nLệnh: {cmd}"
                        })

        except Exception as e:
            self.logger.error(f"WMI scan failed: {e}")
        finally:
            pythoncom.CoUninitialize()

        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        self.running = True
        self.logger.info("WMIMonitor started")
        
        while self.running:
            try:
                self.scan_wmi()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"WMIMonitor error: {e}")
                time.sleep(60)

    def stop(self):
        self.running = False
