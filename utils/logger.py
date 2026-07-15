import logging
import os
from datetime import datetime
from pathlib import Path

class SecurityLogger:
    def __init__(self):
        log_dir = Path(__file__).parent.parent / "logs"
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            filename=log_dir / f"security_monitor_{datetime.now().strftime('%Y%m%d')}.log",
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("SecurityMonitor")

    def info(self, msg):
        self.logger.info(msg)
        
    def warning(self, msg):
        self.logger.warning(msg)
        
    def error(self, msg):
        self.logger.error(msg)
        
    def log_alert(self, alert):
        self.logger.critical(f"ALERT [{alert.get('severity', 'UNKNOWN')}]: {alert.get('type')} - {alert.get('message')}")
