import time

class StartupMonitor:
    def __init__(self, alert_callback, logger, is_admin):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False

    def start(self):
        self.running = True
        self.logger.info("StartupMonitor started")
        while self.running:
            time.sleep(60)

    def stop(self):
        self.running = False
