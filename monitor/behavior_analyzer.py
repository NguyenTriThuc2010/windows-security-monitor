import time

class BehaviorAnalyzer:
    def __init__(self, monitors, alert_callback, logger):
        self.monitors = monitors
        self.alert_callback = alert_callback
        self.logger = logger
        self.running = False

    def start(self):
        self.running = True
        self.logger.info("BehaviorAnalyzer started")
        while self.running:
            time.sleep(10)

    def stop(self):
        self.running = False
