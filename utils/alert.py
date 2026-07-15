class AlertSystem:
    def __init__(self, logger):
        self.logger = logger

    def process_alert(self, alert):
        self.logger.log_alert(alert)
        # Trong tương lai có thể gửi email, webhook Telegram/Discord ở đây
