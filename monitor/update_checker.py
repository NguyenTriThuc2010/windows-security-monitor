"""
Auto Update Checker
Kiểm tra phiên bản mới trên GitHub và thông báo cho người dùng.
Chạy mỗi 6 giờ trong nền.
"""
import urllib.request
import urllib.error
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable

# ── Cấu hình ─────────────────────────────────────────
GITHUB_REPO    = "YOUR_USERNAME/windows-security-monitor"  # Sẽ được cập nhật khi push
VERSION_FILE   = Path(__file__).parent.parent / "VERSION"
CHECK_INTERVAL = 6 * 3600  # Kiểm tra mỗi 6 giờ
API_URL        = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


def get_current_version() -> str:
    """Đọc phiên bản hiện tại từ file VERSION"""
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return "0.0.0"


def parse_version(v: str) -> tuple:
    """Chuyển '3.1.0' -> (3, 1, 0) để so sánh"""
    try:
        parts = v.lstrip("v").split(".")
        return tuple(int(x) for x in parts[:3])
    except Exception:
        return (0, 0, 0)


def check_for_update() -> dict | None:
    """
    Gọi GitHub API để lấy thông tin phiên bản mới nhất.
    Trả về dict thông tin nếu có bản mới, None nếu đang dùng bản mới nhất.
    """
    try:
        req = urllib.request.Request(
            API_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "SecurityMonitor-AutoUpdater/3.0"
            }
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        latest_tag     = data.get("tag_name", "").lstrip("v")
        release_name   = data.get("name", "")
        release_notes  = data.get("body", "")
        html_url       = data.get("html_url", "")
        published_at   = data.get("published_at", "")[:10]

        current = get_current_version()

        if parse_version(latest_tag) > parse_version(current):
            return {
                "current":       current,
                "latest":        latest_tag,
                "name":          release_name,
                "notes":         release_notes[:500],
                "url":           html_url,
                "published_at":  published_at,
            }
    except Exception:
        pass  # Không có mạng hoặc repo chưa public -> bỏ qua
    return None


class UpdateChecker:
    """Chạy kiểm tra cập nhật định kỳ trong thread nền"""

    def __init__(self, alert_callback: Callable, logger):
        self.alert_callback = alert_callback
        self.logger = logger
        self.running = False
        self._notified_versions = set()  # Không báo lặp

        self.stats = {
            "last_check": None,
            "latest_version": None,
            "current_version": get_current_version(),
        }

    def start(self):
        self.running = True
        self.logger.info("UpdateChecker started")

        # Kiểm tra ngay sau khi khởi động 60 giây (cho các module khác ổn định trước)
        time.sleep(60)

        while self.running:
            try:
                self._do_check()
            except Exception as e:
                self.logger.warning(f"UpdateChecker error: {e}")
            time.sleep(CHECK_INTERVAL)

    def _do_check(self):
        self.stats["last_check"] = datetime.now().isoformat()
        result = check_for_update()

        if result:
            latest = result["latest"]
            self.stats["latest_version"] = latest

            if latest not in self._notified_versions:
                self._notified_versions.add(latest)
                self.logger.info(f"New version available: v{latest}")

                # Gửi thông báo lên Dashboard
                self.alert_callback({
                    "module": "UpdateChecker",
                    "severity": "LOW",
                    "type": "UPDATE_AVAILABLE",
                    "message": (
                        f"🆕 CÓ BẢN CẬP NHẬT MỚI!\n"
                        f"Phiên bản hiện tại: v{result['current']}\n"
                        f"Phiên bản mới nhất: v{latest}  ({result['published_at']})\n"
                        f"Tên bản cập nhật: {result['name']}\n"
                        f"{'─' * 50}\n"
                        f"Tóm tắt thay đổi:\n{result['notes']}\n"
                        f"{'─' * 50}\n"
                        f"Tải về tại: {result['url']}\n\n"
                        f"Hướng dẫn cập nhật:\n"
                        f"  1. Mở link ở trên trong trình duyệt\n"
                        f"  2. Tải file SecurityMonitor_v{latest}.zip\n"
                        f"  3. Giải nén và chạy lại cài_đặt.bat"
                    ),
                })
        else:
            self.stats["latest_version"] = self.stats["current_version"]

    def stop(self):
        self.running = False
