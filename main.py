"""
SecurityMonitor - Hệ thống Giám sát Bảo mật Toàn diện 24/7
============================================================
Tác giả: Security Monitor Tool
Phiên bản: 2.0
Mô tả: Giám sát và phát hiện mọi loại bất thường trên Windows
"""

import sys
import os
import time
import ctypes
import threading
import json
from datetime import datetime
from pathlib import Path

# Kiểm tra Python version
if sys.version_info < (3, 8):
    print("❌ Cần Python 3.8 trở lên!")
    sys.exit(1)

# Thêm thư mục gốc vào path
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))


def check_admin():
    """Kiểm tra quyền Administrator"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def install_requirements():
    """Tự động cài đặt thư viện nếu thiếu"""
    import subprocess
    req_file = BASE_DIR / "requirements.txt"
    print("📦 Đang kiểm tra và cài đặt thư viện...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(req_file), "-q"],
        check=True
    )


# Auto-install nếu cần
try:
    import psutil
    import rich
    from watchdog.observers import Observer
except ImportError:
    install_requirements()

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm
from rich import box
import psutil

# Import các module monitor
from monitor.process_monitor import ProcessMonitor
from monitor.network_monitor import NetworkMonitor
from monitor.file_monitor import FileMonitor
from monitor.registry_monitor import RegistryMonitor
from monitor.keylogger_detector import KeyloggerDetector
from monitor.startup_monitor import StartupMonitor
from monitor.api_hook_detector import APIHookDetector
from monitor.memory_analyzer_advanced import MemoryAnalyzerAdvanced
from monitor.wmi_monitor import WMIMonitor
from monitor.infostealer_detector import InfostealerDetector
from monitor.web_protector import WebProtector
from monitor.self_defense import SelfDefenseMonitor
from monitor.behavior_analyzer import BehaviorAnalyzer
from monitor.threat_response import ThreatResponseEngine
from monitor.deep_file_scanner import DeepFileScanner
from monitor.kernel_etw import KernelETWMonitor
from monitor.kernel_module_scanner import KernelModuleScanner
from monitor.crossview_detector import CrossViewDetector
from monitor.update_checker import UpdateChecker
from utils.logger import SecurityLogger
from utils.alert import AlertSystem
from ui.dashboard import SecurityDashboard

console = Console()

BANNER = """
[bold red]
 ██████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗    ███╗   ███╗ ██████╗ ███╗   ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    ████╗ ████║██╔═══██╗████╗  ██║
███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝     ██╔████╔██║██║   ██║██╔██╗ ██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝      ██║╚██╔╝██║██║   ██║██║╚██╗██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║       ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝       ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
[/bold red]
[bold yellow]         🛡️  Hệ Thống Giám Sát Bảo Mật 24/7 - Windows Security Monitor v2.0  🛡️[/bold yellow]
[dim]         Phát hiện: Virus • Keylogger • Spyware • Malware • Network Attacks • Rootkit[/dim]
"""


class SecurityMonitorApp:
    """Ứng dụng giám sát bảo mật chính"""

    def __init__(self):
        self.is_admin = check_admin()
        self.logger = SecurityLogger()
        self.alert_system = AlertSystem(self.logger)
        self.dashboard = SecurityDashboard()
        self.monitors = {}
        self.running = False
        self.alerts = []
        self.lock = threading.Lock()
        self.start_time = datetime.now()
        # Khoi tao Threat Response Engine - nhan canh bao tu tat ca cac module
        self.response_engine = ThreatResponseEngine(
            alert_callback=self.add_alert,
            logger=self.logger,
            is_admin=self.is_admin
        )

    def initialize_monitors(self):
        """Khởi tạo tất cả các module giám sát"""
        console.print("\n[bold cyan]🔧 Đang khởi tạo các module giám sát...[/bold cyan]")

        monitor_configs = [
            ("process", ProcessMonitor, "⚙️  Process Monitor    "),
            ("network", NetworkMonitor, "🌐 Network Monitor    "),
            ("file", FileMonitor, "📁 File System Monitor"),
            ("registry", RegistryMonitor, "🔑 Registry Monitor   "),
            ("keylogger", KeyloggerDetector, "⌨️  Keylogger Detector"),
            ("startup", StartupMonitor, "🚀 Startup Monitor    "),
            ("api_hook", APIHookDetector, "🪝  API Hook Detector  "),
            ("adv_memory", MemoryAnalyzerAdvanced, "🧠 Advanced RAM Scan  "),
            ("wmi", WMIMonitor, "👻 WMI Persistence    "),
            ("infostealer", InfostealerDetector, "🍪 Infostealer Guard  "),
            ("web", WebProtector, "🌍 Web Protector      "),
            ("self_defense", SelfDefenseMonitor, "🛡️  Self Defense       "),
            ("deep_scan", DeepFileScanner, "🔍 Deep File Scanner  "),
            ("kernel_etw", KernelETWMonitor, "🖥️  Kernel ETW Events  "),
            ("kernel_drv", KernelModuleScanner, "🩸 Kernel Driver Scan "),
            ("crossview", CrossViewDetector, "👻 CrossView Rootkit  "),
            ("updater", UpdateChecker, "🔄 Auto Updater       "),
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            for key, MonitorClass, name in monitor_configs:
                task = progress.add_task(f"Khởi tạo {name}...", total=None)
                try:
                    self.monitors[key] = MonitorClass(
                        alert_callback=self.add_alert,
                        logger=self.logger,
                        is_admin=self.is_admin
                    )
                    progress.update(task, description=f"[green]✅ {name} - OK[/green]")
                except Exception as e:
                    progress.update(task, description=f"[yellow]⚠️  {name} - Hạn chế: {e}[/yellow]")
                time.sleep(0.3)

        # Behavior Analyzer cần tất cả monitors khác
        self.behavior_analyzer = BehaviorAnalyzer(
            monitors=self.monitors,
            alert_callback=self.add_alert,
            logger=self.logger
        )

        console.print("\n[bold green]✅ Tất cả module đã sẵn sàng![/bold green]")

    def add_alert(self, alert: dict):
        """Them canh bao moi vao danh sach va chuyen sang engine phan ung"""
        with self.lock:
            alert['timestamp'] = datetime.now().isoformat()
            self.alerts.append(alert)
            self.logger.log_alert(alert)
            if len(self.alerts) > 1000:
                self.alerts = self.alerts[-1000:]
        # Chuyen canh bao sang ThreatResponseEngine de tinh diem va phan ung
        try:
            self.response_engine.ingest_alert(alert)
        except Exception:
            pass

    def start_all_monitors(self):
        """Khởi động tất cả các monitor trong luồng riêng biệt"""
        threads = []
        for name, monitor in self.monitors.items():
            t = threading.Thread(
                target=monitor.start,
                name=f"Monitor-{name}",
                daemon=True
            )
            t.start()
            threads.append(t)

        # Behavior analyzer
        ba_thread = threading.Thread(
            target=self.behavior_analyzer.start,
            name="BehaviorAnalyzer",
            daemon=True
        )
        ba_thread.start()
        threads.append(ba_thread)

        # Threat Response Engine
        re_thread = threading.Thread(
            target=self.response_engine.start,
            name="ThreatResponseEngine",
            daemon=True
        )
        re_thread.start()
        threads.append(re_thread)

        return threads

    def run(self):
        """Chạy ứng dụng chính"""
        import sys
        
        # Sửa lỗi Unicode trên Windows console
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except AttributeError:
            pass
            
        console.print(BANNER)
        time.sleep(1)

        # Kiểm tra quyền admin
        if not self.is_admin:
            console.print(
                Panel(
                    "[yellow]⚠️  CẢNH BÁO: Đang chạy KHÔNG có quyền Administrator!\n"
                    "Một số tính năng sẽ bị hạn chế:\n"
                    "• Không thể giám sát một số process hệ thống\n"
                    "• Keylogger detection có thể không đầy đủ\n"
                    "• Memory analysis bị giới hạn\n\n"
                    "💡 Để có đầy đủ tính năng, chạy lại với quyền Administrator[/yellow]",
                    title="[bold yellow]Cảnh báo Quyền Hạn[/bold yellow]",
                    border_style="yellow"
                )
            )
            time.sleep(2)
        else:
            console.print("[bold green]✅ Đang chạy với quyền Administrator - Toàn bộ tính năng hoạt động[/bold green]")

        # Khởi tạo monitors
        self.initialize_monitors()

        # Xác nhận bắt đầu giám sát
        console.print(f"\n[bold]🔍 Chuẩn bị bắt đầu giám sát 24/7...[/bold]")
        time.sleep(1)

        # Bắt đầu tất cả monitors
        self.running = True
        threads = self.start_all_monitors()
        console.print("\n[bold green]🚀 Tất cả module giám sát đã khởi động![/bold green]\n")
        time.sleep(1)

        # Chạy dashboard
        try:
            self.dashboard.run(
                monitors=self.monitors,
                alerts=self.alerts,
                lock=self.lock,
                start_time=self.start_time,
                is_admin=self.is_admin
            )
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self):
        """Tắt tất cả monitors"""
        console.print("\n\n[bold yellow]🛑 Đang tắt Security Monitor...[/bold yellow]")
        self.running = False
        for monitor in self.monitors.values():
            try:
                monitor.stop()
            except:
                pass

        # Tạo báo cáo cuối
        from ui.report import generate_report
        report_path = generate_report(self.alerts, self.start_time)
        if report_path:
            console.print(f"[bold green]📊 Báo cáo đã được lưu: {report_path}[/bold green]")

        console.print("[bold red]👋 Security Monitor đã dừng. Tạm biệt![/bold red]")


if __name__ == "__main__":
    app = SecurityMonitorApp()
    app.run()
