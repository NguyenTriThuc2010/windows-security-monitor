"""
Keylogger Detector - Phát hiện keylogger và hook bàn phím
Phát hiện: global keyboard hooks, mouse hooks, process monitoring input
"""

import psutil
import time
import ctypes
import threading
from datetime import datetime
from typing import Callable, Set

try:
    import win32api
    import win32con
    import win32gui
    import win32process
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

try:
    import ctypes.wintypes
    HAS_CTYPES = True
except:
    HAS_CTYPES = False


# Process có thể cần hook keyboard hợp lệ (antivirus, accessibility, IME)
LEGITIMATE_HOOK_PROCESSES = {
    "msmpeng.exe",      # Windows Defender
    "nissrv.exe",       # Windows Defender Network
    "avp.exe",          # Kaspersky
    "avgnt.exe",        # Avira
    "bdagent.exe",      # Bitdefender
    "ekrn.exe",         # ESET
    "mbam.exe",         # Malwarebytes
    "ctfmon.exe",       # CTF Monitor (IME, Input Method)
    "tabtip.exe",       # Touch keyboard
    "osk.exe",          # On-screen keyboard
    "magnify.exe",      # Magnifier
    "narrator.exe",     # Narrator
    "acccheck.exe",     # Accessibility
    "svchost.exe",      # System service
    "explorer.exe",     # Explorer
    "dwm.exe",          # Desktop Window Manager
    "inputservice.dll", # Input Service
    "textinputhost.exe", # Text Input
}

# Windows Hook types
WH_KEYBOARD_LL = 13  # Low-level keyboard hook
WH_MOUSE_LL = 14     # Low-level mouse hook
WH_KEYBOARD = 2      # Keyboard hook
WH_CBT = 5           # CBT hook (can monitor all windows)
WH_JOURNALRECORD = 0  # Journal recording hook (keylogger!)
WH_JOURNALPLAYBACK = 1  # Journal playback


class KeyloggerDetector:
    """Phát hiện keylogger và hook bàn phím"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.alerted_procs: Set[int] = set()
        self.scan_interval = 15  # seconds
        self.stats = {
            "hooks_detected": 0,
            "suspicious_procs": 0,
            "last_scan": None
        }
        self.detected_hooks = []

    def check_global_hooks_win32(self) -> list:
        """Kiểm tra global hooks qua Win32 API"""
        suspicious = []

        if not HAS_WIN32:
            return suspicious

        try:
            # Enumerate windows và kiểm tra hooks
            # Đây là cách tiếp cận qua process analysis
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pinfo = proc.info
                    pid = pinfo['pid']
                    name = pinfo['name'].lower() if pinfo['name'] else ""

                    if name in [p.lower() for p in LEGITIMATE_HOOK_PROCESSES]:
                        continue

                    # Kiểm tra modules được load trong process
                    try:
                        modules = proc.memory_maps()
                        for mod in modules:
                            mod_path = mod.path.lower() if hasattr(mod, 'path') else ""

                            # Hook DLLs đáng ngờ
                            hook_indicators = [
                                "hook", "keylog", "spy", "monitor", "capture",
                                "record", "sniff", "intercept", "logger"
                            ]

                            for indicator in hook_indicators:
                                if indicator in mod_path:
                                    if pid not in self.alerted_procs:
                                        self.alerted_procs.add(pid)
                                        suspicious.append({
                                            "pid": pid,
                                            "name": pinfo['name'],
                                            "type": "HOOK_DLL_LOADED",
                                            "severity": "HIGH",
                                            "detail": f"Process '{pinfo['name']}' load DLL đáng ngờ: {mod_path}"
                                        })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue

        except Exception as e:
            self.logger.warning(f"Hook check error: {e}")

        return suspicious

    def check_suspicious_open_handles(self) -> list:
        """Kiểm tra process mở handles đến keyboard device"""
        suspicious = []

        # Kiểm tra qua OpenProcess handles (cần admin)
        if not self.is_admin:
            return suspicious

        keyboard_device_names = [
            "\\Device\\KeyboardClass0",
            "\\Device\\KeyboardClass1",
            "\\Device\\PointerClass0",
        ]

        # Dùng psutil để kiểm tra open files (có thể phát hiện một số trường hợp)
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pname = proc.info['name'].lower() if proc.info['name'] else ""
                if pname in [p.lower() for p in LEGITIMATE_HOOK_PROCESSES]:
                    continue

                # Kiểm tra open files
                try:
                    open_files = proc.open_files()
                    for f in open_files:
                        fpath = f.path.lower()
                        for kbd_dev in keyboard_device_names:
                            if kbd_dev.lower() in fpath:
                                pid = proc.info['pid']
                                if pid not in self.alerted_procs:
                                    self.alerted_procs.add(pid)
                                    suspicious.append({
                                        "pid": pid,
                                        "name": proc.info['name'],
                                        "type": "KEYBOARD_DEVICE_ACCESS",
                                        "severity": "CRITICAL",
                                        "detail": f"🚨 Process '{proc.info['name']}' đang mở keyboard device!\n"
                                                 f"Device: {f.path}"
                                    })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue

        return suspicious

    def check_clipboard_monitoring(self) -> list:
        """Phát hiện process theo dõi clipboard (spyware)"""
        suspicious = []

        try:
            if HAS_WIN32:
                # Kiểm tra clipboard chain
                hwnd = win32gui.GetClipboardOwner()
                if hwnd:
                    try:
                        _, pid = win32process.GetWindowThreadProcessId(hwnd)
                        proc = psutil.Process(pid)
                        pname = proc.name().lower()

                        if pname not in [p.lower() for p in LEGITIMATE_HOOK_PROCESSES]:
                            if pid not in self.alerted_procs:
                                self.alerted_procs.add(pid)
                                suspicious.append({
                                    "pid": pid,
                                    "name": proc.name(),
                                    "type": "CLIPBOARD_MONITOR",
                                    "severity": "MEDIUM",
                                    "detail": f"Process '{proc.name()}' đang theo dõi clipboard (đánh cắp dữ liệu copy/paste?)"
                                })
                    except:
                        pass
        except Exception as e:
            pass

        return suspicious

    def check_process_names_for_keylogger(self) -> list:
        """Kiểm tra tên process có liên quan đến keylogger"""
        suspicious = []

        keylogger_keywords = [
            "keylog", "keycapture", "keyspy", "keystroke",
            "keyrecord", "keygrabber", "klog", "keysniff",
            "ardamax", "revealer", "actual spy", "refog",
            "spyrix", "hoverwatch", "flexispy", "mspy",
            "kidlogger", "systemspy", "wolfeye", "spytech",
            "perfect keylogger", "elite keylogger", "all in one",
        ]

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                pinfo = proc.info
                name_lower = (pinfo['name'] or "").lower()
                exe_lower = (pinfo['exe'] or "").lower()
                cmd_lower = " ".join(pinfo['cmdline'] or []).lower()

                for keyword in keylogger_keywords:
                    if keyword in name_lower or keyword in exe_lower or keyword in cmd_lower:
                        pid = pinfo['pid']
                        if pid not in self.alerted_procs:
                            self.alerted_procs.add(pid)
                            suspicious.append({
                                "pid": pid,
                                "name": pinfo['name'],
                                "type": "KEYLOGGER_PROCESS_NAME",
                                "severity": "CRITICAL",
                                "detail": f"🚨 Process tên khớp keylogger đã biết: '{pinfo['name']}'\n"
                                         f"EXE: {pinfo['exe']}"
                            })
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return suspicious

    def check_screenshot_processes(self) -> list:
        """Phát hiện process chụp màn hình liên tục"""
        suspicious = []

        screenshot_keywords = [
            "screenshot", "screencapture", "screengrab",
            "screendump", "screenrecord", "rdpclip",
        ]

        # Nếu không phải tool hợp lệ
        legit_screen_apps = [
            "snippingtool", "snagit", "obs", "bandicam", "fraps",
            "xsplit", "camstudio", "sharex"  # Tool capture hợp lệ
        ]

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pinfo = proc.info
                name_lower = (pinfo['name'] or "").lower()
                exe_lower = (pinfo['exe'] or "").lower()

                is_legit = any(l in name_lower or l in exe_lower for l in legit_screen_apps)
                if is_legit:
                    continue

                for keyword in screenshot_keywords:
                    if keyword in name_lower or keyword in exe_lower:
                        pid = pinfo['pid']
                        if pid not in self.alerted_procs:
                            suspicious.append({
                                "pid": pid,
                                "name": pinfo['name'],
                                "type": "SCREENSHOT_SPYWARE",
                                "severity": "HIGH",
                                "detail": f"Process có thể chụp màn hình: '{pinfo['name']}'"
                            })
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return suspicious

    def scan(self):
        """Quét phát hiện keylogger"""
        all_suspicious = []
        all_suspicious.extend(self.check_process_names_for_keylogger())
        all_suspicious.extend(self.check_global_hooks_win32())
        all_suspicious.extend(self.check_suspicious_open_handles())
        all_suspicious.extend(self.check_clipboard_monitoring())
        all_suspicious.extend(self.check_screenshot_processes())

        for item in all_suspicious:
            self.stats["hooks_detected"] += 1
            self.detected_hooks.append(item)

            self.alert_callback({
                "module": "KeyloggerDetector",
                "severity": item.get("severity", "HIGH"),
                "type": item["type"],
                "message": item["detail"],
                "process": {
                    "pid": item.get("pid"),
                    "name": item.get("name")
                }
            })

        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        """Bắt đầu phát hiện keylogger"""
        self.running = True
        self.logger.info("KeyloggerDetector started")

        while self.running:
            try:
                self.scan()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"KeyloggerDetector error: {e}")
                time.sleep(20)

    def stop(self):
        self.running = False
