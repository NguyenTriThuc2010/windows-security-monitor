"""
Threat Response Engine - Phản ứng tự động khi phát hiện mối nguy
Có 3 cấp độ hành động:
  LEVEL 1 - SUSPEND:   Tạm treo tiến trình để phân tích (an toàn nhất)
  LEVEL 2 - KILL:      Kết thúc tiến trình độc hại
  LEVEL 3 - ISOLATE:   Chặn mạng + Kill (dành cho mối nguy cao nhất)

QUAN TRỌNG: Phải vượt qua 3 vòng xác minh an toàn trước khi hành động.
"""

import os
import sys
import time
import ctypes
import threading
import subprocess
from datetime import datetime
from typing import Callable, Set, Optional
import psutil

# ──────────────────────────────────────────────
#  DANH SÁCH TIẾN TRÌNH ĐƯỢC BẢO VỆ TUYỆT ĐỐI
#  Không bao giờ được phép Kill các tiến trình này
# ──────────────────────────────────────────────
PROTECTED_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "dwm.exe", "explorer.exe",
    "taskmgr.exe", "regedit.exe", "cmd.exe",
    # Bảo vệ chính bản thân chương trình này
    "python.exe", "pythonw.exe",
    # Bảo vệ Antivirus phổ biến
    "msmpeng.exe", "nissrv.exe", "avp.exe",
    "avgnt.exe", "bdagent.exe", "ekrn.exe",
}

# Ngưỡng điểm tối thiểu để kích hoạt hành động tự động
# (tránh hành động nhầm dựa trên 1 dấu hiệu duy nhất)
KILL_THREAT_SCORE_MIN   = 80   # Tổng điểm >= 80: Kill
SUSPEND_THREAT_SCORE_MIN = 50  # Tổng điểm >= 50: Suspend trước
ISOLATE_THRESHOLD        = 90  # Tổng điểm >= 90 + kết nối mạng: Isolate mạng

# Điểm cộng cho từng loại bằng chứng
EVIDENCE_SCORES = {
    "REVERSE_SHELL":            50,
    "REFLECTIVE_DLL_INJECTION": 45,
    "INLINE_API_HOOK":          40,
    "PROCESS_HOLLOWING":        45,
    "KNOWN_MALWARE_HASH":       50,
    "KNOWN_MALWARE_NAME":       40,
    "BROWSER_DATA_THEFT":       35,
    "DATA_EXFILTRATION_DETECTED": 35,
    "WMI_EVENT_CONSUMER_MALWARE": 30,
    "SUSPICIOUS_CMDLINE":       20,
    "RWX_MEMORY_REGION":        15,
    "SUSPICIOUS_LOCATION":      15,
    "HIGH_CPU_MINER":           10,
    "SUSPICIOUS_PORT":          10,
}


class ThreatRecord:
    """Lưu trữ toàn bộ bằng chứng và điểm nghi ngờ của một tiến trình"""

    def __init__(self, pid: int, name: str):
        self.pid = pid
        self.name = name
        self.threat_score = 0
        self.evidence = []          # Danh sách bằng chứng thu thập được
        self.first_seen = datetime.now()
        self.last_updated = datetime.now()
        self.action_taken = None    # None / "suspended" / "killed" / "isolated"
        self.network_connections = []
        self.has_valid_signature = None  # True/False/None (chưa kiểm tra)

    def add_evidence(self, alert_type: str, message: str):
        score = EVIDENCE_SCORES.get(alert_type, 5)
        self.threat_score += score
        self.evidence.append({
            "type": alert_type,
            "score": score,
            "detail": message,
            "timestamp": datetime.now().isoformat()
        })
        self.last_updated = datetime.now()


class ThreatResponseEngine:
    """
    Engine phản ứng tự động: Thu thập bằng chứng -> Tính điểm nghi ngờ ->
    Xác minh an toàn -> Ra tay cách ly / Kill
    """

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False

        # Bảng theo dõi: pid -> ThreatRecord
        self.threat_records: dict[int, ThreatRecord] = {}
        self.lock = threading.Lock()

        # Các pid đã bị xử lý (tránh xử lý lại)
        self.actioned_pids: Set[int] = set()

        self.stats = {
            "total_tracked": 0,
            "suspended": 0,
            "killed": 0,
            "isolated": 0,
            "false_positive_avoided": 0,
        }

    # ──────────────────────────────────────────
    #  BƯỚC 1: NHẬN CẢNH BÁO TỪ CÁC MODULE KHÁC
    # ──────────────────────────────────────────
    def ingest_alert(self, alert: dict):
        """
        Được gọi mỗi khi có cảnh báo từ bất kỳ module nào.
        Tích lũy bằng chứng và tính điểm cho tiến trình liên quan.
        """
        alert_type = alert.get("type", "")
        proc_info  = alert.get("process", {}) or alert.get("connection", {})
        pid        = proc_info.get("pid") or alert.get("pid")
        pname      = proc_info.get("name", "unknown")

        if not pid:
            return  # Không có PID thì không thể hành động

        with self.lock:
            if pid not in self.threat_records:
                self.threat_records[pid] = ThreatRecord(pid, pname)
                self.stats["total_tracked"] += 1

            record = self.threat_records[pid]
            record.add_evidence(alert_type, alert.get("message", ""))

        # Gọi pipeline xác minh và hành động (trong thread riêng để không block)
        threading.Thread(
            target=self._run_response_pipeline,
            args=(pid,),
            daemon=True
        ).start()

    # ──────────────────────────────────────────
    #  BƯỚC 2: PIPELINE XÁC MINH VÀ PHẢN ỨNG
    # ──────────────────────────────────────────
    def _run_response_pipeline(self, pid: int):
        """Pipeline 3 bước: Thu thập -> Xác minh -> Hành động"""
        time.sleep(2)  # Đợi 2s để thu thập thêm bằng chứng từ các module khác

        with self.lock:
            record = self.threat_records.get(pid)
            if not record or pid in self.actioned_pids:
                return
            score = record.threat_score
            name  = record.name

        if score < SUSPEND_THREAT_SCORE_MIN:
            return  # Điểm chưa đủ, tiếp tục theo dõi

        # ── Vòng bảo vệ 1: Không bao giờ Kill process được bảo vệ ──
        if name.lower() in PROTECTED_PROCESSES:
            self.stats["false_positive_avoided"] += 1
            self.logger.warning(f"[ThreatResponse] Blocked action on PROTECTED process: {name} (PID {pid})")
            return

        # ── Vòng bảo vệ 2: Kiểm tra chữ ký số ──
        sig_valid = self._check_digital_signature(pid)
        with self.lock:
            if pid in self.threat_records:
                self.threat_records[pid].has_valid_signature = sig_valid

        if sig_valid:
            # Phần mềm có chữ ký số hợp lệ -> Giảm 30 điểm, rất có thể là False Positive
            with self.lock:
                if pid in self.threat_records:
                    self.threat_records[pid].threat_score = max(0, score - 30)
                    score = self.threat_records[pid].threat_score
            self.stats["false_positive_avoided"] += 1
            self.logger.info(f"[ThreatResponse] {name} has valid signature, score reduced to {score}")
            if score < SUSPEND_THREAT_SCORE_MIN:
                return

        # ── Vòng bảo vệ 3: Kiểm tra process còn tồn tại không ──
        try:
            proc = psutil.Process(pid)
            if not proc.is_running():
                return
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        # ── Ra tay! ──
        with self.lock:
            self.actioned_pids.add(pid)

        if score >= ISOLATE_THRESHOLD:
            self._action_isolate(pid, name, score)
        elif score >= KILL_THREAT_SCORE_MIN:
            self._action_kill(pid, name, score)
        else:
            self._action_suspend(pid, name, score)

    # ──────────────────────────────────────────
    #  KIỂM TRA CHỮ KÝ SỐ (Digital Signature)
    # ──────────────────────────────────────────
    def _check_digital_signature(self, pid: int) -> bool:
        """Dùng PowerShell Get-AuthenticodeSignature để kiểm tra"""
        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            if not exe_path:
                return False

            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive",
                    "-Command",
                    f"(Get-AuthenticodeSignature '{exe_path}').Status"
                ],
                capture_output=True, text=True, timeout=5
            )
            status = result.stdout.strip()
            # Valid = có chữ ký hợp lệ, NotSigned/HashMismatch = đáng ngờ
            return status == "Valid"
        except Exception:
            return False

    # ──────────────────────────────────────────
    #  CÁC HÀNH ĐỘNG
    # ──────────────────────────────────────────
    def _action_suspend(self, pid: int, name: str, score: int):
        """LEVEL 1: Tạm treo tiến trình để phân tích thêm"""
        try:
            proc = psutil.Process(pid)
            proc.suspend()

            with self.lock:
                if pid in self.threat_records:
                    self.threat_records[pid].action_taken = "suspended"
            self.stats["suspended"] += 1

            self.alert_callback({
                "module": "ThreatResponse",
                "severity": "CRITICAL",
                "type": "PROCESS_SUSPENDED",
                "message": f"⏸️ TỰ ĐỘNG TREO TIẾN TRÌNH!\n"
                           f"Tiến trình '{name}' (PID {pid}) đã bị tạm treo để phân tích.\n"
                           f"Điểm nguy hiểm: {score}/100\n"
                           f"Hệ thống đang thu thập thêm bằng chứng trước khi quyết định Kill."
            })
        except Exception as e:
            self.logger.error(f"[ThreatResponse] Suspend failed for {name}: {e}")

    def _action_kill(self, pid: int, name: str, score: int):
        """LEVEL 2: Kết thúc tiến trình độc hại"""
        try:
            # Ghi log bằng chứng trước khi kill
            self._save_evidence_report(pid)

            proc = psutil.Process(pid)
            proc.kill()

            with self.lock:
                if pid in self.threat_records:
                    self.threat_records[pid].action_taken = "killed"
            self.stats["killed"] += 1

            self.alert_callback({
                "module": "ThreatResponse",
                "severity": "CRITICAL",
                "type": "PROCESS_KILLED",
                "message": f"💀 ĐÃ TIÊU DIỆT TIẾN TRÌNH ĐỘC HẠI!\n"
                           f"Tiến trình '{name}' (PID {pid}) đã bị chấm dứt.\n"
                           f"Điểm nguy hiểm: {score}/100\n"
                           f"Bằng chứng đã được lưu vào logs."
            })
        except Exception as e:
            self.logger.error(f"[ThreatResponse] Kill failed for {name}: {e}")

    def _action_isolate(self, pid: int, name: str, score: int):
        """LEVEL 3: Chặn mạng bằng Windows Firewall + Kill"""
        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()

            # Chặn mạng bằng Windows Firewall (yêu cầu admin)
            if exe_path and self.is_admin:
                fw_rule_name = f"SecurityMonitor_Block_{name}_{pid}"
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={fw_rule_name}",
                    "dir=out", "action=block",
                    f"program={exe_path}"
                ], capture_output=True, timeout=5)

            # Sau đó Kill
            self._action_kill(pid, name, score)

            with self.lock:
                if pid in self.threat_records:
                    self.threat_records[pid].action_taken = "isolated"
            self.stats["isolated"] += 1

            self.alert_callback({
                "module": "ThreatResponse",
                "severity": "CRITICAL",
                "type": "PROCESS_ISOLATED",
                "message": f"🔒 ĐÃ CÁCH LY VÀ TIÊU DIỆT HOÀN TOÀN!\n"
                           f"'{name}' (PID {pid}) đã bị:\n"
                           f"  • Chặn mạng bằng Windows Firewall\n"
                           f"  • Chấm dứt tiến trình\n"
                           f"Điểm nguy hiểm: {score}/100 (mức nguy hiểm cao nhất)"
            })
        except Exception as e:
            self.logger.error(f"[ThreatResponse] Isolate failed for {name}: {e}")

    def _save_evidence_report(self, pid: int):
        """Lưu toàn bộ bằng chứng ra file trước khi Kill"""
        try:
            from pathlib import Path
            import json

            record = self.threat_records.get(pid)
            if not record:
                return

            report_dir = Path(__file__).parent.parent / "logs" / "evidence"
            report_dir.mkdir(parents=True, exist_ok=True)

            report_path = report_dir / f"evidence_{record.name}_{pid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump({
                    "pid": record.pid,
                    "name": record.name,
                    "threat_score": record.threat_score,
                    "has_valid_signature": record.has_valid_signature,
                    "first_seen": record.first_seen.isoformat(),
                    "action_taken": record.action_taken,
                    "evidence": record.evidence,
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def get_watchlist(self) -> list:
        """Trả về danh sách tiến trình đang bị theo dõi (cho dashboard)"""
        with self.lock:
            result = []
            for pid, rec in self.threat_records.items():
                result.append({
                    "pid": pid,
                    "name": rec.name,
                    "score": rec.threat_score,
                    "action": rec.action_taken or "watching",
                    "evidence_count": len(rec.evidence),
                    "signature": rec.has_valid_signature,
                })
            return sorted(result, key=lambda x: x["score"], reverse=True)[:15]

    def cleanup_old_records(self):
        """Xóa các record cũ (process đã chết) khỏi bảng theo dõi"""
        with self.lock:
            dead = [pid for pid in self.threat_records if not psutil.pid_exists(pid)]
            for pid in dead:
                del self.threat_records[pid]
                self.actioned_pids.discard(pid)

    def start(self):
        self.running = True
        self.logger.info("ThreatResponseEngine started")
        while self.running:
            try:
                self.cleanup_old_records()
                time.sleep(30)
            except Exception as e:
                self.logger.error(f"ThreatResponse error: {e}")
                time.sleep(10)

    def stop(self):
        self.running = False
