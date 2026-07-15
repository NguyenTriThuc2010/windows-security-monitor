"""
Permanent Block Engine
Chặn và xóa mã độc vĩnh viễn bằng các cơ chế Windows tích hợp sẵn,
hoạt động kể cả khi Security Monitor KHÔNG chạy:

  1. Windows Firewall Rule   - Chặn mạng in/out vĩnh viễn
  2. Software Restriction Policy (SRP) - Chặn thực thi qua Registry
  3. Windows Defender Block  - Thêm vào danh sách đe dọa của Defender
  4. Startup Removal         - Xóa khỏi tất cả vị trí khởi động
  5. File Deletion / Quarantine - Xóa hoặc cách ly file

Tất cả đều ghi vào Windows Registry / System config nên
TỒN TẠI vĩnh viễn qua mọi lần khởi động lại máy.
"""

import os
import shutil
import subprocess
import winreg
import psutil
from pathlib import Path
from datetime import datetime
from typing import Optional

# Thư mục cách ly (Quarantine)
QUARANTINE_DIR = Path(__file__).parent.parent / "quarantine"

# Registry path cho Software Restriction Policy
SRP_BASE = r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths"

# Log file
BLOCK_LOG = Path(__file__).parent.parent / "logs" / "permanent_blocks.log"


def _log(msg: str):
    """Ghi log thao tác chặn vĩnh viễn"""
    try:
        BLOCK_LOG.parent.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(BLOCK_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────
#  1. WINDOWS FIREWALL - Chặn mạng vĩnh viễn
# ─────────────────────────────────────────────────────────
def block_network_permanent(exe_path: str, process_name: str) -> tuple[bool, str]:
    """
    Tạo Windows Firewall rule chặn INBOUND + OUTBOUND vĩnh viễn.
    Rule tồn tại qua mọi lần reboot dù không chạy Security Monitor.
    """
    rule_name = f"[SecurityMonitor] BLOCK {process_name}"
    results = []
    success = True

    for direction in ["in", "out"]:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name} ({direction})",
            f"dir={direction}", "action=block",
            f"program={exe_path}",
            "enable=yes", "profile=any"
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                results.append(f"  ✅ Firewall {direction.upper()}: Chặn thành công")
            else:
                results.append(f"  ⚠️  Firewall {direction.upper()}: {r.stderr.strip()[:80]}")
                success = False
        except Exception as e:
            results.append(f"  ❌ Firewall {direction.upper()} lỗi: {e}")
            success = False

    msg = "\n".join(results)
    _log(f"FIREWALL BLOCK [{process_name}] {exe_path}: {'OK' if success else 'FAILED'}")
    return success, msg


# ─────────────────────────────────────────────────────────
#  2. SOFTWARE RESTRICTION POLICY - Chặn thực thi vĩnh viễn
# ─────────────────────────────────────────────────────────
def block_execution_srp(exe_path: str, process_name: str) -> tuple[bool, str]:
    """
    Ghi vào Registry Software Restriction Policy để Windows từ chối
    thực thi file này vĩnh viễn — kể cả khi double-click hay chạy từ CMD.
    """
    try:
        # Tạo key SRP nếu chưa có
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, SRP_BASE,
                0, winreg.KEY_ALL_ACCESS
            )
        except FileNotFoundError:
            # Tạo toàn bộ cây key
            winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE, SRP_BASE,
                0, winreg.KEY_ALL_ACCESS
            )
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, SRP_BASE,
                0, winreg.KEY_ALL_ACCESS
            )

        # Tạo subkey cho file này (dùng hash path làm tên unique)
        import hashlib
        key_name = hashlib.md5(exe_path.lower().encode()).hexdigest()[:16]
        sub_key = winreg.CreateKeyEx(key, key_name, 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(sub_key, "Description",     0, winreg.REG_SZ,    f"[SecurityMonitor] Blocked: {process_name}")
        winreg.SetValueEx(sub_key, "ItemData",        0, winreg.REG_EXPAND_SZ, exe_path)
        winreg.SetValueEx(sub_key, "SaferFlags",      0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(sub_key, "LastModified",    0, winreg.REG_BINARY, b'\x00' * 16)
        winreg.CloseKey(sub_key)
        winreg.CloseKey(key)

        _log(f"SRP BLOCK [{process_name}] {exe_path}: OK (key={key_name})")
        return True, f"  ✅ SRP: Đã chặn thực thi vĩnh viễn qua Registry\n     Key: HKLM\\{SRP_BASE}\\{key_name}"

    except PermissionError:
        return False, "  ⚠️  SRP: Cần quyền Administrator để ghi Registry"
    except Exception as e:
        return False, f"  ❌ SRP lỗi: {e}"


# ─────────────────────────────────────────────────────────
#  3. WINDOWS DEFENDER - Báo cáo và yêu cầu quét
# ─────────────────────────────────────────────────────────
def report_to_defender(exe_path: str) -> tuple[bool, str]:
    """Yêu cầu Windows Defender quét ngay file này"""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-Command", f"Start-MpScan -ScanType CustomScan -ScanPath '{exe_path}'"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0:
            _log(f"DEFENDER SCAN {exe_path}: OK")
            return True, "  ✅ Defender: Đã yêu cầu quét file này"
        return False, f"  ⚠️  Defender: {r.stderr.strip()[:100]}"
    except Exception as e:
        return False, f"  ❌ Defender lỗi: {e}"


# ─────────────────────────────────────────────────────────
#  4. STARTUP REMOVAL - Xóa khỏi mọi vị trí khởi động
# ─────────────────────────────────────────────────────────
def remove_from_startup(process_name: str, exe_path: str) -> tuple[bool, str]:
    """Xóa mọi dấu vết của process khỏi các vị trí khởi động Windows"""
    removed = []
    exe_lower = exe_path.lower()

    startup_reg_keys = [
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    for hive, path in startup_reg_keys:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
            i = 0
            to_delete = []
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                    if exe_lower in str(val).lower() or process_name.lower() in str(val).lower():
                        to_delete.append(name)
                    i += 1
                except OSError:
                    break
            for name in to_delete:
                winreg.DeleteValue(key, name)
                removed.append(f"    Đã xóa startup key: {name}")
                _log(f"STARTUP REMOVE [{name}] from {path}")
            winreg.CloseKey(key)
        except Exception:
            pass

    # Xóa khỏi Task Scheduler
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"Get-ScheduledTask | Where-Object {{$_.Actions.Execute -like '*{process_name}*'}} | Unregister-ScheduledTask -Confirm:$false"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            removed.append("    Đã xóa Scheduled Task liên quan")
    except Exception:
        pass

    if removed:
        return True, "  ✅ Startup: Đã xóa khỏi vị trí khởi động:\n" + "\n".join(removed)
    return True, "  ℹ️  Startup: Không tìm thấy trong vị trí khởi động"


# ─────────────────────────────────────────────────────────
#  5. XÓA FILE VĨNH VIỄN
# ─────────────────────────────────────────────────────────
def delete_file_permanent(exe_path: str) -> tuple[bool, str]:
    """Xóa vĩnh viễn file khỏi đĩa (không vào Recycle Bin)"""
    try:
        path = Path(exe_path)
        if not path.exists():
            return False, f"  ⚠️  File không tồn tại: {exe_path}"

        # Kill process đang chạy trước nếu có
        for proc in psutil.process_iter(['pid', 'exe']):
            try:
                if proc.info['exe'] and Path(proc.info['exe']).resolve() == path.resolve():
                    proc.kill()
            except Exception:
                pass

        # Xóa file
        os.remove(exe_path)
        _log(f"DELETE {exe_path}: OK")
        return True, f"  ✅ Đã XÓA VĨNH VIỄN: {exe_path}"
    except PermissionError:
        # Thử dùng cmd /c del để bypass lock
        try:
            subprocess.run(["cmd", "/c", "del", "/f", "/q", exe_path],
                           capture_output=True, timeout=5)
            _log(f"DELETE (force) {exe_path}: OK")
            return True, f"  ✅ Đã XÓA (force): {exe_path}"
        except Exception as e2:
            return False, f"  ❌ Không thể xóa (file bị khóa): {e2}"
    except Exception as e:
        return False, f"  ❌ Lỗi xóa file: {e}"


# ─────────────────────────────────────────────────────────
#  5b. CÁCH LY FILE (Quarantine - an toàn hơn xóa)
# ─────────────────────────────────────────────────────────
def quarantine_file(exe_path: str, process_name: str) -> tuple[bool, str]:
    """Di chuyển file vào thư mục cách ly (quarantine) bảo mật"""
    try:
        QUARANTINE_DIR.mkdir(exist_ok=True)
        path = Path(exe_path)
        if not path.exists():
            return False, f"  ⚠️  File không tồn tại: {exe_path}"

        # Kill process trước
        for proc in psutil.process_iter(['pid', 'exe']):
            try:
                if proc.info['exe'] and Path(proc.info['exe']).resolve() == path.resolve():
                    proc.kill()
            except Exception:
                pass

        # Di chuyển vào quarantine với timestamp
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = QUARANTINE_DIR / f"{ts}_{process_name}"
        shutil.move(exe_path, dest)

        # Ghi metadata
        meta = dest.with_suffix(".meta.txt")
        meta.write_text(
            f"Original: {exe_path}\nProcess: {process_name}\nQuarantined: {datetime.now()}\n",
            encoding="utf-8"
        )
        _log(f"QUARANTINE {exe_path} -> {dest}: OK")
        return True, f"  ✅ Đã CÁCH LY tại: {dest}"
    except Exception as e:
        return False, f"  ❌ Lỗi cách ly: {e}"


# ─────────────────────────────────────────────────────────
#  MAIN: Chặn toàn diện (gọi tất cả các bước)
# ─────────────────────────────────────────────────────────
def block_permanently(exe_path: str, process_name: str, pid: Optional[int] = None,
                      delete_file: bool = False) -> str:
    """
    Thực hiện chặn toàn diện và vĩnh viễn một mã độc:
    1. Kill process đang chạy
    2. Chặn mạng vĩnh viễn (Firewall)
    3. Chặn thực thi vĩnh viễn (SRP Registry)
    4. Xóa khỏi Startup
    5. Báo Defender quét
    6. Xóa hoặc cách ly file
    """
    lines = [
        f"⛔ KẾT QUẢ CHẶN VĨNH VIỄN",
        f"{'═' * 55}",
        f"File: {exe_path}",
        f"Process: {process_name}",
        f"Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"{'─' * 55}",
    ]

    # Bước 0: Kill process ngay
    if pid:
        try:
            p = psutil.Process(int(pid))
            p.kill()
            lines.append(f"  ✅ Kill: Đã dừng process (PID {pid})")
        except Exception as e:
            lines.append(f"  ⚠️  Kill: {e}")
    lines.append("")

    # Bước 1: Firewall
    lines.append("🔒 Chặn mạng (Windows Firewall):")
    ok, msg = block_network_permanent(exe_path, process_name)
    lines.append(msg)

    # Bước 2: SRP
    lines.append("\n🚫 Chặn thực thi (Software Restriction Policy):")
    ok2, msg2 = block_execution_srp(exe_path, process_name)
    lines.append(msg2)

    # Bước 3: Startup
    lines.append("\n🚀 Xóa khỏi khởi động:")
    ok3, msg3 = remove_from_startup(process_name, exe_path)
    lines.append(msg3)

    # Bước 4: Defender
    lines.append("\n🛡️  Windows Defender:")
    ok4, msg4 = report_to_defender(exe_path)
    lines.append(msg4)

    # Bước 5: Xóa hoặc cách ly
    lines.append("\n🗑️  Xử lý file:")
    if delete_file:
        ok5, msg5 = delete_file_permanent(exe_path)
    else:
        ok5, msg5 = quarantine_file(exe_path, process_name)
    lines.append(msg5)

    lines.append(f"\n{'═' * 55}")
    lines.append("✅ Hoàn tất! Các biện pháp chặn đã được ghi vào hệ thống")
    lines.append("và SẼ TỒN TẠI kể cả khi khởi động lại máy.")

    result = "\n".join(lines)
    _log(f"FULL BLOCK COMPLETE: {process_name} @ {exe_path}")
    return result
