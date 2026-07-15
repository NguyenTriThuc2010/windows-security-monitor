"""
Deep File Scanner - Phân tích nội dung tài liệu để tìm mã độc nhúng bên trong.

Hỗ trợ:
  - Office (docx/xlsx/pptx/doc/xls): Quét Macro VBA độc hại qua oletools
  - PDF: Tìm JavaScript nhúng, /Launch, /OpenAction, shellcode ẩn
  - PE (exe/dll): Phân tích cấu trúc, tìm obfuscated payload
  - Phát hiện file "giả mạo" loại (extension không khớp với nội dung thật)
"""

import os
import re
import time
import hashlib
import struct
import threading
from pathlib import Path
from datetime import datetime
from typing import Callable, Set

# ── Thư viện tùy chọn ──────────────────────────────────
try:
    from oletools.olevba import VBA_Parser
    HAS_OLETOOLS = True
except ImportError:
    HAS_OLETOOLS = False

try:
    import fitz  # PyMuPDF
    HAS_PYMUPDF = True
except ImportError:
    HAS_PYMUPDF = False

# ────────────────────────────────────────────────────────

# Thư mục cần quét khi có file mới xuất hiện
WATCH_DIRS = [
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
    os.environ.get("TEMP", ""),
]

# Extension kích hoạt quét sâu
OFFICE_EXTENSIONS  = {".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".docm", ".xlsm"}
PDF_EXTENSIONS     = {".pdf"}
PE_EXTENSIONS      = {".exe", ".dll", ".scr", ".com", ".pif"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}
ALL_SCAN_EXTENSIONS = OFFICE_EXTENSIONS | PDF_EXTENSIONS | PE_EXTENSIONS | ARCHIVE_EXTENSIONS

# ── Chữ ký "Magic Bytes" để kiểm tra loại file thật ────
MAGIC_SIGNATURES = {
    b"\x4D\x5A":                     "PE Executable",    # MZ
    b"\x50\x4B\x03\x04":            "ZIP/Office",        # PK (OOXML = zip)
    b"\xD0\xCF\x11\xE0":            "OLE Compound",      # DOC/XLS cũ
    b"\x25\x50\x44\x46":            "PDF",               # %PDF
    b"\x52\x61\x72\x21":            "RAR Archive",       # Rar!
    b"\x37\x7A\xBC\xAF":            "7-Zip Archive",
    b"\x1F\x8B":                    "GZIP",
}

# Pattern VBA/Macro độc hại (regex)
MALICIOUS_VBA_PATTERNS = [
    (r"Shell\s*\(",                          "Shell() - Thực thi lệnh hệ thống"),
    (r"CreateObject\s*\(.{0,50}WScript",     "WScript CreateObject"),
    (r"CreateObject\s*\(.{0,50}MSXML",       "MSXML Download từ internet"),
    (r"CreateObject\s*\(.{0,50}Scripting",   "Scripting.FileSystemObject"),
    (r"PowerShell",                          "Gọi PowerShell từ Macro"),
    (r"cmd\.exe",                            "Gọi CMD từ Macro"),
    (r"AutoOpen|AutoClose|Document_Open",    "Macro tự động chạy khi mở file"),
    (r"environ\s*\(",                        "Đọc biến môi trường (dấu hiệu evasion)"),
    (r"Chr\(\d+\)\s*&",                      "Chr() obfuscation - code bị mã hóa"),
    (r"[A-Za-z0-9+/]{60,}={0,2}",           "Base64 string dài - payload bị mã hóa"),
    (r"Hex\(",                               "Hex encoding - obfuscated code"),
    (r"StrReverse\s*\(",                     "StrReverse obfuscation"),
]

# Pattern nguy hiểm trong PDF
MALICIOUS_PDF_PATTERNS = [
    "/JavaScript",          # JS nhúng trong PDF
    "/JS",                  # JS nhúng (dạng ngắn)
    "/Launch",              # Kích hoạt ứng dụng ngoài khi mở PDF
    "/OpenAction",          # Chạy action tự động khi mở
    "/AA",                  # Additional Actions
    "/SubmitForm",          # Gửi dữ liệu form ra ngoài
    "/GoToR",               # Remote GoTo (có thể chạy file ngoài)
    "/URI",                 # Chứa link
    "/EmbeddedFile",        # File nhúng bên trong PDF
    "/XFA",                 # XFA form (thường dùng trong tấn công phức tạp)
    "powershell",           # Gọi PowerShell từ PDF action
    "cmd.exe",
    "wscript",
    "mshta",
]

# Heuristic: Tỷ lệ ký tự lạ cao trong code -> Có thể là shellcode/obfuscated
ENTROPY_THRESHOLD = 7.0  # bits/byte (>7.0 = rất ngẫu nhiên, dấu hiệu mã hóa)


def calculate_entropy(data: bytes) -> float:
    """Tính entropy Shannon của dữ liệu (phát hiện shellcode hoặc mã hóa)"""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    total = len(data)
    import math
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def get_real_file_type(filepath: str) -> str:
    """Đọc Magic Bytes để xác định loại file thật (bất kể extension)"""
    try:
        with open(filepath, "rb") as f:
            header = f.read(8)
        for magic, ftype in MAGIC_SIGNATURES.items():
            if header[:len(magic)] == magic:
                return ftype
    except Exception:
        pass
    return "Unknown"


def get_file_hash(filepath: str) -> str:
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


class DeepFileScanner:
    """Phân tích nội dung tài liệu tìm mã độc ẩn bên trong"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scanned_files: Set[str] = set()  # Cache tránh quét lại
        self.scan_interval = 5  # giây - liên tục theo dõi Downloads
        self.stats = {
            "files_scanned": 0,
            "malicious_found": 0,
            "office_scanned": 0,
            "pdf_scanned": 0,
            "pe_scanned": 0,
            "last_scan": None,
        }

    # ── KIỂM TRA GIẢ MẠO LOẠI FILE ─────────────────────
    def check_extension_mismatch(self, filepath: str) -> list:
        """
        Phát hiện file giả mạo: ví dụ file .pdf thực chất là .exe
        Đây là kỹ thuật phổ biến: đổi tên invoice.pdf.exe thành invoice.pdf
        """
        flags = []
        ext = Path(filepath).suffix.lower()
        real_type = get_real_file_type(filepath)

        # PDF giả là exe
        if ext == ".pdf" and real_type == "PE Executable":
            flags.append({
                "severity": "CRITICAL",
                "type": "FILE_TYPE_MISMATCH",
                "detail": f"FILE GIẢ MẠO! File có tên '{Path(filepath).name}' mang extension .pdf\n"
                          f"nhưng nội dung thật là FILE THỰC THI WINDOWS (PE Executable).\n"
                          f"Đây là kỹ thuật đánh lừa người dùng phổ biến nhất của mã độc!"
            })

        # Office file (docx) nhưng thật ra là PE
        if ext in OFFICE_EXTENSIONS and real_type == "PE Executable":
            flags.append({
                "severity": "CRITICAL",
                "type": "FILE_TYPE_MISMATCH",
                "detail": f"FILE GIẢ MẠO! '{Path(filepath).name}' trông như tài liệu Office\n"
                          f"nhưng thực chất là FILE THỰC THI WINDOWS (exe/dll)."
            })

        return flags

    # ── PHÂN TÍCH OFFICE (VBA MACRO) ────────────────────
    def scan_office_document(self, filepath: str) -> list:
        """Quét Macro VBA độc hại trong file Office"""
        flags = []
        if not HAS_OLETOOLS:
            return flags

        self.stats["office_scanned"] += 1
        try:
            vba_parser = VBA_Parser(filepath)

            if not vba_parser.detect_vba_macros():
                return flags  # Không có macro = sạch

            # Có macro! Đọc nội dung VBA code
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                if not vba_code:
                    continue

                found_patterns = []
                for pattern, description in MALICIOUS_VBA_PATTERNS:
                    if re.search(pattern, vba_code, re.IGNORECASE):
                        found_patterns.append(description)

                # Kiểm tra entropy của code (phát hiện obfuscation)
                entropy = calculate_entropy(vba_code.encode("utf-8", errors="ignore"))

                if found_patterns or entropy > ENTROPY_THRESHOLD:
                    severity = "CRITICAL" if len(found_patterns) >= 2 else "HIGH"
                    detail_lines = [
                        f"MACRO VIRUS DETECTED trong: {Path(filepath).name}",
                        f"VBA Stream: {vba_filename}",
                    ]
                    if found_patterns:
                        detail_lines.append(f"Dau hieu nguy hiem: {', '.join(found_patterns)}")
                    if entropy > ENTROPY_THRESHOLD:
                        detail_lines.append(
                            f"Code entropy cao ({entropy:.2f} bits/byte) - "
                            f"Code bị mã hóa/obfuscate để trốn tránh phát hiện!"
                        )
                    flags.append({
                        "severity": severity,
                        "type": "MALICIOUS_MACRO",
                        "detail": "\n".join(detail_lines)
                    })

            vba_parser.close()

        except Exception as e:
            self.logger.warning(f"[DeepScan] Office scan error on {filepath}: {e}")

        return flags

    # ── PHÂN TÍCH PDF ────────────────────────────────────
    def scan_pdf_file(self, filepath: str) -> list:
        """Tìm JavaScript, /Launch action và payload ẩn trong PDF"""
        flags = []
        if not HAS_PYMUPDF:
            return flags

        self.stats["pdf_scanned"] += 1
        try:
            # Đọc raw bytes để tìm pattern nguy hiểm
            with open(filepath, "rb") as f:
                raw_content = f.read()

            raw_text = raw_content.decode("latin-1", errors="ignore")

            found_patterns = []
            for pattern in MALICIOUS_PDF_PATTERNS:
                if pattern.lower() in raw_text.lower():
                    found_patterns.append(pattern)

            if found_patterns:
                severity = "CRITICAL" if "/JavaScript" in found_patterns or "/Launch" in found_patterns else "HIGH"
                flags.append({
                    "severity": severity,
                    "type": "MALICIOUS_PDF",
                    "detail": f"PDF ĐỘC HẠI: File '{Path(filepath).name}' chứa các thành phần nguy hiểm!\n"
                              f"Phát hiện: {', '.join(found_patterns)}\n"
                              f"Mô tả: PDF chứa code JavaScript, Launch action có thể tự động tải\n"
                              f"       và chạy phần mềm độc hại khi bạn mở file này trong Acrobat Reader."
                })

            # Kiểm tra entropy từng trang (phát hiện payload ẩn)
            try:
                doc = fitz.open(filepath)
                for page_num, page in enumerate(doc):
                    text = page.get_text("rawdict")
                    raw_bytes = str(text).encode("utf-8", errors="ignore")
                    if len(raw_bytes) > 100:
                        entropy = calculate_entropy(raw_bytes)
                        if entropy > ENTROPY_THRESHOLD:
                            flags.append({
                                "severity": "MEDIUM",
                                "type": "PDF_HIGH_ENTROPY",
                                "detail": f"PDF '{Path(filepath).name}' trang {page_num+1} có entropy rất cao\n"
                                          f"({entropy:.2f} bits/byte). Có thể chứa dữ liệu bị mã hóa ẩn."
                            })
                doc.close()
            except Exception:
                pass

        except Exception as e:
            self.logger.warning(f"[DeepScan] PDF scan error on {filepath}: {e}")

        return flags

    # ── PHÂN TÍCH PE (EXE/DLL) ──────────────────────────
    def scan_pe_file(self, filepath: str) -> list:
        """Phân tích cấu trúc PE để tìm shellcode và packed malware"""
        flags = []
        self.stats["pe_scanned"] += 1

        try:
            with open(filepath, "rb") as f:
                data = f.read()

            # Kiểm tra MZ header
            if not data.startswith(b"MZ"):
                return flags

            # Tính entropy toàn bộ file
            entropy = calculate_entropy(data)

            if entropy > 7.2:
                flags.append({
                    "severity": "HIGH",
                    "type": "PACKED_EXECUTABLE",
                    "detail": f"File thực thi '{Path(filepath).name}' có entropy cực cao ({entropy:.2f}).\n"
                              f"Đây là dấu hiệu chắc chắn của Packer/Crypter - mã độc thường bị đóng gói\n"
                              f"bằng UPX, MPRESS hoặc custom crypter để trốn tránh phần mềm diệt virus.\n"
                              f"Nguy cơ: Cao"
                })

            # Tìm chuỗi đáng ngờ trong PE
            suspicious_strings = [
                b"IsDebuggerPresent",   # Kiểm tra có đang chạy trong debugger không
                b"VirtualAlloc",       # Cấp phát RAM thực thi
                b"WriteProcessMemory", # Ghi vào RAM tiến trình khác
                b"CreateRemoteThread", # Tạo thread trong tiến trình khác (injection)
                b"SetWindowsHookEx",   # Cài keylogger hook
                b"GetAsyncKeyState",   # Đọc trạng thái phím (keylogger)
                b"HttpSendRequest",    # Gửi HTTP request (C2 communication)
                b"InternetOpenUrl",    # Mở URL (download payload)
                b"CryptEncrypt",       # Mã hóa dữ liệu (ransomware)
                b"FindFirstFile",      # Duyệt file (ransomware tìm file để mã hóa)
            ]

            found_imports = []
            for s in suspicious_strings:
                if s in data:
                    found_imports.append(s.decode("ascii"))

            if len(found_imports) >= 3:
                flags.append({
                    "severity": "HIGH",
                    "type": "SUSPICIOUS_PE_IMPORTS",
                    "detail": f"File thực thi '{Path(filepath).name}' import nhiều API nguy hiểm:\n"
                              f"{', '.join(found_imports)}\n"
                              f"Kết hợp các API này gợi ý khả năng: Process Injection, Keylogger, hoặc Ransomware."
                })

        except Exception as e:
            self.logger.warning(f"[DeepScan] PE scan error on {filepath}: {e}")

        return flags

    # ── MAIN SCAN ────────────────────────────────────────
    def scan_file(self, filepath: str):
        """Quét toàn diện một file"""
        if not os.path.isfile(filepath):
            return

        ext = Path(filepath).suffix.lower()
        if ext not in ALL_SCAN_EXTENSIONS:
            return

        cache_key = f"{filepath}:{os.path.getmtime(filepath)}"
        if cache_key in self.scanned_files:
            return
        self.scanned_files.add(cache_key)

        self.stats["files_scanned"] += 1
        file_hash = get_file_hash(filepath)
        all_flags = []

        # Vòng 1: Kiểm tra giả mạo extension
        all_flags.extend(self.check_extension_mismatch(filepath))

        # Vòng 2: Phân tích nội dung theo loại
        if ext in OFFICE_EXTENSIONS:
            all_flags.extend(self.scan_office_document(filepath))
        elif ext in PDF_EXTENSIONS:
            all_flags.extend(self.scan_pdf_file(filepath))
        elif ext in PE_EXTENSIONS:
            all_flags.extend(self.scan_pe_file(filepath))

        # Phát cảnh báo
        for flag in all_flags:
            self.stats["malicious_found"] += 1
            self.alert_callback({
                "module": "DeepFileScanner",
                "severity": flag.get("severity", "HIGH"),
                "type": flag["type"],
                "message": flag["detail"],
                "file": filepath,
                "sha256": file_hash,
                "process": {"pid": None, "name": "FileScanner"}
            })

        self.stats["last_scan"] = datetime.now().isoformat()

    def scan_watch_dirs(self):
        """Quét tất cả file mới trong thư mục giám sát"""
        current_time = time.time()
        for watch_dir in WATCH_DIRS:
            if not watch_dir or not os.path.isdir(watch_dir):
                continue
            try:
                for fname in os.listdir(watch_dir):
                    fpath = os.path.join(watch_dir, fname)
                    if not os.path.isfile(fpath):
                        continue
                    # Chỉ quét file được tạo/sửa trong 5 phút qua
                    if current_time - os.path.getmtime(fpath) < 300:
                        self.scan_file(fpath)
            except Exception:
                continue

    def start(self):
        self.running = True
        self.logger.info(f"DeepFileScanner started (oletools={HAS_OLETOOLS}, pymupdf={HAS_PYMUPDF})")

        while self.running:
            try:
                self.scan_watch_dirs()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"DeepFileScanner error: {e}")
                time.sleep(10)

    def stop(self):
        self.running = False
