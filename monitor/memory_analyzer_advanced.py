"""
Advanced Memory Analyzer - Quét và phân tích trực tiếp RAM
Phát hiện: Process Hollowing, Reflective DLL Injection, Shellcode injection
"""

import ctypes
from ctypes import wintypes
import psutil
import time
from datetime import datetime
from typing import Callable, Set

# Hằng số Windows API
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

# Structs
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

# WinAPI definitions
kernel32 = ctypes.windll.kernel32

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.restype = ctypes.c_size_t
VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.restype = wintypes.BOOL
ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


class MemoryAnalyzerAdvanced:
    """Module phân tích bộ nhớ cấp thấp"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scan_interval = 120  # RAM scan khá nặng, nên scan chậm
        self.alerted_pids = set()
        self.stats = {
            "procs_scanned": 0,
            "rwx_regions_found": 0,
            "injections_detected": 0,
            "last_scan": None
        }

    def _read_memory(self, h_process, address, size):
        """Đọc vùng nhớ của một process khác"""
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        
        if ReadProcessMemory(h_process, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
            return buffer.raw[:bytes_read.value]
        return None

    def scan_process_memory(self, pid: int, proc_name: str):
        """Quét toàn bộ vùng nhớ của một process để tìm mã độc"""
        flags = []
        
        # Mở process với quyền đọc memory
        h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_process:
            return flags

        try:
            sysinfo = wintypes.SYSTEM_INFO()
            kernel32.GetSystemInfo(ctypes.byref(sysinfo))
            
            address = 0
            # max_address = sysinfo.lpMaximumApplicationAddress (Thường để an toàn thì quét đến 0x7FFFFFFF)
            
            mbi = MEMORY_BASIC_INFORMATION()
            
            # Duyệt qua các vùng nhớ (Memory Pages)
            while VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                # Kiểm tra vùng nhớ RWX (Read-Write-Execute)
                # Mã độc thường cấp phát vùng nhớ này để nhúng shellcode (khác với ứng dụng bình thường hiếm khi dùng RWX)
                if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
                    if mbi.Protect == PAGE_EXECUTE_READWRITE:
                        self.stats["rwx_regions_found"] += 1
                        
                        # Cần bỏ qua một số process hợp lệ sử dụng JIT (như trình duyệt web, .NET)
                        legit_jit_procs = ["chrome.exe", "msedge.exe", "firefox.exe", "node.exe", "java.exe"]
                        if proc_name.lower() not in legit_jit_procs:
                            flags.append({
                                "type": "RWX_MEMORY_REGION",
                                "severity": "HIGH",
                                "detail": f"Phát hiện vùng nhớ RWX (Execute-Read-Write) bất thường tại địa chỉ 0x{mbi.BaseAddress:X} có kích thước {mbi.RegionSize} bytes.\nĐây là dấu hiệu đặc trưng của Shellcode/Code Injection."
                            })

                        # Đọc nội dung vùng nhớ để tìm MZ header (Reflective DLL)
                        if mbi.RegionSize > 1024: # Đủ lớn để chứa một PE
                            mem_data = self._read_memory(h_process, mbi.BaseAddress, min(1024, mbi.RegionSize))
                            if mem_data and mem_data.startswith(b'MZ'):
                                flags.append({
                                    "type": "REFLECTIVE_DLL_INJECTION",
                                    "severity": "CRITICAL",
                                    "detail": f"🚨 Phát hiện chữ ký MZ (file thực thi) trong vùng nhớ Private Memory (0x{mbi.BaseAddress:X})!\nĐây là kỹ thuật Reflective DLL Injection (Fileless Malware) - Một DLL được load thẳng vào RAM không qua API của Windows."
                                })

                address += mbi.RegionSize

        except Exception as e:
            pass
        finally:
            CloseHandle(h_process)

        return flags

    def scan_all(self):
        """Quét tất cả process đang chạy"""
        if not self.is_admin:
            self.logger.warning("MemoryAnalyzer requires Administrator privileges. Scan aborted.")
            return

        self.logger.info("Bắt đầu quét sâu vào bộ nhớ (Deep RAM Scan)...")
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                
                # Bỏ qua system idle và system
                if pid <= 4 or not name:
                    continue

                if pid in self.alerted_pids:
                    continue

                self.stats["procs_scanned"] += 1
                
                flags = self.scan_process_memory(pid, name)
                if flags:
                    self.alerted_pids.add(pid)
                    self.stats["injections_detected"] += len(flags)
                    
                    for flag in flags:
                        self.alert_callback({
                            "module": "MemoryAnalyzer",
                            "severity": flag.get("severity", "CRITICAL"),
                            "type": flag["type"],
                            "message": f"Process: '{name}' (PID: {pid})\n{flag['detail']}",
                            "process": {
                                "pid": pid,
                                "name": name
                            }
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                continue

        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        self.running = True
        self.logger.info("MemoryAnalyzerAdvanced started")
        
        while self.running:
            try:
                self.scan_all()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"MemoryAnalyzer error: {e}")
                time.sleep(30)

    def stop(self):
        self.running = False
