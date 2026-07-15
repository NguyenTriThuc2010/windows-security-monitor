"""
API Hook Detector - Phát hiện Inline Hook trong các thư viện hệ thống
Kỹ thuật chuyên sâu để phát hiện các Rootkit tàng hình và User-mode Keyloggers.
"""

import ctypes
from ctypes import wintypes
import psutil
import time
from datetime import datetime
from typing import Callable, Dict

# Định nghĩa các structs và hằng số của Windows API
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

# Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# LoadLibrary và GetProcAddress
LoadLibraryA = kernel32.LoadLibraryA
LoadLibraryA.restype = wintypes.HMODULE
LoadLibraryA.argtypes = [wintypes.LPCSTR]

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = ctypes.c_void_p
GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]

# Các API nhạy cảm thường bị Rootkit/Malware hook để che giấu hành vi
CRITICAL_APIS = {
    "ntdll.dll": [
        "NtQuerySystemInformation",   # Thường bị hook để giấu tiến trình
        "NtReadVirtualMemory",        # Thường bị hook để giấu đọc RAM
        "NtWriteVirtualMemory",       # Hook để theo dõi memory injection
        "NtCreateUserProcess",        # Hook để theo dõi khởi tạo tiến trình
        "NtAllocateVirtualMemory",    # Hook memory allocation
        "NtProtectVirtualMemory",     # Hook thay đổi quyền memory
        "NtResumeThread",             # Hook process hollowing
        "LdrLoadDll"                  # Hook DLL injection
    ],
    "kernel32.dll": [
        "CreateProcessInternalW",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "SetWindowsHookExW"
    ],
    "user32.dll": [
        "SetWindowsHookExW",
        "SetWindowsHookExA",
        "GetAsyncKeyState"
    ]
}


class APIHookDetector:
    """Phát hiện các thay đổi (hooks) trong các API cốt lõi"""

    def __init__(self, alert_callback: Callable, logger, is_admin: bool):
        self.alert_callback = alert_callback
        self.logger = logger
        self.is_admin = is_admin
        self.running = False
        self.scan_interval = 60  # seconds (Không cần scan quá nhanh)
        self.baseline_opcodes = {}
        self.alerted_hooks = set()
        self.stats = {
            "apis_checked": 0,
            "hooks_found": 0,
            "last_scan": None
        }

    def _get_api_address(self, dll_name: str, api_name: str):
        """Lấy địa chỉ của một API trên RAM"""
        h_mod = LoadLibraryA(dll_name.encode('utf-8'))
        if not h_mod:
            return None
        return GetProcAddress(h_mod, api_name.encode('utf-8'))

    def _read_memory(self, address, size=5) -> bytes:
        """Đọc vài byte đầu tiên tại địa chỉ hàm (self process)"""
        if not address:
            return b""
        
        buffer = (ctypes.c_ubyte * size)()
        bytes_read = ctypes.c_size_t(0)

        # Đọc bộ nhớ của chính process Python này
        # Nếu Rootkit cài đặt global hook, nó sẽ tiêm DLL vào mọi process, kể cả process Python
        # Do đó, đọc RAM của chính mình sẽ thấy API bị sửa đổi.
        try:
            h_process = kernel32.GetCurrentProcess()
            result = kernel32.ReadProcessMemory(
                h_process,
                ctypes.c_void_p(address),
                ctypes.byref(buffer),
                size,
                ctypes.byref(bytes_read)
            )
            
            if result and bytes_read.value > 0:
                return bytes(buffer[:bytes_read.value])
        except Exception as e:
            pass
        return b""

    def build_baseline(self):
        """
        Lấy opcode chuẩn (unhooked) của các API.
        Trong thực tế, nên lấy opcode từ file DLL trên đĩa, nhưng để đơn giản 
        và tránh load từ đĩa liên tục, ta lấy giá trị hiện tại lúc mới khởi động làm chuẩn.
        (Lưu ý: Nếu máy ĐÃ bị nhiễm trước khi chạy tool, baseline này có thể sai).
        """
        self.logger.info("Building API Opcode Baseline...")
        
        for dll, apis in CRITICAL_APIS.items():
            if dll not in self.baseline_opcodes:
                self.baseline_opcodes[dll] = {}
                
            for api in apis:
                addr = self._get_api_address(dll, api)
                if addr:
                    opcodes = self._read_memory(addr, 5)
                    if opcodes:
                        self.baseline_opcodes[dll][api] = opcodes
                        self.stats["apis_checked"] += 1

    def scan_for_hooks(self):
        """Kiểm tra xem API có bị hook bằng lệnh JMP không"""
        if not self.baseline_opcodes:
            self.build_baseline()

        for dll, apis in CRITICAL_APIS.items():
            for api in apis:
                addr = self._get_api_address(dll, api)
                if not addr:
                    continue

                current_opcodes = self._read_memory(addr, 5)
                if not current_opcodes or len(current_opcodes) < 1:
                    continue

                # Kỹ thuật Inline Hooking phổ biến nhất: 
                # Ghi đè lệnh JMP (0xE9) hoặc JMP QWORD PTR (0xFF 0x25) vào đầu hàm
                first_byte = current_opcodes[0]
                
                is_hooked = False
                hook_type = ""

                if first_byte == 0xE9: # Relative JMP
                    is_hooked = True
                    hook_type = "JMP (0xE9)"
                elif len(current_opcodes) >= 2 and current_opcodes[0] == 0xFF and current_opcodes[1] == 0x25: # Absolute JMP
                    is_hooked = True
                    hook_type = "JMP PTR (FF 25)"

                # Nếu phát hiện byte lệnh JMP ở đầu hàm (và không phải là opcode nguyên gốc của hàm đó)
                # Ví dụ ntdll functions thường bắt đầu bằng 4C 8B D1 B8 (mov r10, rcx; mov eax, syscall_num)
                if is_hooked:
                    baseline_ops = self.baseline_opcodes.get(dll, {}).get(api, b"")
                    # Chắc chắn rằng nó thực sự bị thay đổi so với lúc khởi động
                    if current_opcodes != baseline_ops:
                        alert_key = f"apihook:{dll}:{api}"
                        if alert_key not in self.alerted_hooks:
                            self.alerted_hooks.add(alert_key)
                            self.stats["hooks_found"] += 1
                            
                            hex_opcodes = ' '.join([f"{b:02X}" for b in current_opcodes])
                            
                            self.alert_callback({
                                "module": "APIHookDetector",
                                "severity": "CRITICAL",
                                "type": "INLINE_API_HOOK",
                                "message": f"🚨 Phát hiện ROOTKIT/HOOK! Hàm hệ thống '{api}' trong '{dll}' đã bị sửa đổi mã lệnh.\n"
                                           f"Opcodes hiện tại: {hex_opcodes} (Nghi ngờ: {hook_type})\n"
                                           f"Mục đích: Một chương trình đang bí mật chặn/theo dõi dữ liệu hệ thống."
                            })

        self.stats["last_scan"] = datetime.now().isoformat()

    def start(self):
        self.running = True
        self.logger.info("APIHookDetector started")
        
        while self.running:
            try:
                self.scan_for_hooks()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"APIHookDetector error: {e}")
                time.sleep(10)

    def stop(self):
        self.running = False
