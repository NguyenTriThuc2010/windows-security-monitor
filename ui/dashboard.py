"""
Security Monitor GUI - Giao diện đồ họa hiện đại
Thay thế hoàn toàn terminal output bằng cửa sổ GUI dark-mode đẹp mắt.
"""

import tkinter as tk
from tkinter import ttk, font
import threading
import time
from datetime import datetime


# Bảng màu Dark Mode
COLORS = {
    "bg":          "#0d1117",   # Nền chính (GitHub dark)
    "bg2":         "#161b22",   # Nền panel
    "bg3":         "#21262d",   # Nền hàng bảng
    "border":      "#30363d",   # Viền
    "text":        "#e6edf3",   # Chữ chính
    "text_dim":    "#7d8590",   # Chữ mờ
    "accent":      "#58a6ff",   # Màu nhấn (xanh dương)
    "green":       "#3fb950",   # OK / safe
    "yellow":      "#d29922",   # Warning
    "red":         "#f85149",   # Critical
    "orange":      "#e3b341",   # High
    "purple":      "#bc8cff",   # Module color
    "header_bg":   "#1c2128",   # Nền tiêu đề cột
}

SEVERITY_COLORS = {
    "CRITICAL": COLORS["red"],
    "HIGH":     COLORS["orange"],
    "MEDIUM":   COLORS["yellow"],
    "LOW":      COLORS["green"],
    "INFO":     COLORS["accent"],
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}


class SecurityDashboard:
    def __init__(self):
        self.root = None
        self.monitors = {}
        self.alerts = []
        self.lock = None
        self.start_time = None

        # Biến tkinter (chỉ khởi tạo trong thread GUI)
        self._alert_tree = None
        self._stat_labels = {}
        self._module_frames = {}
        self._last_alert_count = 0
        self._alert_data = {}  # item_id -> full alert dict

    # ─────────────────────────────────────────────────────
    #  KHỞI TẠO CỬA SỔ
    # ─────────────────────────────────────────────────────
    def _build_window(self):
        self.root = tk.Tk()
        self.root.title("Security Monitor 24/7  |  Windows Threat Detection")
        self.root.geometry("1280x800")
        self.root.minsize(900, 600)
        self.root.configure(bg=COLORS["bg"])

        # Icon / taskbar (bỏ qua nếu không có file .ico)
        try:
            self.root.iconbitmap("icon.ico")
        except Exception:
            pass

        self._apply_ttk_style()
        self._build_header()
        self._build_main()
        self._build_statusbar()

    def _apply_ttk_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".",
            background=COLORS["bg"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["bg2"],
            bordercolor=COLORS["border"],
            darkcolor=COLORS["bg"],
            lightcolor=COLORS["bg2"],
            troughcolor=COLORS["bg2"],
            selectbackground=COLORS["accent"],
            selectforeground=COLORS["bg"],
            font=("Segoe UI", 10),
        )
        style.configure("Treeview",
            background=COLORS["bg3"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["bg3"],
            rowheight=28,
            font=("Segoe UI", 9),
        )
        style.configure("Treeview.Heading",
            background=COLORS["header_bg"],
            foreground=COLORS["accent"],
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Treeview",
            background=[("selected", "#1f3a5f")],
            foreground=[("selected", COLORS["text"])],
        )
        style.configure("TScrollbar",
            background=COLORS["bg2"],
            troughcolor=COLORS["bg"],
            bordercolor=COLORS["border"],
            arrowcolor=COLORS["text_dim"],
        )
        style.configure("Card.TFrame",
            background=COLORS["bg2"],
            relief="flat",
        )
        style.configure("TLabel",
            background=COLORS["bg"],
            foreground=COLORS["text"],
        )
        style.configure("Dim.TLabel",
            background=COLORS["bg"],
            foreground=COLORS["text_dim"],
            font=("Segoe UI", 9),
        )

    # ─────────────────────────────────────────────────────
    #  HEADER
    # ─────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=COLORS["bg2"], height=56)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        # Logo / title
        tk.Label(hdr,
            text="  🛡️  Security Monitor",
            bg=COLORS["bg2"], fg=COLORS["accent"],
            font=("Segoe UI", 15, "bold"),
        ).pack(side="left", padx=16)

        tk.Label(hdr,
            text="Windows Threat Detection  •  24/7",
            bg=COLORS["bg2"], fg=COLORS["text_dim"],
            font=("Segoe UI", 10),
        ).pack(side="left")

        # Uptime label (bên phải)
        self._uptime_var = tk.StringVar(value="Uptime: 0s")
        tk.Label(hdr,
            textvariable=self._uptime_var,
            bg=COLORS["bg2"], fg=COLORS["text_dim"],
            font=("Segoe UI", 9),
        ).pack(side="right", padx=16)

        # Trạng thái admin
        self._admin_var = tk.StringVar(value="")
        tk.Label(hdr,
            textvariable=self._admin_var,
            bg=COLORS["bg2"],
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", padx=8)

        # Đường kẻ phân cách
        tk.Frame(self.root, bg=COLORS["border"], height=1).pack(fill="x")

    # ─────────────────────────────────────────────────────
    #  MAIN CONTENT  (trái: stats + modules | phải: alerts)
    # ─────────────────────────────────────────────────────
    def _build_main(self):
        main = tk.Frame(self.root, bg=COLORS["bg"])
        main.pack(fill="both", expand=True)

        # ── Cột trái ──────────────────────────────────────
        left = tk.Frame(main, bg=COLORS["bg"], width=300)
        left.pack(side="left", fill="y", padx=(12, 6), pady=12)
        left.pack_propagate(False)

        self._build_stats_card(left)
        self._build_modules_card(left)

        # ── Cột phải (bảng cảnh báo) ──────────────────────
        right = tk.Frame(main, bg=COLORS["bg"])
        right.pack(side="left", fill="both", expand=True, padx=(6, 12), pady=12)

        self._build_alerts_panel(right)

    def _card(self, parent, title):
        """Tạo một khung card có tiêu đề"""
        outer = tk.Frame(parent, bg=COLORS["bg2"],
                         highlightbackground=COLORS["border"],
                         highlightthickness=1)
        outer.pack(fill="x", pady=(0, 10))

        tk.Label(outer, text=title,
                 bg=COLORS["bg2"], fg=COLORS["accent"],
                 font=("Segoe UI", 10, "bold"),
                 padx=12, pady=8,
                 anchor="w"
                 ).pack(fill="x")
        tk.Frame(outer, bg=COLORS["border"], height=1).pack(fill="x")

        body = tk.Frame(outer, bg=COLORS["bg2"])
        body.pack(fill="x", padx=12, pady=8)
        return body

    def _build_stats_card(self, parent):
        body = self._card(parent, "  📊  Tổng quan")
        stats_defs = [
            ("total_alerts", "Tổng cảnh báo",  COLORS["text"]),
            ("critical",     "🔴 Critical",     COLORS["red"]),
            ("high",         "🟠 High",         COLORS["orange"]),
            ("medium",       "🟡 Medium",       COLORS["yellow"]),
            ("monitored",    "Modules đang chạy", COLORS["green"]),
        ]
        for key, label, color in stats_defs:
            row = tk.Frame(body, bg=COLORS["bg2"])
            row.pack(fill="x", pady=3)
            tk.Label(row, text=label, bg=COLORS["bg2"],
                     fg=COLORS["text_dim"], font=("Segoe UI", 9),
                     anchor="w").pack(side="left")
            var = tk.StringVar(value="0")
            tk.Label(row, textvariable=var, bg=COLORS["bg2"],
                     fg=color, font=("Segoe UI", 11, "bold"),
                     anchor="e").pack(side="right")
            self._stat_labels[key] = var

    def _build_modules_card(self, parent):
        body = self._card(parent, "  ⚙️  Modules")
        self._modules_body = body

    def _build_alerts_panel(self, parent):
        # Tiêu đề + bộ lọc
        top = tk.Frame(parent, bg=COLORS["bg"])
        top.pack(fill="x", pady=(0, 6))

        tk.Label(top, text="  📋  Cảnh báo thời gian thực",
                 bg=COLORS["bg"], fg=COLORS["text"],
                 font=("Segoe UI", 11, "bold")).pack(side="left")

        # Nút Clear
        tk.Button(top, text="🗑  Xóa",
                  bg=COLORS["bg3"], fg=COLORS["text_dim"],
                  activebackground=COLORS["border"],
                  activeforeground=COLORS["text"],
                  relief="flat", padx=10, pady=3,
                  cursor="hand2",
                  command=self._clear_alerts,
                  font=("Segoe UI", 9),
                  ).pack(side="right")

        # Bộ lọc severity
        self._filter_var = tk.StringVar(value="ALL")
        for sev in ("ALL", "CRITICAL", "HIGH", "MEDIUM"):
            color = SEVERITY_COLORS.get(sev, COLORS["text"])
            tk.Radiobutton(top,
                text=sev, variable=self._filter_var, value=sev,
                bg=COLORS["bg"], fg=color,
                selectcolor=COLORS["bg2"],
                activebackground=COLORS["bg"],
                font=("Segoe UI", 8, "bold"),
                command=self._apply_filter,
            ).pack(side="right", padx=4)

        tk.Label(top, text="Lọc:", bg=COLORS["bg"],
                 fg=COLORS["text_dim"], font=("Segoe UI", 9)
                 ).pack(side="right", padx=(0, 4))

        # ── Treeview ──────────────────────────────────────
        cols = ("time", "severity", "module", "type", "message")
        frame = tk.Frame(parent,
                         bg=COLORS["border"], padx=1, pady=1)
        frame.pack(fill="both", expand=True)

        self._alert_tree = ttk.Treeview(frame, columns=cols,
                                        show="headings",
                                        selectmode="browse")
        self._alert_tree.heading("time",     text="Thời gian")
        self._alert_tree.heading("severity", text="Mức độ")
        self._alert_tree.heading("module",   text="Module")
        self._alert_tree.heading("type",     text="Loại")
        self._alert_tree.heading("message",  text="Thông báo")

        self._alert_tree.column("time",     width=95,  stretch=False)
        self._alert_tree.column("severity", width=80,  stretch=False)
        self._alert_tree.column("module",   width=140, stretch=False)
        self._alert_tree.column("type",     width=180, stretch=False)
        self._alert_tree.column("message",  width=400, stretch=True)

        # Màu từng severity
        for sev, color in SEVERITY_COLORS.items():
            self._alert_tree.tag_configure(sev, foreground=color)

        vsb = ttk.Scrollbar(frame, orient="vertical",
                             command=self._alert_tree.yview)
        self._alert_tree.configure(yscrollcommand=vsb.set)

        vsb.pack(side="right", fill="y")
        self._alert_tree.pack(fill="both", expand=True)

        # Click vào hàng -> hiện chi tiết
        self._alert_tree.bind("<ButtonRelease-1>", self._on_row_select)

        # ── KHUNG CHI TIẾT MỞ RỘNG ─────────────────────
        detail_frame = tk.Frame(parent,
                                bg=COLORS["bg2"],
                                highlightbackground=COLORS["border"],
                                highlightthickness=1)
        detail_frame.pack(fill="both", expand=False, pady=(6, 0))

        # Header + nút hành động
        hdr_row = tk.Frame(detail_frame, bg=COLORS["bg2"])
        hdr_row.pack(fill="x", padx=8, pady=(6, 2))

        tk.Label(hdr_row, text="▼ Chi tiet canh bao",
                 bg=COLORS["bg2"], fg=COLORS["accent"],
                 font=("Segoe UI", 10, "bold"), anchor="w").pack(side="left")

        # Nút hành động
        btn_style = {
            "bg": COLORS["bg3"], "relief": "flat",
            "activebackground": COLORS["border"],
            "cursor": "hand2", "font": ("Segoe UI", 8, "bold"),
            "padx": 8, "pady": 3,
        }

        tk.Button(hdr_row, text="📋 Copy", fg=COLORS["accent"],
                  command=self._copy_detail, **btn_style).pack(side="right", padx=2)

        tk.Button(hdr_row, text="✅ Bo qua", fg=COLORS["green"],
                  command=self._dismiss_alert, **btn_style).pack(side="right", padx=2)

        tk.Button(hdr_row, text="🔒 Block mang", fg=COLORS["orange"],
                  command=self._block_network, **btn_style).pack(side="right", padx=2)

        tk.Button(hdr_row, text="💀 Kill Process", fg=COLORS["red"],
                  command=self._kill_process, **btn_style).pack(side="right", padx=2)

        tk.Frame(detail_frame, bg=COLORS["border"], height=1).pack(fill="x", padx=8)

        # ── Thông tin tổng quan (2 cột) ───────────
        info_row = tk.Frame(detail_frame, bg=COLORS["bg2"])
        info_row.pack(fill="x", padx=8, pady=(6, 2))

        # Cột trái: meta
        meta_left = tk.Frame(info_row, bg=COLORS["bg2"])
        meta_left.pack(side="left", fill="x", expand=True)

        self._detail_meta = {}
        meta_fields = [
            ("severity", "Muc do:"),
            ("module",   "Module:"),
            ("type",     "Loai:"),
            ("time",     "Thoi gian:"),
            ("pid",      "PID:"),
            ("file",     "File:"),
            ("sha256",   "SHA-256:"),
        ]
        for key, label in meta_fields:
            row = tk.Frame(meta_left, bg=COLORS["bg2"])
            row.pack(fill="x", pady=1)
            tk.Label(row, text=label, bg=COLORS["bg2"],
                     fg=COLORS["text_dim"], font=("Segoe UI", 8),
                     width=10, anchor="e").pack(side="left")
            var = tk.StringVar(value="—")
            tk.Label(row, textvariable=var, bg=COLORS["bg2"],
                     fg=COLORS["text"], font=("Segoe UI", 8, "bold"),
                     anchor="w").pack(side="left", padx=(4, 0))
            self._detail_meta[key] = var

        tk.Frame(detail_frame, bg=COLORS["border"], height=1).pack(fill="x", padx=8, pady=4)

        # ── Nội dung chi tiết (scrollable) ────────
        tk.Label(detail_frame, text="  Noi dung day du:",
                 bg=COLORS["bg2"], fg=COLORS["purple"],
                 font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x", padx=8)

        txt_frame = tk.Frame(detail_frame, bg=COLORS["bg2"])
        txt_frame.pack(fill="both", expand=True, padx=8, pady=(2, 6))

        self._detail_text = tk.Text(txt_frame,
                                    bg=COLORS["bg3"],
                                    fg=COLORS["text"],
                                    font=("Cascadia Code", 9),
                                    relief="flat",
                                    wrap="word",
                                    height=5,
                                    state="disabled",
                                    padx=8, pady=6)
        detail_vsb = ttk.Scrollbar(txt_frame, orient="vertical",
                                   command=self._detail_text.yview)
        self._detail_text.configure(yscrollcommand=detail_vsb.set)
        detail_vsb.pack(side="right", fill="y")
        self._detail_text.pack(fill="both", expand=True)

        # Lưu alert đang chọn để nút hành động dùng
        self._selected_alert = None

    # ─────────────────────────────────────────────────────
    #  STATUS BAR
    # ─────────────────────────────────────────────────────
    def _build_statusbar(self):
        tk.Frame(self.root, bg=COLORS["border"], height=1).pack(fill="x")
        bar = tk.Frame(self.root, bg=COLORS["bg2"], height=26)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        self._status_var = tk.StringVar(value="He thong dang khoi dong...")
        tk.Label(bar, textvariable=self._status_var,
                 bg=COLORS["bg2"], fg=COLORS["text_dim"],
                 font=("Segoe UI", 8), anchor="w",
                 padx=10).pack(side="left", fill="y")

        self._pulse_var = tk.StringVar(value="●")
        self._pulse_label = tk.Label(bar, textvariable=self._pulse_var,
                                     bg=COLORS["bg2"], fg=COLORS["green"],
                                     font=("Segoe UI", 9))
        self._pulse_label.pack(side="right", padx=10)

    # ─────────────────────────────────────────────────────
    #  SỰ KIỆN CLICK VÀO HÀNG
    # ─────────────────────────────────────────────────────
    def _on_row_select(self, event):
        sel = self._alert_tree.selection()
        if not sel:
            return
        item_id = sel[0]
        alert = self._alert_data.get(item_id)
        self._selected_alert = alert

        if alert:
            full_msg = alert.get("message", "")
            sev      = alert.get("severity", "")
            module   = alert.get("module", "")
            atype    = alert.get("type", "")
            ts       = alert.get("timestamp", "")[:19].replace("T", " ")
            pid      = alert.get("process", {}).get("pid", "") if isinstance(alert.get("process"), dict) else ""
            fpath    = alert.get("file", "")
            sha      = alert.get("sha256", "")

            # Cập nhật các trường meta
            sev_icon = SEVERITY_ICONS.get(sev, "")
            self._detail_meta["severity"].set(f"{sev_icon} {sev}")
            self._detail_meta["module"].set(module)
            self._detail_meta["type"].set(atype)
            self._detail_meta["time"].set(ts)
            self._detail_meta["pid"].set(str(pid) if pid else "N/A")
            self._detail_meta["file"].set(str(fpath)[:80] if fpath else "N/A")
            self._detail_meta["sha256"].set(str(sha)[:40] + "..." if sha else "N/A")

            # Nội dung đầy đủ
            self._detail_text.configure(state="normal")
            self._detail_text.delete("1.0", "end")
            self._detail_text.insert("end", full_msg)
            self._detail_text.configure(state="disabled")
        else:
            values = self._alert_tree.item(item_id, "values")
            text = values[4] if len(values) >= 5 else ""
            self._detail_text.configure(state="normal")
            self._detail_text.delete("1.0", "end")
            self._detail_text.insert("end", text)
            self._detail_text.configure(state="disabled")

    # ─────────────────────────────────────────────────────
    #  NÚT HÀNH ĐỘNG
    # ─────────────────────────────────────────────────────
    def _kill_process(self):
        """Kill tiến trình liên quan đến cảnh báo đang chọn"""
        if not self._selected_alert:
            return
        proc = self._selected_alert.get("process", {})
        pid = proc.get("pid") if isinstance(proc, dict) else None
        if not pid:
            self._status_var.set("  Khong co PID de kill.")
            return
        try:
            import psutil
            p = psutil.Process(int(pid))
            name = p.name()
            p.kill()
            self._status_var.set(f"  DA KILL: {name} (PID {pid})")
        except Exception as e:
            self._status_var.set(f"  Loi kill: {e}")

    def _block_network(self):
        """Chặn mạng cho tiến trình đang chọn bằng Windows Firewall"""
        if not self._selected_alert:
            return
        proc = self._selected_alert.get("process", {})
        pid = proc.get("pid") if isinstance(proc, dict) else None
        if not pid:
            self._status_var.set("  Khong co PID de block.")
            return
        try:
            import psutil, subprocess
            p = psutil.Process(int(pid))
            exe = p.exe()
            name = p.name()
            rule_name = f"SecurityMonitor_Block_{name}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=out", "action=block",
                f"program={exe}"
            ], capture_output=True, timeout=5)
            self._status_var.set(f"  DA CHAN MANG: {name} ({exe})")
        except Exception as e:
            self._status_var.set(f"  Loi block: {e}")

    def _dismiss_alert(self):
        """Xóa cảnh báo đang chọn khỏi bảng"""
        sel = self._alert_tree.selection()
        if sel:
            item_id = sel[0]
            self._alert_data.pop(item_id, None)
            self._alert_tree.delete(item_id)
            self._selected_alert = None
            # Reset meta fields
            for var in self._detail_meta.values():
                var.set("—")
            self._detail_text.configure(state="normal")
            self._detail_text.delete("1.0", "end")
            self._detail_text.configure(state="disabled")
            self._status_var.set("  Da bo qua canh bao.")

    def _copy_detail(self):
        """Copy nội dung chi tiết vào clipboard"""
        if not self._selected_alert:
            return
        try:
            text = self._selected_alert.get("message", "")
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._status_var.set("  Da copy noi dung vao clipboard!")
        except Exception:
            pass

    def _clear_alerts(self):
        for item in self._alert_tree.get_children():
            self._alert_tree.delete(item)

    def _apply_filter(self):
        """Lọc bảng theo severity đã chọn (rebuild from self.alerts)"""
        self._clear_alerts()
        sev_filter = self._filter_var.get()
        with self.lock:
            alerts_snapshot = list(self.alerts[-500:])
        for a in alerts_snapshot:
            sev = a.get("severity", "INFO")
            if sev_filter != "ALL" and sev != sev_filter:
                continue
            self._insert_alert_row(a)

    def _insert_alert_row(self, alert: dict):
        sev      = alert.get("severity", "INFO")
        icon     = SEVERITY_ICONS.get(sev, "\u25cf")
        time_str = alert.get("timestamp", "")[:19].replace("T", " ")
        # Hiển thị 80 ký tự đầu trong cột (full message lưu trong _alert_data)
        short_msg = alert.get("message", "").replace("\n", " ")[:90]
        if len(alert.get("message", "")) > 90:
            short_msg += "..."

        item_id = self._alert_tree.insert("", 0,
            values=(
                time_str,
                f"{icon} {sev}",
                alert.get("module", ""),
                alert.get("type", ""),
                short_msg,
            ),
            tags=(sev,)
        )
        # Lưu full alert vào cache
        self._alert_data[item_id] = alert

        # Giới hạn 300 hàng hiển thị
        children = self._alert_tree.get_children()
        if len(children) > 300:
            old_id = children[-1]
            self._alert_data.pop(old_id, None)
            self._alert_tree.delete(old_id)

    # ─────────────────────────────────────────────────────
    #  VÒNG LẶP CẬP NHẬT (chạy mỗi 1.5s)
    # ─────────────────────────────────────────────────────
    def _update_loop(self):
        if not self.running:
            return
        try:
            self._update_stats()
            self._update_modules()
            self._update_new_alerts()
            self._update_uptime()
            self._pulse_animation()
        except Exception:
            pass
        self.root.after(1500, self._update_loop)

    def _update_stats(self):
        with self.lock:
            alerts = list(self.alerts)
        total    = len(alerts)
        critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        high     = sum(1 for a in alerts if a.get("severity") == "HIGH")
        medium   = sum(1 for a in alerts if a.get("severity") == "MEDIUM")

        self._stat_labels["total_alerts"].set(str(total))
        self._stat_labels["critical"].set(str(critical))
        self._stat_labels["high"].set(str(high))
        self._stat_labels["medium"].set(str(medium))
        self._stat_labels["monitored"].set(str(len(self.monitors)))

        # Status bar
        if critical > 0:
            self._status_var.set(f"  Phat hien {critical} canh bao CRITICAL! Kiem tra ngay.")
            self._pulse_label.configure(fg=COLORS["red"])
        elif high > 0:
            self._status_var.set(f"  Co {high} canh bao muc HIGH can chu y.")
            self._pulse_label.configure(fg=COLORS["orange"])
        else:
            self._status_var.set(f"  He thong dang giam sat... Tong {total} su kien ghi nhan.")
            self._pulse_label.configure(fg=COLORS["green"])

    def _update_modules(self):
        """Vẽ lại danh sách module"""
        for w in self._modules_body.winfo_children():
            w.destroy()
        for key, mon in self.monitors.items():
            row = tk.Frame(self._modules_body, bg=COLORS["bg2"])
            row.pack(fill="x", pady=2)
            last = getattr(getattr(mon, "stats", {}), "get",
                           lambda k, d=None: d)("last_scan", None)
            if hasattr(mon, "stats") and isinstance(mon.stats, dict):
                last = mon.stats.get("last_scan", "—")
            else:
                last = "—"
            tk.Label(row, text=f"● {key}",
                     bg=COLORS["bg2"], fg=COLORS["green"],
                     font=("Segoe UI", 9), anchor="w"
                     ).pack(side="left")
            tk.Label(row, text=str(last)[:8] if last and last != "—" else "chay...",
                     bg=COLORS["bg2"], fg=COLORS["text_dim"],
                     font=("Segoe UI", 8), anchor="e"
                     ).pack(side="right")

    def _update_new_alerts(self):
        """Chỉ thêm cảnh báo mới (không rebuild toàn bộ)"""
        with self.lock:
            count = len(self.alerts)
        if count == self._last_alert_count:
            return
        sev_filter = self._filter_var.get()
        with self.lock:
            new_alerts = self.alerts[self._last_alert_count:]
        for a in new_alerts:
            sev = a.get("severity", "INFO")
            if sev_filter == "ALL" or sev == sev_filter:
                self._insert_alert_row(a)
        self._last_alert_count = count

    def _update_uptime(self):
        if self.start_time:
            delta = datetime.now() - self.start_time
            h, r = divmod(int(delta.total_seconds()), 3600)
            m, s = divmod(r, 60)
            self._uptime_var.set(f"Uptime: {h:02d}:{m:02d}:{s:02d}")

    _pulse_state = True
    def _pulse_animation(self):
        self._pulse_state = not self._pulse_state
        self._pulse_var.set("●" if self._pulse_state else "○")

    # ─────────────────────────────────────────────────────
    #  ENTRY POINT (gọi từ main.py)
    # ─────────────────────────────────────────────────────
    def run(self, monitors, alerts, lock, start_time, is_admin):
        self.monitors   = monitors
        self.alerts     = alerts
        self.lock       = lock
        self.start_time = start_time
        self.running    = True

        self._build_window()

        # Cập nhật trạng thái Admin
        if is_admin:
            self._admin_var.set("✅ Administrator")
            self._pulse_label.configure(fg=COLORS["green"])
        else:
            self._admin_var.set("⚠️ No Admin")

        # Bắt đầu vòng lặp cập nhật
        self.root.after(2000, self._update_loop)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        self.running = False
        self.root.destroy()
