"""ui/report.py - Tạo báo cáo HTML khi tắt chương trình"""

import os
from datetime import datetime
from pathlib import Path


def generate_report(alerts: list, start_time: datetime) -> str:
    """Tạo báo cáo HTML tóm tắt phiên giám sát"""
    try:
        log_dir = Path(__file__).parent.parent / "logs"
        log_dir.mkdir(exist_ok=True)
        report_path = log_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        duration = datetime.now() - start_time
        h, r = divmod(int(duration.total_seconds()), 3600)
        m, s = divmod(r, 60)

        sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in alerts:
            sev = a.get("severity", "LOW")
            if sev in sev_count:
                sev_count[sev] += 1

        rows = ""
        for a in reversed(alerts[-200:]):
            sev = a.get("severity", "INFO")
            color = {"CRITICAL": "#f85149", "HIGH": "#e3b341",
                     "MEDIUM": "#d29922", "LOW": "#3fb950"}.get(sev, "#7d8590")
            msg = a.get("message", "").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
            rows += f"""<tr>
                <td>{a.get('timestamp','')[:19].replace('T',' ')}</td>
                <td style="color:{color};font-weight:bold">{sev}</td>
                <td>{a.get('module','')}</td>
                <td>{a.get('type','')}</td>
                <td>{msg}</td>
            </tr>"""

        html = f"""<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8">
<title>Security Monitor Report</title>
<style>
  body{{background:#0d1117;color:#e6edf3;font-family:Segoe UI,sans-serif;padding:20px}}
  h1{{color:#58a6ff}} table{{width:100%;border-collapse:collapse;margin-top:20px}}
  th{{background:#1c2128;color:#58a6ff;padding:10px;text-align:left}}
  td{{padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top;font-size:13px}}
  tr:hover{{background:#161b22}}
  .stat{{display:inline-block;background:#161b22;border:1px solid #30363d;
         border-radius:8px;padding:12px 24px;margin:8px;text-align:center}}
  .stat .num{{font-size:28px;font-weight:bold}} .stat .lbl{{color:#7d8590;font-size:12px}}
</style></head><body>
<h1>Security Monitor - Bao cao phien giam sat</h1>
<p style="color:#7d8590">Bat dau: {start_time.strftime('%Y-%m-%d %H:%M:%S')} 
   &nbsp;|&nbsp; Thoi gian chay: {h:02d}:{m:02d}:{s:02d}</p>
<div>
  <div class="stat"><div class="num" style="color:#e6edf3">{len(alerts)}</div>
    <div class="lbl">Tong canh bao</div></div>
  <div class="stat"><div class="num" style="color:#f85149">{sev_count['CRITICAL']}</div>
    <div class="lbl">Critical</div></div>
  <div class="stat"><div class="num" style="color:#e3b341">{sev_count['HIGH']}</div>
    <div class="lbl">High</div></div>
  <div class="stat"><div class="num" style="color:#d29922">{sev_count['MEDIUM']}</div>
    <div class="lbl">Medium</div></div>
</div>
<table><thead><tr><th>Thoi gian</th><th>Muc do</th>
<th>Module</th><th>Loai</th><th>Thong bao</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        return str(report_path)
    except Exception:
        return ""
