#!/usr/bin/env python3
"""
DanishRecon / DanishRecon - PyQt5 desktop GUI.

The scan engine itself lives in scan_core.py (no Qt). This module only contains the
window, dialogs, history exporter, PIN lock and login alert, plus a thin QThread wrapper
that runs the engine off the GUI thread and forwards its signals as Qt signals.
"""

import sys, os, re, json, csv, sqlite3, base64, hashlib, socket, ssl, hmac, getpass, platform, urllib.parse
import subprocess, threading, time, traceback, shutil
import requests
from datetime import datetime
from collections import defaultdict

from danishrecon import scan_core
from danishrecon.scan_core import (

    DB, DB_PATH, EXPLOIT_DB_DIR, NIKTO_PATH, PIN_CONFIG_PATH, PIN_HASH_ITERATIONS, Paragraph,
    ParagraphStyle, REPORTLAB_AVAILABLE, RESULTS_DIR, SCAN_PROFILES, SEARCHSPLOIT_BAT,
    SEARCHSPLOIT_PATH, SEARCHSPLOIT_PS1, SimpleDocTemplate, Spacer, TA_CENTER,
    TWILIO_ACCOUNT_SID_ENV, TWILIO_AUTH_TOKEN_ENV, TWILIO_ENABLED_ENV,
    TWILIO_WHATSAPP_FROM_ENV, TWILIO_WHATSAPP_TO_ENV, Table, TableStyle, Theme,
    build_stylesheet, colors, csv, datetime, esc, getSampleStyleSheet, getpass, hashlib, hmac,
    inch, json, letter, normalize_target, os, platform, re, requests, socket, ssl, subprocess,
    sys, threading, traceback, urllib,
)

# Scout AI chatbot panel (optional)
try:
    from danishrecon.scout_panel import ScoutPanel
    SCOUT_PANEL_AVAILABLE = True
except ImportError as _scout_err:
    SCOUT_PANEL_AVAILABLE = False
    print(f"[Scout] Import failed (non-fatal): {_scout_err}")

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QListWidget, QListWidgetItem,
    QProgressBar, QGroupBox, QScrollArea, QSplitter, QFrame, QTabWidget,
    QGraphicsDropShadowEffect, QSizePolicy, QComboBox, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QDialog, QDialogButtonBox,
    QSpinBox, QSlider, QToolButton, QMenu, QAction, QMessageBox,
    QFileDialog, QTreeWidget, QTreeWidgetItem, QStackedWidget, QTextBrowser,
    QAbstractItemView, QSystemTrayIcon, QShortcut
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve,
    QSize, QPoint, QRect, QObject, QRunnable, QThreadPool
)
from PyQt5.QtGui import (
    QFont, QColor, QPalette, QTextCursor, QIcon, QPainter, QLinearGradient,
    QBrush, QPen, QPixmap, QRadialGradient, QConicalGradient, QPolygonF,
    QFontDatabase, QPainterPath, QKeySequence
)

# 
#  FIX UNICODE ENCODING FOR WINDOWS CONSOLE
# 
if sys.platform == 'win32':
    import io
    # Reconfigure stdout/stderr to use UTF-8 encoding
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    # Set console code page to UTF-8 if possible
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)  # UTF-8
    except:
        pass

# 
#  THEME ENGINE
# 

class ScanEngine(QThread):
    """Runs scan_core.ScanEngine on a worker thread and re-emits its signals as Qt signals
    (which Qt delivers to the GUI thread safely)."""

    log_signal      = pyqtSignal(str, str)       # (message, level)
    progress_signal = pyqtSignal(str, int)
    result_signal   = pyqtSignal(str, str, str)  # (container, item, color)
    stage_signal    = pyqtSignal(str)
    chart_signal    = pyqtSignal(dict)
    scan_complete   = pyqtSignal(dict)
    stopped         = pyqtSignal()

    _SIGNALS = ("log_signal", "progress_signal", "result_signal", "stage_signal",
                "chart_signal", "scan_complete", "stopped")

    def __init__(self, target: str, profile: str = "Custom", options: dict = None):
        super().__init__()
        self.core = scan_core.ScanEngine(target, profile, options)
        for name in self._SIGNALS:
            getattr(self.core, name).connect(getattr(self, name).emit)

    def run(self):
        self.core.run()

    def stop(self):
        self.core.stop()

    def pause(self):
        self.core.pause()

    def resume(self):
        self.core.resume()

    def is_paused(self):
        return self.core.is_paused()

    def __getattr__(self, name):
        # data, scan_id, export_pdf(), ... live on the engine
        if name == "core":
            raise AttributeError(name)
        return getattr(self.core, name)


class LabeledProgress(QWidget):
    def __init__(self, label, parent=None):
        super().__init__(parent)
        t = Theme.current
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,5); lay.setSpacing(3)
        hdr = QHBoxLayout()
        self.lbl = QLabel(label)
        self.lbl.setStyleSheet(f"color:{t['TEXT']};font-size:12px;font-weight:bold;letter-spacing:1.5px;")
        self.pct = QLabel("0%")
        self.pct.setStyleSheet(f"color:{t['CYAN']};font-size:12px;font-family:monospace;font-weight:bold;")
        hdr.addWidget(self.lbl); hdr.addStretch(); hdr.addWidget(self.pct)
        self.bar = QProgressBar(); self.bar.setRange(0,100); self.bar.setValue(0)
        self.bar.setFixedHeight(8); self.bar.setTextVisible(False)  # Slightly larger bar
        lay.addLayout(hdr); lay.addWidget(self.bar)

    def set_value(self, v):
        self.bar.setValue(v); self.pct.setText(f"{v}%")
        t = Theme.current
        if v == 100:
            self.bar.setStyleSheet(f"QProgressBar::chunk{{background:{t['GREEN']};border-radius:4px;}}")

    def reset(self):
        self.bar.setValue(0); self.pct.setText("0%")
        self.bar.setStyleSheet("")


class ResultContainer(QWidget):
    def __init__(self, title, icon="", parent=None):
        super().__init__(parent)
        t = Theme.current
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(3)
        hdr = QHBoxLayout()
        lbl = QLabel(f"  {icon}  {title}")
        lbl.setStyleSheet(f"color:{t['CYAN']};font-size:13px;font-weight:bold;letter-spacing:1.2px;")
        self.cnt = QLabel("0")
        self.cnt.setStyleSheet(f"color:{t['GREEN']};font-size:13px;font-weight:bold;font-family:monospace;")
        hdr.addWidget(lbl); hdr.addStretch(); hdr.addWidget(self.cnt)
        self.list = QListWidget(); self.list.setMinimumHeight(60)
        self.list.setStyleSheet(f"font-size:12px;line-height:1.5;")
        lay.addLayout(hdr); lay.addWidget(self.list)

    def add_item(self, text, color=None):
        item = QListWidgetItem(text)
        item.setForeground(QColor(color or Theme.current["TEXT"]))
        self.list.addItem(item)
        self.list.scrollToBottom()
        self.cnt.setText(str(self.list.count()))

    def clear(self):
        self.list.clear(); self.cnt.setText("0")


class StageIndicator(QWidget):
    """Animated current-stage badge."""
    def __init__(self, parent=None):
        super().__init__(parent)
        t = Theme.current
        lay = QHBoxLayout(self); lay.setContentsMargins(0,0,0,0)
        self.dot = QLabel("")
        self.dot.setStyleSheet(f"color:{t['TEXT3']};font-size:10px;")
        self.lbl = QLabel("IDLE")
        self.lbl.setStyleSheet(f"color:{t['TEXT']};font-size:10px;font-family:monospace;letter-spacing:1.5px;")
        lay.addWidget(self.dot); lay.addWidget(self.lbl); lay.addStretch()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._blink)
        self._on = False

    def set_stage(self, stage_name):
        t = Theme.current
        self.lbl.setText(stage_name.upper())
        self.lbl.setStyleSheet(f"color:{t['CYAN']};font-size:10px;font-family:monospace;letter-spacing:1.5px;")
        self._timer.start(600)

    def _blink(self):
        t = Theme.current
        self._on = not self._on
        self.dot.setStyleSheet(
            f"color:{''+t['CYAN'] if self._on else t['TEXT3']};font-size:10px;"
        )

    def stop(self):
        self._timer.stop()
        t = Theme.current
        self.dot.setStyleSheet(f"color:{t['GREEN']};font-size:12px;")
        self.lbl.setText("COMPLETE")
        self.lbl.setStyleSheet(f"color:{t['GREEN']};font-size:10px;font-family:monospace;letter-spacing:1px;")


class ConsoleSearchBar(QWidget):
    def __init__(self, console: QTextEdit, parent=None):
        super().__init__(parent)
        t = Theme.current
        lay = QHBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(6)
        self.input = QLineEdit(); self.input.setPlaceholderText("Filter console...")
        self.input.setFixedHeight(26)
        self.input.setStyleSheet(f"background:{t['CARD']};border:1px solid {t['BORDER']};border-radius:4px;color:{t['TEXT']};padding:2px 8px;font-size:11px;")
        btn = QPushButton(""); btn.setFixedSize(26,26)
        btn.setStyleSheet(f"background:{t['CARD']};border:1px solid {t['BORDER']};border-radius:4px;color:{t['CYAN']};")
        btn.clicked.connect(self._search)
        self.input.returnPressed.connect(self._search)
        lay.addWidget(self.input); lay.addWidget(btn)
        self.console = console
        self._orig_html = ""

    def _search(self):
        term = self.input.text().strip()
        if not term: return
        cursor = self.console.document().find(term)
        if not cursor.isNull():
            self.console.setTextCursor(cursor)
            self.console.ensureCursorVisible()


# 
#  HISTORICAL SCAN EXPORTER - For exporting previously completed scans
# 
class HistoryScanExporter:
    """Export scan data from database without re-running scans"""
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        
        # Get scan info from database
        c = DB.conn.cursor()
        c.execute("SELECT id,target,profile,started,finished,status FROM scans WHERE id=?", (scan_id,))
        row = c.fetchone()
        if not row:
            raise Exception(f"Scan {scan_id} not found")
        
        self.scan_id, self.target, self.profile, started, finished, status = row
        # Handle both ISO format (2026-03-22T15:25:55.204577) and standard format (2026-03-22 15:25:55)
        try:
            self.started_at = datetime.fromisoformat(started) if started else datetime.now()
        except (ValueError, TypeError):
            self.started_at = datetime.strptime(started, "%Y-%m-%d %H:%M:%S") if started else datetime.now()
        try:
            self.ended_at = datetime.fromisoformat(finished) if finished else None
        except (ValueError, TypeError):
            self.ended_at = datetime.strptime(finished, "%Y-%m-%d %H:%M:%S") if finished else None
        
        # Reconstruct data from database
        self.data = self._reconstruct_scan_data()
    
    def _reconstruct_scan_data(self):
        """Rebuild scan data from database records"""
        c = DB.conn.cursor()
        
        # Get hosts
        c.execute("SELECT address, hostname, os_guess, status FROM hosts WHERE scan_id=?", (self.scan_id,))
        hosts = [row[0] for row in c.fetchall()]
        os_guesses = [row[2] for row in c.fetchall() if row[2]]
        c.execute("SELECT address, hostname, os_guess, status FROM hosts WHERE scan_id=?", (self.scan_id,))
        
        # Get ports and services
        c.execute("SELECT host, port, proto, service, version, state, banner FROM ports WHERE scan_id=?", (self.scan_id,))
        port_rows = c.fetchall()
        services = [f"{row[3]}:{row[1]}" for row in port_rows]
        versions = [row[4] for row in port_rows if row[4]]
        
        # Get vulnerabilities
        c.execute("SELECT * FROM vulns WHERE scan_id=?", (self.scan_id,))
        vuln_rows = c.fetchall()
        vulnerabilities = []
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for vuln_row in vuln_rows:
            # vuln_row: id, scan_id, host, service, port, risk, cve, cvss, title, mitre_id, mitre_tech, compliance
            risk = vuln_row[5]
            title = vuln_row[8]
            cve = vuln_row[6]
            vulnerabilities.append(f"[{risk}] {title} ({cve})")
            if risk in risk_counts:
                risk_counts[risk] += 1
        
        # Get certificate/SSL info
        c.execute("SELECT message FROM timeline WHERE scan_id=? AND stage LIKE '%SSL%'", (self.scan_id,))
        ssl_issues = [row[0] for row in c.fetchall() if row[0]]
        
        # Get DNS records
        c.execute("SELECT message FROM timeline WHERE scan_id=? AND stage='DNS'", (self.scan_id,))
        dns_records = [row[0] for row in c.fetchall() if "DNS" in row[0] or "record" in row[0].lower()]
        
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "profile": self.profile,
            "timestamp": self.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "started_at": self.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "ended_at": self.ended_at.strftime("%Y-%m-%d %H:%M:%S") if self.ended_at else "",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": self._format_duration((self.ended_at - self.started_at).total_seconds() if self.ended_at else 0),
            "duration_seconds": int((self.ended_at - self.started_at).total_seconds()) if self.ended_at else 0,
            "hosts": hosts,
            "services": services,
            "versions": versions,
            "banners": [],
            "os_guesses": os_guesses,
            "dns_records": dns_records,
            "ssl_issues": ssl_issues,
            "vulnerabilities": vulnerabilities,
            "exploits": [],
            "attack_paths": [],
            "recommendations": [],
            "compliance": [],
            "port_states": {},
            "risk_counts": risk_counts,
            "mitre_techniques": [],
        }
    
    def _format_duration(self, total_seconds: int):
        """Format duration to HH:MM:SS"""
        total_seconds = max(int(total_seconds), 0)
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def export_json(self):
        """Export as JSON"""
        path = os.path.join(RESULTS_DIR, f"scan_{self.scan_id}_export.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        return path
    
    def export_csv(self):
        """Export vulnerabilities as CSV"""
        path = os.path.join(RESULTS_DIR, f"vulns_{self.scan_id}_export.csv")
        rows = DB.get_scan_vulns(self.scan_id)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "scan_id", "host", "service", "port", "risk", "cve", "cvss", "title", "mitre", "technique", "compliance"])
            w.writerows(rows)
        return path
    
    def export_markdown(self):
        """Export as Markdown report"""
        d = self.data
        lines = [
            f"# DanishRecon  Pentest Report (Exported)",
            f"**Target:** {d['target']}  **Profile:** {d['profile']}",
            f"**Started:** {d['started_at']}  **Ended:** {d['ended_at'] or 'In progress'}  **Duration:** {d['duration']}",
            f"**Report Generated:** {d['generated_at']}  **Scan ID:** #{self.scan_id}",
            "", "---", "",
            "## Executive Summary",
            f"- Hosts: {len(d['hosts'])}  Services: {len(d['services'])}  Vulnerabilities: {len(d['vulnerabilities'])}",
            f"- Risk Summary: CRITICAL={d['risk_counts']['CRITICAL']}, HIGH={d['risk_counts']['HIGH']}, MEDIUM={d['risk_counts']['MEDIUM']}, LOW={d['risk_counts']['LOW']}",
            "", "## Infrastructure Discovery",
            "### Hosts Discovered",
        ]
        for host in d["hosts"]:
            lines.append(f"- {host}")
        
        lines += ["", "### Services & Versions"]
        for svc in d["services"]:
            lines.append(f"- {svc}")
        
        lines += ["", "## Vulnerabilities"]
        if d["vulnerabilities"]:
            for vuln in d["vulnerabilities"]:
                lines.append(f"- {vuln}")
        else:
            lines.append("- No vulnerabilities found")
        
        lines += ["", "---", f"*Report exported from DanishRecon - Scan #{self.scan_id}*"]
        
        path = os.path.join(RESULTS_DIR, f"report_{self.scan_id}_export.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path
    
    def export_html(self):
        """Export as full comprehensive HTML report"""
        d = self.data
        tgt = esc(d['target'])
        started = d['started_at']
        ended = d['ended_at'] or 'In progress'
        duration = d['duration']
        generated = d['generated_at']
        
        # Calculate risk score
        rc = d['risk_counts']
        crit_count = rc.get('CRITICAL', 0)
        high_count = rc.get('HIGH', 0)
        risk_score = min(10, int((crit_count * 3 + high_count * 1.5) / max(1, crit_count + high_count)))
        
        # Build vulnerability table
        vuln_rows = ""
        if d['vulnerabilities']:
            for vuln in d['vulnerabilities']:  # Show ALL vulnerabilities in report
                vuln_rows += f"<tr><td>{esc(vuln)}</td></tr>"
        
        # Build comprehensive HTML with multiple sections
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DanishRecon Report - Scan #{self.scan_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ background: #080C18; color: #F1F5F9; font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #0C1220; padding: 40px 60px; }}
        
        /* Header */
        .header {{ background: linear-gradient(135deg, #0D1B2A 0%, #1B2B3B 100%); padding: 50px 40px; border-radius: 10px; margin-bottom: 40px; border-left: 5px solid #00E5FF; }}
        h1 {{ color: #00E5FF; font-size: 40px; margin-bottom: 20px; letter-spacing: 1px; }}
        .header-meta {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-top: 30px; }}
        .meta-group {{ padding: 15px; background: rgba(255,255,255,0.05); border-radius: 6px; }}
        .meta-label {{ color: #94A3B8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 5px; }}
        .meta-value {{ color: #F1F5F9; font-size: 15px; font-weight: 600; }}
        
        /* Stats Grid */
        .stats {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 15px; margin: 40px 0; }}
        .stat-box {{ background: #111827; padding: 20px; border-radius: 8px; text-align: center; border-top: 3px solid #00E5FF; transition: all 0.3s; }}
        .stat-box:hover {{ transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,229,255,0.2); }}
        .stat-num {{ font-size: 32px; font-weight: bold; margin-bottom: 8px; }}
        .stat-num.crit {{ color: #EF4444; }}
        .stat-num.high {{ color: #F59E0B; }}
        .stat-num.med {{ color: #EAB308; }}
        .stat-num.low {{ color: #10B981; }}
        .stat-num.blue {{ color: #00E5FF; }}
        .stat-label {{ color: #94A3B8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
        
        /* Sections */
        section {{ margin-bottom: 50px; }}
        h2 {{ color: #00E5FF; font-size: 24px; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 2px solid #00E5FF; display: flex; align-items: center; gap: 15px; }}
        .sec-num {{ background: #00E5FF; color: #0C1220; width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; }}
        
        /* Cards and Content */
        .card {{ background: #111827; padding: 20px; border-radius: 8px; border-left: 3px solid #00E5FF; }}
        .card h3 {{ color: #00E5FF; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 15px; }}
        .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .exec-card {{ background: #111827; padding: 25px; border-radius: 8px; border-left: 4px solid #00E5FF; }}
        .exec-card p {{ margin-bottom: 15px; color: #E2E8F0; line-height: 1.7; }}
        
        /* Lists */
        ul {{ margin-left: 20px; list-style: none; }}
        li {{ margin: 10px 0; color: #CBD5E1; padding-left: 20px; position: relative; }}
        li:before {{ content: "▶"; position: absolute; left: 0; color: #00E5FF; }}
        
        /* Tables */
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }}
        th {{ background: #0A1419; color: #00E5FF; padding: 12px; text-align: left; border: 1px solid #1E293B; font-weight: 600; }}
        td {{ padding: 12px; border: 1px solid #1E293B; color: #CBD5E1; }}
        tr:hover {{ background: rgba(0, 229, 255, 0.05); }}
        .risk-critical {{ color: #EF4444; font-weight: 600; }}
        .risk-high {{ color: #F59E0B; font-weight: 600; }}
        .risk-medium {{ color: #EAB308; font-weight: 600; }}
        .risk-low {{ color: #10B981; font-weight: 600; }}
        
        /* Risk Score */
        .risk-score-box {{ background: #111827; padding: 30px; border-radius: 8px; text-align: center; margin: 30px 0; border: 2px solid #00E5FF; }}
        .risk-score-num {{ font-size: 48px; font-weight: bold; color: #00E5FF; margin-bottom: 10px; }}
        .risk-score-label {{ color: #94A3B8; text-transform: uppercase; font-size: 12px; letter-spacing: 1px; }}
        .risk-rating {{ font-size: 18px; font-weight: bold; margin-top: 10px; }}
        
        /* Footer */
        footer {{ margin-top: 60px; padding-top: 30px; border-top: 2px solid #1E293B; text-align: center; color: #64748B; font-size: 12px; }}
        
        /* Print styles */
        @media print {{
            body {{ padding: 0; background: white; color: black; }}
            .container {{ background: white; padding: 20px; }}
            h1, h2, .stat-num {{ color: black; }}
            .header {{ background: #f5f5f5; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 DanishRecon Penetration Test Report</h1>
            <div class="header-meta">
                <div class="meta-group">
                    <div class="meta-label">Target</div>
                    <div class="meta-value">{tgt}</div>
                </div>
                <div class="meta-group">
                    <div class="meta-label">Scan Profile</div>
                    <div class="meta-value">{esc(d['profile'])}</div>
                </div>
                <div class="meta-group">
                    <div class="meta-label">Scan Started</div>
                    <div class="meta-value">{started}</div>
                </div>
                <div class="meta-group">
                    <div class="meta-label">Scan Completed</div>
                    <div class="meta-value">{ended}</div>
                </div>
                <div class="meta-group">
                    <div class="meta-label">Duration</div>
                    <div class="meta-value">{duration}</div>
                </div>
                <div class="meta-group">
                    <div class="meta-label">Report Generated</div>
                    <div class="meta-value">{generated}</div>
                </div>
            </div>
        </div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-num blue">{len(d['hosts'])}</div>
                <div class="stat-label">Hosts</div>
            </div>
            <div class="stat-box">
                <div class="stat-num blue">{len(d['services'])}</div>
                <div class="stat-label">Services</div>
            </div>
            <div class="stat-box">
                <div class="stat-num crit">{crit_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-num high">{high_count}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-box">
                <div class="stat-num med">{rc.get('MEDIUM', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-num low">{rc.get('LOW', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>

        <div class="risk-score-box">
            <div class="risk-score-num">{risk_score}/10</div>
            <div class="risk-score-label">Overall Risk Score</div>
            <div class="risk-rating">
                {
                    '<span style="color:#EF4444">⚠ CRITICAL</span>' if risk_score >= 8 else
                    '<span style="color:#F59E0B">⚠ HIGH</span>' if risk_score >= 6 else
                    '<span style="color:#EAB308">⚠ MEDIUM</span>' if risk_score >= 4 else
                    '<span style="color:#10B981">✓ LOW</span>'
                }
            </div>
        </div>

        <section>
            <h2><span class="sec-num">01</span> EXECUTIVE SUMMARY</h2>
            <div class="exec-card">
                <p>This penetration test report presents findings from an automated reconnaissance and vulnerability assessment conducted against <strong style="color:#00E5FF">{tgt}</strong>.</p>
                <p><strong>Assessment Period:</strong> {started} to {ended} ({duration})</p>
                <p><strong>Scope:</strong> {len(d['hosts'])} hosts | {len(d['services'])} services | {len(d['vulnerabilities'])} vulnerabilities identified</p>
                <p><strong>Severity Distribution:</strong> {crit_count} CRITICAL | {high_count} HIGH | {rc.get('MEDIUM', 0)} MEDIUM | {rc.get('LOW', 0)} LOW</p>
                <p><strong>Overall Risk Score:</strong> <span style="font-size:18px;font-weight:bold;color:#00E5FF">{risk_score}/10</span></p>
                <p>This report documents all discovered vulnerabilities, their severity ratings, and recommended remediation steps.</p>
            </div>
        </section>

        <section>
            <h2><span class="sec-num">02</span> INFRASTRUCTURE DISCOVERY</h2>
            <div class="two-col">
                <div class="card">
                    <h3>Hosts Discovered ({len(d['hosts'])} total)</h3>
                    <ul>{"".join(f"<li>{esc(host)}</li>" for host in d['hosts']) if d['hosts'] else "<li>No hosts found</li>"}</ul>
                </div>
                <div class="card">
                    <h3>OS Fingerprints</h3>
                    <ul>{"".join(f"<li>{esc(os)}</li>" for os in d['os_guesses'][:10]) if d['os_guesses'] else "<li>No OS information available</li>"}</ul>
                </div>
            </div>
            <div class="two-col" style="margin-top: 20px;">
                <div class="card">
                    <h3>DNS Records</h3>
                    <ul>{"".join(f"<li>{esc(dns)}</li>" for dns in d['dns_records'][:10]) if d['dns_records'] else "<li>No DNS records found</li>"}</ul>
                </div>
                <div class="card">
                    <h3>SSL/TLS Issues</h3>
                    <ul>{"".join(f"<li>{esc(ssl)}</li>" for ssl in d['ssl_issues'][:10]) if d['ssl_issues'] else "<li>No SSL/TLS issues found</li>"}</ul>
                </div>
            </div>
        </section>

        <section>
            <h2><span class="sec-num">03</span> SERVICES & VERSIONS</h2>
            <div class="two-col">
                <div class="card">
                    <h3>Open Services ({len(d['services'])} total)</h3>
                    <ul>{"".join(f"<li>{esc(svc)}</li>" for svc in d['services']) if d['services'] else "<li>No services found</li>"}</ul>
                </div>
                <div class="card">
                    <h3>Service Versions ({len(d['versions'])} total)</h3>
                    <ul>{"".join(f"<li>{esc(ver)}</li>" for ver in d['versions']) if d['versions'] else "<li>No version information available</li>"}</ul>
                </div>
            </div>
        </section>

        <section>
            <h2><span class="sec-num">04</span> VULNERABILITIES</h2>
            <div class="card">
                <p style='color:#00E5FF;font-weight:bold;margin-bottom:15px;'>Total Vulnerabilities Found: <span style='font-size:18px;'>{len(d['vulnerabilities'])}</span></p>
                <table>
                    <thead>
                        <tr>
                            <th>Vulnerability Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {vuln_rows if vuln_rows else '<tr><td style="color:#94A3B8">No vulnerabilities found</td></tr>'}
                    </tbody>
                </table>
                <p style='margin-top:15px;color:#94A3B8;font-size:12px;'><em>Displaying all {len(d['vulnerabilities'])} vulnerabilities identified during scan</em></p>
            </div>
        </section>

        <section>
            <h2><span class="sec-num">05</span> REMEDIATION RECOMMENDATIONS</h2>
            <div class="card">
                <h3>Priority Actions</h3>
                <ul>
                    <li>Remediate all CRITICAL vulnerabilities within 24 hours</li>
                    <li>Address HIGH severity findings within 7 days</li>
                    <li>Plan remediation for MEDIUM findings within 30 days</li>
                    <li>Monitor and patch LOW severity issues during regular maintenance windows</li>
                    {f"<li><strong>Target:</strong> {tgt}</li>" if tgt else ""}
                </ul>
            </div>
        </section>

        <footer>
            <p>DanishRecon Penetration Test Report | Scan #{self.scan_id}</p>
            <p>FOR AUTHORIZED PENETRATION TESTING ONLY | DO NOT DISTRIBUTE</p>
            <p>Generated on {generated}</p>
        </footer>
    </div>
</body>
</html>"""
        
        path = os.path.join(RESULTS_DIR, f"report_{self.scan_id}_export.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path
    
    def export_pdf(self):
        """Export as PDF report"""
        if not REPORTLAB_AVAILABLE:
            raise Exception("ReportLab not installed. Install with: pip install reportlab")
        
        d = self.data
        path = os.path.join(RESULTS_DIR, f"report_{self.scan_id}_export.pdf")
        
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        
        doc = SimpleDocTemplate(path, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        elements = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        styles.add(ParagraphStyle(
            name='CustomTitle', parent=styles['Heading1'],
            fontSize=24, textColor=colors.HexColor('#00E5FF'),
            spaceAfter=30, alignment=TA_CENTER
        ))
        styles.add(ParagraphStyle(
            name='CustomHeading', parent=styles['Heading2'],
            fontSize=16, textColor=colors.HexColor('#00E5FF'),
            spaceAfter=12, spaceBefore=12
        ))
        
        # Title
        elements.append(Paragraph("DanishRecon Penetration Test Report", styles['CustomTitle']))
        elements.append(Spacer(1, 0.3 * inch))
        
        # Metadata
        meta_data = [
            ["Target:", d['target']],
            ["Profile:", d['profile']],
            ["Started:", d['started_at']],
            ["Ended:", d['ended_at'] or 'In progress'],
            ["Duration:", d['duration']],
            ["Scan ID:", f"#{self.scan_id}"],
        ]
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#111827')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#1E293B')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#0C1220'), colors.HexColor('#111827')]),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 0.3 * inch))
        
        # Summary
        elements.append(Paragraph("Summary", styles['CustomHeading']))
        summary_data = [
            ["Hosts", str(len(d['hosts']))],
            ["Services", str(len(d['services']))],
            ["CRITICAL", str(d['risk_counts']['CRITICAL'])],
            ["HIGH", str(d['risk_counts']['HIGH'])],
            ["MEDIUM", str(d['risk_counts']['MEDIUM'])],
            ["LOW", str(d['risk_counts']['LOW'])],
        ]
        summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#111827')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#1E293B')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.2 * inch))
        
        # Vulnerabilities
        elements.append(Paragraph("Vulnerabilities", styles['CustomHeading']))
        if d['vulnerabilities']:
            # Show ALL vulnerabilities in PDF export
            vuln_list = "<br/>".join(f"• {v}" for v in d['vulnerabilities'])  # NO LIMIT
            elements.append(Paragraph(vuln_list, styles['Normal']))
            elements.append(Paragraph(f"<i>Total: {len(d['vulnerabilities'])} vulnerabilities</i>", styles['Normal']))
        else:
            elements.append(Paragraph("No vulnerabilities found", styles['Normal']))
        
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(f"<i>Report generated {d['generated_at']}</i>", styles['Normal']))
        
        # Build PDF
        doc.build(elements)
        return path


# 
#  SCAN HISTORY DIALOG
# 
class HistoryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        t = Theme.current
        self.setWindowTitle("Scan History")
        self.resize(900, 500)
        self.setStyleSheet(build_stylesheet(t))
        lay = QVBoxLayout(self)

        lbl = QLabel("  SCAN HISTORY & EXPORT")
        lbl.setStyleSheet(f"color:{t['CYAN']};font-size:11px;font-weight:bold;letter-spacing:2px;padding:4px 0;")
        lay.addWidget(lbl)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID","TARGET","PROFILE","STARTED","FINISHED","STATUS"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        lay.addWidget(self.table)

        # Export format selection
        export_layout = QHBoxLayout()
        export_label = QLabel("Export Selected Scan As:")
        export_label.setStyleSheet(f"color:{t['TEXT']};font-size:10px;padding:5px 0;")
        export_layout.addWidget(export_label)
        
        self.format_combo = QComboBox()
        self.format_combo.addItems(["HTML", "JSON", "CSV", "Markdown"])
        if REPORTLAB_AVAILABLE:
            self.format_combo.addItem("PDF")
        self.format_combo.setStyleSheet(f"background:{t['CARD']};color:{t['TEXT']};border:1px solid {t['BORDER']};padding:4px;")
        export_layout.addWidget(self.format_combo)
        
        export_btn = QPushButton("  Export")
        export_btn.clicked.connect(self._export_selected)
        export_layout.addWidget(export_btn)
        export_layout.addStretch()
        lay.addLayout(export_layout)

        btn_box = QHBoxLayout()
        compare_btn = QPushButton(" Compare Scans (select 2)")
        compare_btn.clicked.connect(self._compare_selected)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_box.addWidget(compare_btn)
        btn_box.addStretch()
        btn_box.addWidget(close_btn)
        lay.addLayout(btn_box)

        self._load()

    def _load(self):
        rows = DB.get_all_scans()
        self.table.setRowCount(len(rows))
        status_colors = {"complete": "#10B981", "running": "#F59E0B", "failed": "#EF4444"}
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                item = QTableWidgetItem(str(val or ""))
                if c == 5:
                    item.setForeground(QColor(status_colors.get(str(val),"#94A3B8")))
                self.table.setItem(r, c, item)
    
    def _export_selected(self):
        """Export selected scan in chosen format"""
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "Selection Error", "Please select a scan to export.")
            return
        
        scan_id = int(self.table.item(selected[0].row(), 0).text())
        format_type = self.format_combo.currentText().upper()
        
        try:
            exporter = HistoryScanExporter(scan_id)
            
            if format_type == "HTML":
                path = exporter.export_html()
            elif format_type == "JSON":
                path = exporter.export_json()
            elif format_type == "CSV":
                path = exporter.export_csv()
            elif format_type == "MARKDOWN":
                path = exporter.export_markdown()
            elif format_type == "PDF":
                path = exporter.export_pdf()
            else:
                path = None
            
            if path:
                QMessageBox.information(self, "Export Successful", 
                    f"Report exported to:\n{path}\n\nFile will open in a moment...")
                # Open the exported file
                if format_type == "HTML" or format_type == "PDF":
                    import webbrowser
                    try:
                        if format_type == "HTML":
                            webbrowser.open(path)
                    except:
                        pass
            else:
                QMessageBox.warning(self, "Export Failed", "Failed to export scan report.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error exporting scan:\n{str(e)}")
    
    def _compare_selected(self):
        """Open comparison dialog for selected scans"""
        t = Theme.current
        selected = self.table.selectionModel().selectedRows()
        if len(selected) != 2:
            QMessageBox.warning(self, "Selection Error",
                                "Please select exactly 2 scans to compare.\n\nClick one row, hold Ctrl, then click another row.")
            return
        
        # Get scan IDs from selected rows
        scan1_id = int(self.table.item(selected[0].row(), 0).text())
        scan2_id = int(self.table.item(selected[1].row(), 0).text())
        
        # Reset to single selection mode for comparison
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.clearSelection()
        
        # Open comparison dialog
        dlg = ScanComparisonDialog(scan1_id, scan2_id, self)
        dlg.exec_()


class ScanComparisonDialog(QDialog):
    """Dialog to compare two scans side-by-side"""
    def __init__(self, scan1_id, scan2_id, parent=None):
        super().__init__(parent)
        self.scan1_id = scan1_id
        self.scan2_id = scan2_id
        
        t = Theme.current
        self.setWindowTitle("Scan Comparison")
        self.resize(1200, 700)
        self.setStyleSheet(build_stylesheet(t))
        
        # Load scan data
        self.scan1 = DB.get_scan_data(scan1_id)
        self.scan2 = DB.get_scan_data(scan2_id)
        
        self._build_ui()
        self._compare_scans()
    
    def _build_ui(self):
        t = Theme.current
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Title
        title = QLabel(" SCAN COMPARISON")
        title.setStyleSheet(f"color:{t['CYAN']};font-size:14px;font-weight:bold;letter-spacing:2px;padding:8px;")
        layout.addWidget(title)
        
        # Scan info header
        info_layout = QHBoxLayout()
        
        scan1_info = self.scan1['scan_info']
        scan2_info = self.scan2['scan_info']
        
        info1 = QLabel(f"<b>Scan #{scan1_info[0]}</b><br>"
                       f"Target: {scan1_info[1]}<br>"
                       f"Date: {scan1_info[3][:16] if scan1_info[3] else 'N/A'}")
        info1.setStyleSheet(f"color:{t['TEXT']};background:{t['CARD']};padding:10px;border-radius:5px;border:1px solid {t['BORDER']};")
        
        vs_label = QLabel("<center><b>VS</b></center>")
        vs_label.setStyleSheet(f"color:{t['CYAN']};font-size:16px;padding:10px;")
        
        info2 = QLabel(f"<b>Scan #{scan2_info[0]}</b><br>"
                       f"Target: {scan2_info[1]}<br>"
                       f"Date: {scan2_info[3][:16] if scan2_info[3] else 'N/A'}")
        info2.setStyleSheet(f"color:{t['TEXT']};background:{t['CARD']};padding:10px;border-radius:5px;border:1px solid {t['BORDER']};")
        
        info_layout.addWidget(info1)
        info_layout.addWidget(vs_label)
        info_layout.addWidget(info2)
        layout.addLayout(info_layout)
        
        # Tabs for different comparisons
        tabs = QTabWidget()
        tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {t['BORDER']};
                background: {t['CARD']};
            }}
            QTabBar::tab {{
                background: {t['CARD2']};
                color: {t['TEXT2']};
                padding: 8px 16px;
                border: 1px solid {t['BORDER']};
                border-bottom: none;
            }}
            QTabBar::tab:selected {{
                background: {t['CYAN']};
                color: {t['BG']};
                font-weight: bold;
            }}
        """)
        
        # Summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet(f"background:{t['CONSOLE_BG']};color:{t['TEXT']};font-family:monospace;font-size:10px;border:1px solid {t['BORDER']};")
        tabs.addTab(self.summary_text, "Summary")
        
        # Services tab
        self.services_text = QTextEdit()
        self.services_text.setReadOnly(True)
        self.services_text.setStyleSheet(f"background:{t['CONSOLE_BG']};color:{t['TEXT']};font-family:monospace;font-size:10px;border:1px solid {t['BORDER']};")
        tabs.addTab(self.services_text, "Services")
        
        # Vulnerabilities tab
        self.vulns_text = QTextEdit()
        self.vulns_text.setReadOnly(True)
        self.vulns_text.setStyleSheet(f"background:{t['CONSOLE_BG']};color:{t['TEXT']};font-family:monospace;font-size:10px;border:1px solid {t['BORDER']};")
        tabs.addTab(self.vulns_text, "Vulnerabilities")
        
        # Hosts tab
        self.hosts_text = QTextEdit()
        self.hosts_text.setReadOnly(True)
        self.hosts_text.setStyleSheet(f"background:{t['CONSOLE_BG']};color:{t['TEXT']};font-family:monospace;font-size:10px;border:1px solid {t['BORDER']};")
        tabs.addTab(self.hosts_text, "Hosts")
        
        layout.addWidget(tabs)
        
        # Legend
        legend = QLabel("""
            <b>Legend:</b> 
            <span style='color:#10B981'> NEW</span> | 
            <span style='color:#EF4444'> REMOVED</span> | 
            <span style='color:#F59E0B'> CHANGED</span> | 
            <span style='color:#00E5FF'> UNCHANGED</span>
        """)
        legend.setStyleSheet(f"color:{t['TEXT2']};padding:8px;background:{t['CARD2']};border-radius:4px;")
        layout.addWidget(legend)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        close_btn.setFixedWidth(100)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)
    
    def _compare_scans(self):
        """Compare the two scans and display differences"""
        
        # Compare hosts
        hosts1 = set(h[0] for h in self.scan1['hosts'])  # address
        hosts2 = set(h[0] for h in self.scan2['hosts'])
        
        new_hosts = hosts2 - hosts1
        removed_hosts = hosts1 - hosts2
        common_hosts = hosts1 & hosts2
        
        # Compare services (port + service name)
        services1 = {f"{s[0]}:{s[1]}/{s[2]} {s[3]}" for s in self.scan1['services']}  # host:port/proto service
        services2 = {f"{s[0]}:{s[1]}/{s[2]} {s[3]}" for s in self.scan2['services']}
        
        new_services = services2 - services1
        removed_services = services1 - services2
        common_services = services1 & services2
        
        # Compare service versions
        services1_dict = {f"{s[0]}:{s[1]}/{s[2]} {s[3]}": s[4] for s in self.scan1['services']}  # key: version
        services2_dict = {f"{s[0]}:{s[1]}/{s[2]} {s[3]}": s[4] for s in self.scan2['services']}
        
        version_changes = []
        for svc in common_services:
            v1 = services1_dict.get(svc, "")
            v2 = services2_dict.get(svc, "")
            if v1 != v2:
                version_changes.append((svc, v1, v2))
        
        # Compare vulnerabilities
        vulns1 = {f"{v[0]}:{v[1]} {v[4]}" for v in self.scan1['vulns']}  # host:service CVE
        vulns2 = {f"{v[0]}:{v[1]} {v[4]}" for v in self.scan2['vulns']}
        
        new_vulns = vulns2 - vulns1
        fixed_vulns = vulns1 - vulns2
        
        # Get critical new vulnerabilities
        critical_new_vulns = []
        for v in self.scan2['vulns']:
            vuln_key = f"{v[0]}:{v[1]} {v[4]}"
            if vuln_key in new_vulns and v[3] == 'CRITICAL':
                critical_new_vulns.append(v)
        
        # Build summary
        summary_html = f"""
<b> SCAN COMPARISON SUMMARY </b>

<b>Hosts:</b>
  Total in Scan 1: {len(hosts1)}
  Total in Scan 2: {len(hosts2)}
  <span style='color:#10B981'> New hosts: {len(new_hosts)}</span>
  <span style='color:#EF4444'> Removed hosts: {len(removed_hosts)}</span>
  <span style='color:#00E5FF'> Unchanged: {len(common_hosts)}</span>

<b>Services:</b>
  Total in Scan 1: {len(services1)}
  Total in Scan 2: {len(services2)}
  <span style='color:#10B981'> New services: {len(new_services)}</span>
  <span style='color:#EF4444'> Removed services: {len(removed_services)}</span>
  <span style='color:#F59E0B'> Version changes: {len(version_changes)}</span>
  <span style='color:#00E5FF'> Unchanged: {len(common_services) - len(version_changes)}</span>

<b>Vulnerabilities:</b>
  Total in Scan 1: {len(vulns1)}
  Total in Scan 2: {len(vulns2)}
  <span style='color:#10B981'> New vulnerabilities: {len(new_vulns)}</span>
  <span style='color:#EF4444'> Fixed vulnerabilities: {len(fixed_vulns)}</span>
  <span style='color:#FF0000;font-weight:bold'> CRITICAL new vulnerabilities: {len(critical_new_vulns)}</span>

<b>Change Score:</b>
  {self._calculate_change_score(len(new_hosts), len(removed_hosts), len(new_services), len(removed_services), len(version_changes), len(new_vulns))}
        """
        
        self.summary_text.setHtml(summary_html)
        
        # Build services comparison
        services_html = "<b> SERVICES COMPARISON </b>\n\n"
        
        if new_services:
            services_html += "<b><span style='color:#10B981'> NEW SERVICES:</span></b>\n"
            for svc in sorted(new_services):
                services_html += f"  <span style='color:#10B981'>+ {svc}</span>\n"
            services_html += "\n"
        
        if removed_services:
            services_html += "<b><span style='color:#EF4444'> REMOVED SERVICES:</span></b>\n"
            for svc in sorted(removed_services):
                services_html += f"  <span style='color:#EF4444'>- {svc}</span>\n"
            services_html += "\n"
        
        if version_changes:
            services_html += "<b><span style='color:#F59E0B'> VERSION CHANGES:</span></b>\n"
            for svc, v1, v2 in sorted(version_changes):
                services_html += f"  <span style='color:#F59E0B'> {svc}\n    From: {v1 or 'unknown'}\n    To:   {v2 or 'unknown'}</span>\n"
            services_html += "\n"
        
        if not new_services and not removed_services and not version_changes:
            services_html += "<span style='color:#10B981'>No service changes detected.</span>\n"
        
        self.services_text.setHtml(services_html)
        
        # Build vulnerabilities comparison
        vulns_html = "<b> VULNERABILITIES COMPARISON </b>\n\n"
        
        if critical_new_vulns:
            vulns_html += "<b><span style='color:#FF0000'> CRITICAL NEW VULNERABILITIES:</span></b>\n"
            for v in critical_new_vulns:
                vulns_html += f"  <span style='color:#FF0000'> [{v[4]}] {v[6]} (CVSS: {v[5]})\n    Host: {v[0]} | Service: {v[1]}:{v[2]}</span>\n\n"
        
        if new_vulns:
            vulns_html += f"<b><span style='color:#10B981'> NEW VULNERABILITIES ({len(new_vulns)}):</span></b>\n"
            for v in sorted(new_vulns):
                vulns_html += f"  <span style='color:#10B981'>+ {v}</span>\n"
            vulns_html += "\n"
        
        if fixed_vulns:
            vulns_html += f"<b><span style='color:#10B981'> FIXED VULNERABILITIES ({len(fixed_vulns)}):</span></b>\n"
            for v in sorted(fixed_vulns):
                vulns_html += f"  <span style='color:#10B981'> {v}</span>\n"
            vulns_html += "\n"
        
        if not new_vulns and not fixed_vulns:
            vulns_html += "<span style='color:#00E5FF'>No vulnerability changes detected.</span>\n"
        
        self.vulns_text.setHtml(vulns_html)
        
        # Build hosts comparison
        hosts_html = "<b> HOSTS COMPARISON </b>\n\n"
        
        if new_hosts:
            hosts_html += "<b><span style='color:#10B981'> NEW HOSTS:</span></b>\n"
            for h in sorted(new_hosts):
                hosts_html += f"  <span style='color:#10B981'>+ {h}</span>\n"
            hosts_html += "\n"
        
        if removed_hosts:
            hosts_html += "<b><span style='color:#EF4444'> REMOVED/OFFLINE HOSTS:</span></b>\n"
            for h in sorted(removed_hosts):
                hosts_html += f"  <span style='color:#EF4444'>- {h}</span>\n"
            hosts_html += "\n"
        
        if common_hosts:
            hosts_html += f"<b><span style='color:#00E5FF'> UNCHANGED HOSTS ({len(common_hosts)}):</span></b>\n"
            for h in sorted(list(common_hosts)[:10]):  # Show first 10
                hosts_html += f"  <span style='color:#00E5FF'> {h}</span>\n"
            if len(common_hosts) > 10:
                hosts_html += f"  <span style='color:#94A3B8'>... and {len(common_hosts) - 10} more</span>\n"
        
        self.hosts_text.setHtml(hosts_html)
    
    def _calculate_change_score(self, new_hosts, removed_hosts, new_services, removed_services, version_changes, new_vulns):
        """Calculate and return a change score description"""
        total_changes = new_hosts + removed_hosts + new_services + removed_services + version_changes + new_vulns
        
        if total_changes == 0:
            return "<span style='color:#10B981'>Minimal changes - Environment stable</span>"
        elif total_changes < 5:
            return f"<span style='color:#00E5FF'>Low change activity ({total_changes} changes)</span>"
        elif total_changes < 15:
            return f"<span style='color:#F59E0B'>Moderate change activity ({total_changes} changes)</span>"
        else:
            return f"<span style='color:#EF4444'>High change activity ({total_changes} changes) - Review recommended</span>"


class AppPinDialog(QDialog):
    def __init__(self, setup_mode=False, attempts_left=3, parent=None):
        super().__init__(parent)
        self.setup_mode = setup_mode
        self.pin_value = ""

        self.setWindowTitle("Set App PIN" if setup_mode else "Unlock DanishRecon")
        self.setModal(True)
        self.setFixedSize(420, 230 if setup_mode else 200)

        layout = QVBoxLayout(self)
        message = (
            "Create a 4-12 digit PIN to protect GUI access."
            if setup_mode
            else f"Enter PIN to open GUI. Attempts left: {attempts_left}"
        )
        info = QLabel(message)
        info.setWordWrap(True)
        layout.addWidget(info)

        self.pin_input = QLineEdit()
        self.pin_input.setPlaceholderText("PIN")
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.setMaxLength(12)
        layout.addWidget(self.pin_input)

        self.confirm_input = None
        if setup_mode:
            self.confirm_input = QLineEdit()
            self.confirm_input.setPlaceholderText("Confirm PIN")
            self.confirm_input.setEchoMode(QLineEdit.Password)
            self.confirm_input.setMaxLength(12)
            layout.addWidget(self.confirm_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _validate(self):
        pin = self.pin_input.text().strip()
        if not (4 <= len(pin) <= 12 and pin.isdigit()):
            QMessageBox.warning(self, "Invalid PIN", "PIN must be 4-12 digits.")
            return

        if self.setup_mode:
            confirm = self.confirm_input.text().strip() if self.confirm_input else ""
            if pin != confirm:
                QMessageBox.warning(self, "Mismatch", "PIN and confirmation must match.")
                return

        self.pin_value = pin
        self.accept()


def _hash_pin(pin: str, salt_hex: str = None):
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, PIN_HASH_ITERATIONS)
    return salt.hex(), digest.hex()


def _load_pin_config():
    if not os.path.exists(PIN_CONFIG_PATH):
        return None
    try:
        with open(PIN_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if "salt" in cfg and "pin_hash" in cfg:
            return cfg
    except Exception:
        pass
    return None


def _save_pin_config(pin: str):
    salt_hex, pin_hash = _hash_pin(pin)
    data = {
        "salt": salt_hex,
        "pin_hash": pin_hash,
        "algo": "pbkdf2_sha256",
        "iterations": PIN_HASH_ITERATIONS,
    }
    with open(PIN_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _verify_pin(pin: str, cfg: dict):
    salt_hex = cfg.get("salt", "")
    expected_hash = cfg.get("pin_hash", "")
    if not salt_hex or not expected_hash:
        return False
    _, computed_hash = _hash_pin(pin, salt_hex)
    return hmac.compare_digest(computed_hash, expected_hash)


def _env_is_enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _parse_twilio_recipients(raw_text: str):
    parts = re.split(r"[,;\n\r]+", raw_text or "")
    recipients = []
    seen = set()
    for part in parts:
        value = part.strip()
        if not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        recipients.append(value)
    return recipients


def _normalize_whatsapp_number(value: str):
    cleaned = (value or "").strip()
    if not cleaned:
        return ""
    if not cleaned.lower().startswith("whatsapp:"):
        cleaned = f"whatsapp:{cleaned}"
    return cleaned


def _is_valid_whatsapp_number(value: str) -> bool:
    # Expected format: whatsapp:+<countrycode><number>
    # Phone numbers are typically 10-15 digits
    return bool(re.fullmatch(r"whatsapp:\+\d{10,15}", value or ""))


def _get_twilio_login_alert_config():
    if not _env_is_enabled(TWILIO_ENABLED_ENV):
        return None, "disabled"

    to_numbers = _parse_twilio_recipients(os.getenv(TWILIO_WHATSAPP_TO_ENV, ""))
    from_number = _normalize_whatsapp_number(os.getenv(TWILIO_WHATSAPP_FROM_ENV, ""))
    normalized_to_numbers = [_normalize_whatsapp_number(v) for v in to_numbers]

    cfg = {
        "account_sid": os.getenv(TWILIO_ACCOUNT_SID_ENV, "").strip(),
        "auth_token": os.getenv(TWILIO_AUTH_TOKEN_ENV, "").strip(),
        "from_number": from_number,
        "to_numbers": normalized_to_numbers,
    }
    missing = [key for key in ("account_sid", "auth_token", "from_number") if not cfg[key]]
    if not cfg["to_numbers"]:
        missing.append("to_numbers")
    if missing:
        return None, f"missing env vars: {', '.join(missing)}"

    if not re.fullmatch(r"AC[a-fA-F0-9]{32}", cfg["account_sid"]):
        return None, "invalid account_sid format"
    if not _is_valid_whatsapp_number(cfg["from_number"]):
        return None, "invalid from_number format (expected whatsapp:+E164)"

    invalid_recipients = [num for num in cfg["to_numbers"] if not _is_valid_whatsapp_number(num)]
    if invalid_recipients:
        return None, "invalid to_numbers format (expected whatsapp:+E164)"

    return cfg, None


def _parse_twilio_error_response(response):
    try:
        payload = response.json()
    except Exception:
        text_preview = (response.text or "").strip()
        if len(text_preview) > 220:
            text_preview = text_preview[:220] + "..."
        return {
            "status": response.status_code,
            "code": "unknown",
            "message": text_preview or "No response body",
            "more_info": "",
        }

    return {
        "status": response.status_code,
        "code": payload.get("code", "unknown"),
        "message": payload.get("message", "Unknown Twilio error"),
        "more_info": payload.get("more_info", ""),
    }


def _resolve_windows_precise_location():
    if platform.system().lower() != "windows":
        return None

    ps_script = r'''
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
    [void][Windows.Devices.Geolocation.Geolocator, Windows.Devices.Geolocation, ContentType = WindowsRuntime]
    $geo = New-Object Windows.Devices.Geolocation.Geolocator
    $geo.DesiredAccuracy = [Windows.Devices.Geolocation.PositionAccuracy]::High
    $pos = $geo.GetGeopositionAsync().AsTask().GetAwaiter().GetResult()
    $p = $pos.Coordinate.Point.Position
    $a = $pos.Coordinate.Accuracy
    $json = @{ lat = $p.Latitude; lon = $p.Longitude; accuracy_m = $a } | ConvertTo-Json -Compress
    Write-Output $json
} catch {
    exit 1
}
'''

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        payload = json.loads(result.stdout.strip())
        lat = payload.get("lat")
        lon = payload.get("lon")
        if lat is None or lon is None:
            return None
        return {
            "lat": float(lat),
            "lon": float(lon),
            "accuracy_m": payload.get("accuracy_m"),
            "source": "windows-location",
        }
    except Exception:
        return None


def _reverse_geocode(lat, lon):
    try:
        resp = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "jsonv2"},
            headers={"User-Agent": "DanishRecon/1.0"},
            timeout=6,
        )
        resp.raise_for_status()
        payload = resp.json()
        addr = payload.get("address", {})
        city = addr.get("city") or addr.get("town") or addr.get("village") or "unknown"
        region = addr.get("state") or addr.get("county") or "unknown"
        country = addr.get("country") or "unknown"
        return city, region, country
    except Exception:
        return "unknown", "unknown", "unknown"


def _resolve_login_location():
    # HARDCODED: NIT Jalandhar, Punjab, India (precise campus coordinates)
    # Coordinates: 31.396778°N, 75.534861°E
    location = {
        "public_ip": "unknown",
        "local_ip": "unknown",
        "city": "Jalandhar",
        "region": "Punjab",
        "country": "India",
        "lat": 31.396778,
        "lon": 75.534861,
        "accuracy_m": 10,  # ~10 meters (GPS-level accuracy)
        "source": "hardcoded-nit-jalandhar",
    }

    try:
        location["local_ip"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        pass

    return location


def _send_twilio_whatsapp_login_alert():
    cfg, reason = _get_twilio_login_alert_config()
    if cfg is None:
        print(f"[Startup Alert] Twilio WhatsApp login alert skipped: {reason}")
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host_name = socket.gethostname()
    user_name = getpass.getuser()
    location = _resolve_login_location()
    coords = (
        f"{location['lat']}, {location['lon']}"
        if location["lat"] is not None and location["lon"] is not None
        else "unknown"
    )
    map_query = (
        coords
        if coords != "unknown"
        else f"{location['city']}, {location['region']}, {location['country']}"
    )
    map_url = f"https://maps.google.com/?q={urllib.parse.quote_plus(map_query)}"
    accuracy_text = (
        f"{location['accuracy_m']:.0f} m"
        if isinstance(location.get("accuracy_m"), (int, float))
        else "unknown"
    )
    precision_text = (
        "Exact (device location)"
        if location.get("source") == "windows-location"
        else "Approximate (IP-based)"
    )
    body = (
        "DanishRecon GUI login detected.\n"
        f"User: {user_name}\n"
        f"Host: {host_name}\n"
        f"OS: {platform.system()} {platform.release()}\n"
        f"Time: {now}\n"
        f"Public IP: {location['public_ip']}\n"
        f"Local IP: {location['local_ip']}\n"
        f"Location: {location['city']}, {location['region']}, {location['country']}\n"
        f"Coordinates: {coords}\n"
        f"Accuracy: {accuracy_text}\n"
        f"Precision: {precision_text}\n"
        f"Google Maps: {map_url}"
    )

    sent_count = 0
    failed_count = 0
    for to_number in cfg["to_numbers"]:
        try:
            payload = {
                "From": cfg["from_number"],
                "To": to_number,
                "Body": body,
            }

            response = requests.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{cfg['account_sid']}/Messages.json",
                auth=(cfg["account_sid"], cfg["auth_token"]),
                data=payload,
                timeout=15,
            )
            response.raise_for_status()
            response_payload = response.json()
            print(
                f"[Startup Alert] Twilio WhatsApp login alert sent to {to_number}: "
                f"SID={response_payload.get('sid', 'unknown')}"
            )
            sent_count += 1
        except requests.exceptions.HTTPError:
            err = _parse_twilio_error_response(response)
            print(
                f"[Startup Alert] Twilio WhatsApp login alert failed for {to_number}: "
                f"HTTP {err['status']} | Twilio code={err['code']} | {err['message']}"
            )
            if err["more_info"]:
                print(f"[Startup Alert] Twilio docs: {err['more_info']}")
            failed_count += 1
        except Exception as exc:
            print(f"[Startup Alert] Twilio WhatsApp login alert failed for {to_number}: {exc}")
            failed_count += 1

    print(
        f"[Startup Alert] Twilio WhatsApp summary: sent={sent_count}, failed={failed_count}, "
        f"total={len(cfg['to_numbers'])}"
    )


def start_gui_login_alert_async():
    threading.Thread(target=_send_twilio_whatsapp_login_alert, daemon=True).start()


def enforce_app_pin(parent=None):
    cfg = _load_pin_config()
    if cfg is None:
        QMessageBox.information(parent, "PIN Setup", "Set a PIN to protect DanishRecon GUI access.")
        setup = AppPinDialog(setup_mode=True, parent=parent)
        if setup.exec_() != QDialog.Accepted:
            return False
        try:
            _save_pin_config(setup.pin_value)
        except Exception as e:
            QMessageBox.critical(parent, "PIN Setup Failed", f"Could not save PIN: {e}")
            return False
        QMessageBox.information(parent, "PIN Enabled", "App PIN lock is enabled.")
        return True

    for attempt in range(3):
        attempts_left = 3 - attempt
        unlock = AppPinDialog(setup_mode=False, attempts_left=attempts_left, parent=parent)
        if unlock.exec_() != QDialog.Accepted:
            return False
        if _verify_pin(unlock.pin_value, cfg):
            return True
        if attempts_left > 1:
            QMessageBox.warning(parent, "Wrong PIN", f"Incorrect PIN. Attempts left: {attempts_left - 1}")

    QMessageBox.critical(parent, "Access Denied", "Too many failed attempts. App will close.")
    return False


# 
#  MAIN WINDOW
# 
class PreflightDialog(QDialog):
    """First-run System Check: shows tool/package/config readiness with install hints."""

    def __init__(self, report, parent=None):
        super().__init__(parent)
        self.setWindowTitle("DanishRecon - System Check")
        self.setMinimumWidth(640)
        lay = QVBoxLayout(self)

        status = report.get("status", "ready")
        banner = {
            "ready":     ("All core components present - you're ready to scan.", "#1e7e34"),
            "degraded":  ("Runs, but some core features are disabled.",          "#b8860b"),
            "not_ready": ("Missing CRITICAL components - install them to scan.",  "#b02a37"),
        }.get(status, ("System check complete.", "#555"))
        head = QLabel(f"<b>{status.upper()}</b> - {banner[0]}")
        head.setStyleSheet(f"color:{banner[1]}; font-size:14px; padding:6px;")
        head.setWordWrap(True)
        lay.addWidget(head)

        checks = report.get("checks", [])
        table = QTableWidget(len(checks), 4)
        table.setHorizontalHeaderLabels(["Status", "Component", "Severity", "Detail / Fix"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        for row, c in enumerate(checks):
            ok = c["ok"]
            cells = [
                "OK" if ok else "MISS",
                c["name"],
                c["severity"],
                (c.get("version") or c.get("path") or "") if ok
                else f"{c['purpose']}  ->  {c['hint']}",
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(str(text))
                if col == 0:
                    item.setForeground(QColor("#1e7e34") if ok else QColor("#b02a37"))
                table.setItem(row, col, item)
        table.resizeColumnsToContents()
        lay.addWidget(table)

        row = QHBoxLayout()
        close = QPushButton("Continue")
        close.clicked.connect(self.accept)
        row.addStretch(1); row.addWidget(close)
        lay.addLayout(row)


class DanishReconMain(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DanishRecon    Advanced Vulnerability Analysis Platform")
        self.setMinimumSize(1180, 700)      # fits a 1366x768 laptop screen
        self.resize(1500, 900)
        self.scan_thread = None
        self.scan_data   = None
        self._theme_dark = True
        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._blink_indicator)
        self._blink_on = False
        
        # Notification tracking
        self.critical_findings = []
        self.high_findings = []
        self.sound_enabled = True  # Toggle for sound alerts
        
        # System tray icon for notifications
        self.tray_icon = None
        self._setup_tray_icon()

        self._preflight = None
        self._apply_theme()
        self._build_ui()
        self._setup_shortcuts()
        self._verify_tools()
        self._run_preflight_check()

    def _run_preflight_check(self):
        """Run the system readiness check, log it, gate the scan button, and show the
        System Check dialog on first launch if anything is missing."""
        try:
            from danishrecon.preflight import run_preflight
            report = run_preflight()
        except Exception as _pf_err:
            self._preflight = None
            print(f"[preflight] check skipped: {_pf_err}")
            return
        self._preflight = report
        self._apply_preflight(report)
        try:
            if report.get("status") != "ready":
                PreflightDialog(report, self).exec_()
        except Exception as _dlg_err:
            print(f"[preflight] dialog skipped: {_dlg_err}")

    def _apply_preflight(self, report):
        """Log the preflight result and disable scanning if a CRITICAL item is missing."""
        s = report["summary"]
        status = report["status"]
        missing = [c for c in report["checks"] if not c["ok"]]

        def _log(msg, level):
            try:
                self._append_log(msg, level)
            except Exception:
                print(msg)

        _log(f"System check: {status.upper()} "
             f"({s['ok']}/{s['total']} ready, {s['missing_critical']} critical missing)", "stage")
        for c in missing:
            _log(f"  missing [{c['severity']}] {c['name']} - {c['hint']}", "warn")

        if s["missing_critical"] > 0:
            self.start_btn.setEnabled(False)
            self.start_btn.setText("  START SCAN (missing tools)")
            self.start_btn.setToolTip(
                "Cannot scan: install the CRITICAL items shown in the console, then restart. "
                "Run `python preflight.py` for details.")

    def _verify_tools(self):
        """Verify and log tool paths at startup for diagnostics"""
        print("\n" + "="*70)
        print("DanishRecon - Tool Path Diagnostics")
        print("="*70)
        print(f"Working Directory: {os.getcwd()}")
        print(f"Script Location: {os.path.dirname(os.path.abspath(__file__))}")
        print(f"\nTool Paths:")
        print(f"  NIKTO_PATH: {NIKTO_PATH}")
        print(f"    Exists: {bool(NIKTO_PATH) and os.path.exists(NIKTO_PATH)}")
        print(f"  EXPLOIT_DB_DIR: {EXPLOIT_DB_DIR}")
        print(f"    Exists: {os.path.exists(EXPLOIT_DB_DIR)}")
        print(f"  SEARCHSPLOIT_PS1: {SEARCHSPLOIT_PS1}")
        print(f"    Exists: {os.path.exists(SEARCHSPLOIT_PS1)}")
        print(f"  SEARCHSPLOIT_BAT: {SEARCHSPLOIT_BAT}")
        print(f"    Exists: {os.path.exists(SEARCHSPLOIT_BAT)}")
        print(f"  SEARCHSPLOIT_PATH (selected): {SEARCHSPLOIT_PATH}")
        print(f"    Exists: {bool(SEARCHSPLOIT_PATH) and os.path.exists(SEARCHSPLOIT_PATH)}")
        if SEARCHSPLOIT_PATH and os.path.exists(SEARCHSPLOIT_PATH):
            print(f"    File size: {os.path.getsize(SEARCHSPLOIT_PATH)} bytes")
        print(f"  RESULTS_DIR: {RESULTS_DIR}")
        print(f"    Exists: {os.path.exists(RESULTS_DIR)}")
        print(f"  DB_PATH: {DB_PATH}")
        print(f"    Exists: {os.path.exists(DB_PATH)}")
        twilio_cfg, twilio_reason = _get_twilio_login_alert_config()
        print(f"\n WhatsApp Login Alert:")
        print(f"  Enabled Env Flag: {_env_is_enabled(TWILIO_ENABLED_ENV)}")
        print(f"  Transport: Twilio REST API over HTTPS")
        if twilio_cfg:
            print(f"  Status: Ready")
            print(f"  From: {twilio_cfg['from_number']}")
            print(f"  Recipients: {', '.join(twilio_cfg['to_numbers'])}")
            print(f"  Recipient Count: {len(twilio_cfg['to_numbers'])}")
            print(f"  Message: Plain WhatsApp Body (login details)")
        else:
            print(f"  Status: Not Ready ({twilio_reason})")
        
        # Report the sound backend (no startup beep — just availability)
        print(f"\n Sound Alert System:")
        print(f"  Sound Enabled: {self.sound_enabled}")
        if platform.system() == "Windows":
            try:
                import winsound  # noqa: F401
                print(f"  Sound backend: winsound (Windows) - Available")
            except Exception as e:
                print(f"  Sound backend: winsound not available ({e})")
        else:
            print(f"  Sound backend: Qt QApplication.beep() ({platform.system()})")

        print("="*70 + "\n")
    
    def _setup_shortcuts(self):
        """Setup keyboard shortcuts for quick actions"""
        try:
            # Ctrl+N: New/Start scan
            shortcut_new = QShortcut(QKeySequence("Ctrl+N"), self)
            shortcut_new.activated.connect(self._start_scan)
            shortcut_new.setContext(Qt.ApplicationShortcut)
            
            # Ctrl+S: Stop scan
            shortcut_stop = QShortcut(QKeySequence("Ctrl+S"), self)
            shortcut_stop.activated.connect(self._stop_scan)
            shortcut_stop.setContext(Qt.ApplicationShortcut)
            
            # Ctrl+E: Export results
            shortcut_export = QShortcut(QKeySequence("Ctrl+E"), self)
            shortcut_export.activated.connect(self._show_export_menu)
            shortcut_export.setContext(Qt.ApplicationShortcut)
            
            # Ctrl+F: Search results
            shortcut_search = QShortcut(QKeySequence("Ctrl+F"), self)
            shortcut_search.activated.connect(self._show_search_dialog)
            shortcut_search.setContext(Qt.ApplicationShortcut)
            
            # Ctrl+R: Open report
            shortcut_report = QShortcut(QKeySequence("Ctrl+R"), self)
            shortcut_report.activated.connect(self._open_report)
            shortcut_report.setContext(Qt.ApplicationShortcut)
            
            # Ctrl+P: Pause/Resume scan (changed from Space to avoid conflicts)
            shortcut_pause = QShortcut(QKeySequence("Ctrl+P"), self)
            shortcut_pause.activated.connect(self._toggle_pause_resume)
            shortcut_pause.setContext(Qt.ApplicationShortcut)

            # Ctrl+Alt+P: Change app PIN
            shortcut_pin = QShortcut(QKeySequence("Ctrl+Alt+P"), self)
            shortcut_pin.activated.connect(self._change_app_pin)
            shortcut_pin.setContext(Qt.ApplicationShortcut)
            
            print(" Keyboard shortcuts loaded successfully")
            self.statusBar().showMessage("    Keyboard shortcuts: Ctrl+N=Scan Ctrl+S=Stop Ctrl+E=Export Ctrl+F=Search Ctrl+R=Report Ctrl+P=Pause Ctrl+Alt+P=PIN", 4000)
        except Exception as e:
            print(f" Error setting up shortcuts: {e}")
            self.statusBar().showMessage(f"    Shortcuts error: {e}", 5000)
    
    def _show_search_dialog(self):
        """Show search dialog to filter results"""
        if not self.scan_data:
            self.statusBar().showMessage("    No scan data to search. Run a scan first.")
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Search Results")
        dialog.setMinimumWidth(700)
        dialog.setMinimumHeight(500)
        
        t = Theme.current
        dialog.setStyleSheet(f"""
            QDialog {{
                background: {t['BG']};
                color: {t['TEXT']};
            }}
            QLineEdit {{
                background: {t['CARD']};
                color: {t['TEXT']};
                border: 1px solid {t['BORDER']};
                border-radius: 4px;
                padding: 8px;
                font-size: 11px;
            }}
            QTextEdit {{
                background: {t['CONSOLE_BG']};
                color: {t['TEXT']};
                border: 1px solid {t['BORDER']};
                border-radius: 4px;
                font-family: monospace;
                font-size: 10px;
            }}
            QPushButton {{
                background: {t['CARD']};
                color: {t['TEXT']};
                border: 1px solid {t['BORDER']};
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10px;
            }}
            QPushButton:hover {{
                background: {t['CARD2']};
                border-color: {t['CYAN']};
            }}
            QLabel {{
                color: {t['TEXT']};
                font-size: 11px;
            }}
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(10)
        
        # Search input
        search_layout = QHBoxLayout()
        search_label = QLabel(" Search:")
        search_input = QLineEdit()
        search_input.setPlaceholderText("Enter keyword to search in all results (services, vulns, exploits, etc.)")
        search_layout.addWidget(search_label)
        search_layout.addWidget(search_input)
        layout.addLayout(search_layout)
        
        # Filter options
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by:"))
        filter_critical = QCheckBox("Critical")
        filter_critical.setChecked(True)
        filter_high = QCheckBox("High")
        filter_high.setChecked(True)
        filter_medium = QCheckBox("Medium")
        filter_medium.setChecked(True)
        filter_low = QCheckBox("Low")
        filter_low.setChecked(True)
        filter_layout.addWidget(filter_critical)
        filter_layout.addWidget(filter_high)
        filter_layout.addWidget(filter_medium)
        filter_layout.addWidget(filter_low)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Results display
        results_text = QTextEdit()
        results_text.setReadOnly(True)
        layout.addWidget(results_text)
        
        # Stats label
        stats_label = QLabel("")
        stats_label.setStyleSheet(f"color:{t['TEXT2']};font-size:10px;")
        layout.addWidget(stats_label)
        
        def perform_search():
            query = search_input.text().strip().lower()
            if not query:
                results_text.setPlainText("Enter a search term to filter results.")
                return
            
            results_text.clear()
            count = 0
            
            # Search in all data
            results_text.append(f" SEARCH RESULTS FOR: '{query}' \n")
            
            # Hosts
            if any(query in str(h).lower() for h in self.scan_data.get('hosts', [])):
                results_text.append(f"\n HOSTS ")
                for host in self.scan_data.get('hosts', []):
                    if query in str(host).lower():
                        results_text.append(f"   {host}")
                        count += 1
            
            # Services
            if any(query in str(s).lower() for s in self.scan_data.get('services', [])):
                results_text.append(f"\n SERVICES ")
                for svc in self.scan_data.get('services', []):
                    if query in str(svc).lower():
                        results_text.append(f"   {svc}")
                        count += 1
            
            # Vulnerabilities (with severity filtering)
            vulns = self.scan_data.get('vulns', [])
            filtered_vulns = []
            for v in vulns:
                if query in str(v).lower():
                    risk = "CRITICAL" if "CRITICAL" in v.upper() else \
                           "HIGH" if "HIGH" in v.upper() else \
                           "MEDIUM" if "MEDIUM" in v.upper() else "LOW"
                    
                    if (risk == "CRITICAL" and filter_critical.isChecked()) or \
                       (risk == "HIGH" and filter_high.isChecked()) or \
                       (risk == "MEDIUM" and filter_medium.isChecked()) or \
                       (risk == "LOW" and filter_low.isChecked()):
                        filtered_vulns.append(v)
            
            if filtered_vulns:
                results_text.append(f"\n VULNERABILITIES ")
                for v in filtered_vulns:
                    results_text.append(f"  {v}")
                    count += 1
            
            # Exploits
            if any(query in str(e).lower() for e in self.scan_data.get('exploits', [])):
                results_text.append(f"\n EXPLOITS ")
                for exp in self.scan_data.get('exploits', []):
                    if query in str(exp).lower():
                        results_text.append(f"   {exp}")
                        count += 1
            
            # OS guesses
            if any(query in str(o).lower() for o in self.scan_data.get('os_guesses', [])):
                results_text.append(f"\n OS FINGERPRINTS ")
                for os_g in self.scan_data.get('os_guesses', []):
                    if query in str(os_g).lower():
                        results_text.append(f"   {os_g}")
                        count += 1
            
            stats_label.setText(f"Found {count} matching results")
            
            if count == 0:
                results_text.append(f"\nNo results found for '{query}'")
        
        # Connect search
        search_input.textChanged.connect(lambda: perform_search())
        for chk in [filter_critical, filter_high, filter_medium, filter_low]:
            chk.stateChanged.connect(perform_search)
        
        # Initial message
        results_text.setPlainText("Enter a search term above to filter scan results...")
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.exec_()
    
    def _toggle_pause_resume(self):
        """Toggle pause/resume for running scan"""
        if not self.scan_thread or not self.scan_thread.isRunning():
            self.statusBar().showMessage("    No active scan to pause/resume")
            return
        
        if self.scan_thread.is_paused():
            self.scan_thread.resume()
            self.statusBar().showMessage("    Scan resumed (press Ctrl+P to pause)")
            t = Theme.current
            self.status_pill.setText(" SCANNING")
            self.status_pill.setStyleSheet(
                f"color:{t['ORANGE']};font-size:10px;font-family:monospace;letter-spacing:1px;"
                f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
            self._set_live_indicator("live")
        else:
            self.scan_thread.pause()
            self.statusBar().showMessage("    Scan paused (press Ctrl+P to resume)")
            t = Theme.current
            self.status_pill.setText(" PAUSED")
            self.status_pill.setStyleSheet(
                f"color:{t['PURPLE']};font-size:10px;font-family:monospace;letter-spacing:1px;"
                f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
            self._set_live_indicator("paused")
    
    def _setup_tray_icon(self):
        """Setup system tray icon for notifications"""
        try:
            # Check if system tray is available
            if not QSystemTrayIcon.isSystemTrayAvailable():
                print(" System tray not available on this system")
                self.tray_icon = None
                return
            
            self.tray_icon = QSystemTrayIcon(self)
            # Create a simple icon (you can replace with actual icon file)
            icon_pixmap = QPixmap(16, 16)
            icon_pixmap.fill(QColor(0, 229, 255))  # Cyan color
            self.tray_icon.setIcon(QIcon(icon_pixmap))
            self.tray_icon.setToolTip("DanishRecon")
            
            # Tray menu
            tray_menu = QMenu()
            show_action = tray_menu.addAction("Show DanishRecon")
            show_action.triggered.connect(self.show)
            tray_menu.addSeparator()
            sound_action = tray_menu.addAction("Sound Alerts")
            sound_action.setCheckable(True)
            sound_action.setChecked(self.sound_enabled)
            sound_action.triggered.connect(self._toggle_sound)
            tray_menu.addSeparator()
            quit_action = tray_menu.addAction("Quit")
            quit_action.triggered.connect(QApplication.quit)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()
            
            # Connect double-click to show window
            self.tray_icon.activated.connect(self._tray_activated)
            
            print(" System tray icon initialized successfully")
        except Exception as e:
            print(f" Failed to create system tray icon: {e}")
            import traceback
            traceback.print_exc()
            self.tray_icon = None
    
    def _tray_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()
    
    def _toggle_sound(self, checked):
        """Toggle sound alerts on/off"""
        self.sound_enabled = checked
        status = "enabled" if checked else "disabled"
        self.statusBar().showMessage(f"    Sound alerts {status}")
    
    def _play_alert_sound(self, severity="critical"):
        """Play a system beep for alerts (cross-platform: winsound on Windows, Qt beep elsewhere)."""
        if not self.sound_enabled:
            return

        try:
            if platform.system() == "Windows":
                import winsound
                freq = 2000 if severity == "critical" else 1500
                dur = 300 if severity == "critical" else 200
                winsound.Beep(freq, dur)
            else:
                # macOS / Linux: Qt provides a portable system bell
                QApplication.beep()
        except Exception as e:
            print(f" alert sound failed ({e}) - falling back to Qt beep")
            try:
                QApplication.beep()
            except Exception:
                pass
    
    def _send_desktop_notification(self, title, message, severity="info"):
        """Send desktop notification via system tray or fallback to message box"""
        # Try system tray notification first
        if self.tray_icon and self.tray_icon.isVisible():
            try:
                icon = QSystemTrayIcon.Information
                if severity == "critical":
                    icon = QSystemTrayIcon.Critical
                elif severity == "warning":
                    icon = QSystemTrayIcon.Warning
                
                self.tray_icon.showMessage(title, message, icon, 5000)  # 5 seconds
                print(f" Desktop notification sent: {title}")
                return
            except Exception as e:
                print(f" Tray notification failed: {e}")
        
        # Fallback: Log to console and status bar
        print(f" NOTIFICATION: {title} - {message}")
        self.statusBar().showMessage(f"    {title}: {message}"[:100], 10000)
    
    def _show_scan_summary_dialog(self, data):
        """Show popup dialog with scan completion summary"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Scan Complete - Summary")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(400)
        
        t = Theme.current
        dialog.setStyleSheet(f"""
            QDialog {{
                background: {t['BG']};
                color: {t['TEXT']};
            }}
            QLabel {{
                color: {t['TEXT']};
                font-family: monospace;
            }}
            QPushButton {{
                background: {t['CARD']};
                color: {t['TEXT']};
                border: 1px solid {t['BORDER']};
                border-radius: 4px;
                padding: 8px 16px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background: {t['CARD2']};
                border-color: {t['CYAN']};
            }}
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        
        # Title
        title_label = QLabel(f" SCAN COMPLETED: {data.get('target', 'Unknown')}")
        title_label.setStyleSheet(f"color:{t['GREEN']};font-size:16px;font-weight:bold;")
        layout.addWidget(title_label)
        
        # Summary stats
        rc = data.get("risk_counts", {})
        stats_html = f"""
        <div style='background:{t['CARD']};padding:15px;border-radius:6px;border:1px solid {t['BORDER']};'>
            <p style='color:{t['TEXT2']};font-size:12px;margin:5px;'><b>Hosts Discovered:</b> {len(data.get('hosts', []))}</p>
            <p style='color:{t['TEXT2']};font-size:12px;margin:5px;'><b>Services Found:</b> {len(data.get('services', []))}</p>
            <p style='color:{t['TEXT2']};font-size:12px;margin:5px;'><b>Vulnerabilities:</b> {len(data.get('vulns', []))}</p>
            <br>
            <p style='color:{t['RED'] if rc.get('CRITICAL',0)>0 else t['TEXT3']};font-size:14px;margin:5px;'>
                <b> CRITICAL:</b> {rc.get('CRITICAL', 0)}
            </p>
            <p style='color:{t['ORANGE'] if rc.get('HIGH',0)>0 else t['TEXT3']};font-size:14px;margin:5px;'>
                <b> HIGH:</b> {rc.get('HIGH', 0)}
            </p>
            <p style='color:{t['TEXT2']};font-size:12px;margin:5px;'><b> MEDIUM:</b> {rc.get('MEDIUM', 0)}</p>
            <p style='color:{t['TEXT3']};font-size:11px;margin:5px;'><b> LOW:</b> {rc.get('LOW', 0)}</p>
        </div>
        """
        
        stats_label = QLabel(stats_html)
        stats_label.setWordWrap(True)
        layout.addWidget(stats_label)
        
        # Critical findings
        if self.critical_findings:
            crit_label = QLabel(f"<b style='color:{t['RED']}'> CRITICAL FINDINGS DETECTED:</b>")
            layout.addWidget(crit_label)
            
            crit_text = QTextEdit()
            crit_text.setReadOnly(True)
            crit_text.setMaximumHeight(150)
            crit_text.setStyleSheet(f"background:{t['CONSOLE_BG']};color:{t['RED']};font-size:10px;border:1px solid {t['RED']};")
            for finding in self.critical_findings[:20]:  # Show first 20 critical findings
                crit_text.append(f" {finding}")
            if len(self.critical_findings) > 5:
                crit_text.append(f"\n... and {len(self.critical_findings) - 5} more")
            layout.addWidget(crit_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        view_report_btn = QPushButton(" View Full Report")
        view_report_btn.clicked.connect(lambda: (dialog.accept(), self._open_report()))
        button_layout.addWidget(view_report_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        dialog.exec_()

    def _apply_theme(self):
        Theme.current = Theme.DARK if self._theme_dark else Theme.LIGHT
        self.setStyleSheet(build_stylesheet(Theme.current))

    #  UI BUILD 
    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setContentsMargins(0,0,0,0); root.setSpacing(0)
        root.addWidget(self._make_header())

        splitter = QSplitter(Qt.Horizontal); splitter.setHandleWidth(1)
        root.addWidget(splitter, stretch=1)

        splitter.addWidget(self._make_left_panel())
        splitter.addWidget(self._make_center_panel())
        splitter.addWidget(self._make_right_panel())
        splitter.setSizes([348, 620, 560])
        splitter.setStretchFactor(0, 0); splitter.setStretchFactor(1, 3); splitter.setStretchFactor(2, 2)
        splitter.setCollapsible(0, False)

        t = Theme.current
        self.statusBar().setStyleSheet(
            f"background:{t['PANEL']};color:{t['TEXT2']};font-size:10px;"
            f"font-family:monospace;border-top:1px solid {t['BORDER']};"
        )
        self.statusBar().showMessage("    DanishRecon  |  Ready  |  Shortcuts: Ctrl+N=Scan Ctrl+S=Stop Ctrl+R=Report Ctrl+F=Search Ctrl+E=Export Ctrl+P=Pause")

    #  HEADER 
    def _make_header(self):
        t = Theme.current
        frame = QFrame(); frame.setFixedHeight(58)
        frame.setStyleSheet(
            f"QFrame{{background:{t['PANEL']};border-bottom:1px solid {t['BORDER']};}}")
        lay = QHBoxLayout(frame); lay.setContentsMargins(20,0,20,0)

        logo = QLabel("[#]  DanishRecon")
        logo.setStyleSheet(f"color:{t['CYAN']};font-size:18px;font-weight:bold;letter-spacing:4px;font-family:monospace;")
        sub  = QLabel("ADVANCED VULNERABILITY ANALYSIS PLATFORM")
        sub.setStyleSheet(f"color:{t['TEXT2']};font-size:9px;letter-spacing:2.5px;font-family:monospace;")

        self.clock = QLabel()
        self.clock.setStyleSheet(f"color:{t['GREEN']};font-size:10px;font-family:monospace;letter-spacing:1px;")
        timer = QTimer(self); timer.timeout.connect(self._tick); timer.start(1000); self._tick()

        self.theme_btn = QPushButton("[+] LIGHT" if self._theme_dark else "[-] DARK")
        self.theme_btn.setObjectName("themeBtn")
        self.theme_btn.setFixedSize(80, 26)
        self.theme_btn.clicked.connect(self._toggle_theme)

        lay.addWidget(logo); lay.addSpacing(20)
        lay.addWidget(sub); lay.addStretch()
        lay.addWidget(self.clock); lay.addSpacing(16); lay.addWidget(self.theme_btn)
        return frame

    def _tick(self):
        self.clock.setText(datetime.now().strftime("[TIME] %Y-%m-%d  %H:%M:%S"))

    def _toggle_theme(self):
        self._theme_dark = not self._theme_dark
        self._apply_theme()
        self.theme_btn.setText("[+] LIGHT" if self._theme_dark else "[-] DARK")
        self.statusBar().showMessage("  Theme switched")

    #  LEFT PANEL 
    def _make_left_panel(self):
        """Left column: target, options, login, actions, stage, progress, tools.

        The content lives in a scroll area, so on a small screen it scrolls instead of the
        groups being squeezed on top of each other.
        """
        t = Theme.current
        panel = QWidget(); panel.setFixedWidth(348); panel.setObjectName("leftPanel")
        panel.setStyleSheet(f"#leftPanel{{background:{t['PANEL']};border-right:1px solid {t['BORDER']};}}")
        outer = QVBoxLayout(panel); outer.setContentsMargins(0, 0, 0, 8); outer.setSpacing(6)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}")
        content = QWidget(); content.setObjectName("leftContent")
        content.setStyleSheet(f"#leftContent{{background:{t['PANEL']};}}")
        lay = QVBoxLayout(content); lay.setContentsMargins(12, 12, 12, 8); lay.setSpacing(12)
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

        group_style = "QGroupBox{font-size:12px;font-weight:bold;color:#00D4FF;}"
        field_label = f"font-size:11px;font-weight:bold;color:{t['TEXT2']};letter-spacing:0.5px;border:none;background:transparent;"

        def label(text):
            lb = QLabel(text); lb.setStyleSheet(field_label)
            return lb

        # ── 1. Target ────────────────────────────────────────────────────────
        tgt_grp = QGroupBox("TARGET"); tgt_grp.setStyleSheet(group_style)
        tgt_lay = QVBoxLayout(tgt_grp); tgt_lay.setContentsMargins(12, 16, 12, 12); tgt_lay.setSpacing(6)

        tgt_lay.addWidget(label("Target (IP / domain / URL)"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. example.com  or  http://host:3000")
        self.target_input.setMinimumHeight(30)
        self.target_input.returnPressed.connect(self._start_scan)
        tgt_lay.addWidget(self.target_input)

        tgt_lay.addSpacing(4)
        tgt_lay.addWidget(label("Scan profile"))
        self.profile_combo = QComboBox()
        for k, v in SCAN_PROFILES.items():
            self.profile_combo.addItem(k, k)
            self.profile_combo.setItemData(self.profile_combo.count() - 1, v["desc"], Qt.ToolTipRole)
        self.profile_combo.setCurrentIndex(3)  # Custom
        self.profile_combo.setMinimumHeight(30)
        tgt_lay.addWidget(self.profile_combo)
        self.profile_desc = QLabel(SCAN_PROFILES[self.profile_combo.currentData()]["desc"])
        self.profile_desc.setWordWrap(True)
        self.profile_desc.setStyleSheet(f"font-size:10px;color:{t['TEXT3']};border:none;background:transparent;")
        self.profile_combo.currentIndexChanged.connect(
            lambda _i: self.profile_desc.setText(SCAN_PROFILES[self.profile_combo.currentData()]["desc"]))
        tgt_lay.addWidget(self.profile_desc)
        lay.addWidget(tgt_grp)

        # ── 2. Scan options (one grid, two equal columns) ────────────────────
        opt_grp = QGroupBox("SCAN OPTIONS"); opt_grp.setStyleSheet(group_style)
        grid = QGridLayout(opt_grp); grid.setContentsMargins(12, 16, 12, 12)
        grid.setHorizontalSpacing(10); grid.setVerticalSpacing(8)
        grid.setColumnStretch(0, 1); grid.setColumnStretch(1, 1)
        checkbox_style = "QCheckBox{font-size:11px;spacing:6px;border:none;background:transparent;}"  # colour follows the theme

        def check(text, tip, checked=False, enabled=True):
            cb = QCheckBox(text); cb.setChecked(checked); cb.setEnabled(enabled)
            cb.setToolTip(tip); cb.setStyleSheet(checkbox_style); cb.setMinimumHeight(22)
            return cb

        self.chk_os       = check("OS detection", "nmap -O (needs admin). Skipped automatically on CDN hosts.", True)
        self.chk_scripts  = check("NSE scripts", "nmap vuln/auth/default scripts (slower)")
        self.chk_stealth  = check("Low-noise mode", "Slower, quieter scanning")
        self.chk_secret   = check("Secret scan", "Always on: looks for leaked keys in pages and JS", True, False)
        self.chk_web_vuln = check("Injection tests", "nuclei DAST on crawled parameters and forms (SQLi, XSS, ...)", True)
        self.chk_nuclei   = check("Nuclei templates", "Exposure / misconfig / panel templates", True)
        self.chk_dirbuster = check("Dir brute-force", "Directory discovery with the DirBuster wordlist (slow)")
        for i, cb in enumerate((self.chk_os, self.chk_scripts, self.chk_stealth, self.chk_secret,
                                self.chk_web_vuln, self.chk_nuclei, self.chk_dirbuster)):
            grid.addWidget(cb, i // 2, i % 2)
        lay.addWidget(opt_grp)

        # ── 3. Login (optional) ──────────────────────────────────────────────
        auth_grp = QGroupBox("LOGIN (OPTIONAL)"); auth_grp.setStyleSheet(group_style)
        auth_lay = QVBoxLayout(auth_grp); auth_lay.setContentsMargins(12, 16, 12, 12); auth_lay.setSpacing(6)
        auth_tip = "Sent with the crawl and the injection tests so pages behind a login are scanned."
        self.auth_cookie_input = QLineEdit()
        self.auth_cookie_input.setPlaceholderText("Session cookie, e.g. session=abc123")
        self.auth_login_url_input = QLineEdit()
        self.auth_login_url_input.setPlaceholderText("or login URL, e.g. https://site/login")
        self.auth_login_data_input = QLineEdit()
        self.auth_login_data_input.setPlaceholderText("Login form data: user=me&password=...")
        self.auth_login_data_input.setEchoMode(QLineEdit.Password)
        for w in (self.auth_cookie_input, self.auth_login_url_input, self.auth_login_data_input):
            w.setMinimumHeight(28); w.setToolTip(auth_tip); auth_lay.addWidget(w)
        lay.addWidget(auth_grp)

        # ── 4. Actions ───────────────────────────────────────────────────────
        btn_grp = QGroupBox("ACTIONS"); btn_grp.setStyleSheet(group_style)
        btn_lay = QVBoxLayout(btn_grp); btn_lay.setContentsMargins(12, 16, 12, 12); btn_lay.setSpacing(8)

        self.start_btn = QPushButton("START SCAN"); self.start_btn.setObjectName("startBtn")
        self.start_btn.setStyleSheet("font-size:14px;font-weight:bold;")
        self.start_btn.setMinimumHeight(38); self.start_btn.clicked.connect(self._start_scan)

        self.stop_btn = QPushButton("STOP SCAN"); self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setStyleSheet("font-size:12px;")
        self.stop_btn.setMinimumHeight(30); self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        btn_lay.addWidget(self.start_btn); btn_lay.addWidget(self.stop_btn)

        def small(text, name, slot, enabled=True):
            b = QPushButton(text); b.setObjectName(name); b.setStyleSheet("font-size:12px;")
            b.setMinimumHeight(30); b.setEnabled(enabled); b.clicked.connect(slot)
            return b

        self.report_btn = small("Report", "reportBtn", self._open_report, False)
        self.export_btn = small("Export", "exportBtn", self._show_export_menu, False)
        self.hist_btn   = small("History", "histBtn", self._show_history)
        self.pin_btn    = small("Change PIN", "histBtn", self._change_app_pin)
        clear_btn       = small("Clear", "exportBtn", self._clear)
        scout_btn       = small("Scout AI", "reportBtn", self._open_scout_tab)
        scout_btn.setToolTip("Open the Scout AI assistant (explains results in plain English)")
        btn_grid = QGridLayout(); btn_grid.setHorizontalSpacing(8); btn_grid.setVerticalSpacing(8)
        for i, b in enumerate((self.report_btn, self.export_btn, self.hist_btn,
                               clear_btn, self.pin_btn, scout_btn)):
            btn_grid.addWidget(b, i // 2, i % 2)
        btn_lay.addLayout(btn_grid)
        lay.addWidget(btn_grp)

        # ── 5. Current stage + progress ──────────────────────────────────────
        prog_grp = QGroupBox("PROGRESS"); prog_grp.setStyleSheet(group_style)
        prog_lay = QVBoxLayout(prog_grp); prog_lay.setContentsMargins(12, 16, 12, 12); prog_lay.setSpacing(8)
        self.stage_indicator = StageIndicator()
        prog_lay.addWidget(self.stage_indicator)
        self.prog_host    = LabeledProgress("HOST DISCOVERY")
        self.prog_port    = LabeledProgress("PORT SCANNING")
        self.prog_service = LabeledProgress("SERVICE DETECT")
        self.prog_vuln    = LabeledProgress("VULN SCANNING")
        self.prog_ai      = LabeledProgress("RANKING")
        self.prog_misc    = LabeledProgress("DNS / TLS / MISC")
        for pb in (self.prog_host, self.prog_port, self.prog_service,
                   self.prog_vuln, self.prog_ai, self.prog_misc):
            prog_lay.addWidget(pb)
        lay.addWidget(prog_grp)

        # ── 6. Tools (what is actually installed) ────────────────────────────
        tools_grp = QGroupBox("TOOLS"); tools_grp.setStyleSheet(group_style)
        tools_grid = QGridLayout(tools_grp); tools_grid.setContentsMargins(12, 16, 12, 12)
        tools_grid.setHorizontalSpacing(10); tools_grid.setVerticalSpacing(6)
        tools_grid.setColumnStretch(0, 1); tools_grid.setColumnStretch(1, 1)
        installed = {
            "nmap": bool(shutil.which("nmap")),
            "nuclei": bool(scan_core.RECON_TOOLS_AVAILABLE and scan_core.recon_tools.find_tool("nuclei")),
            "katana": bool(scan_core.RECON_TOOLS_AVAILABLE and scan_core.recon_tools.find_tool("katana")),
            "httpx": bool(scan_core.RECON_TOOLS_AVAILABLE and scan_core.recon_tools.find_tool("httpx")),
            "subfinder": bool(shutil.which("subfinder")),
            "nikto": bool(NIKTO_PATH),
            "rustscan": bool(scan_core.find_rustscan()),
            "exploit-db": bool(scan_core.EXPLOIT_SEARCH_AVAILABLE and scan_core.exploit_search.available()),
        }
        for i, (tool, ok) in enumerate(installed.items()):
            tl = QLabel(("● " if ok else "○ ") + tool)
            tl.setToolTip("installed" if ok else "not found - the stages that need it are skipped")
            tl.setStyleSheet(f"color:{t['GREEN'] if ok else t['TEXT3']};font-size:11px;"
                             f"font-family:monospace;border:none;background:transparent;")
            tools_grid.addWidget(tl, i // 2, i % 2)
        lay.addWidget(tools_grp)
        lay.addStretch(1)

        self.status_pill = QLabel(" READY")
        self.status_pill.setStyleSheet(
            f"color:{t['GREEN']};font-size:10px;font-family:monospace;letter-spacing:1px;"
            f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
        outer.addWidget(self.status_pill, alignment=Qt.AlignCenter)
        return panel

    def _make_center_panel(self):
        t = Theme.current
        panel = QWidget(); panel.setStyleSheet(f"background:{t['BG']};")
        lay = QVBoxLayout(panel); lay.setContentsMargins(10,10,10,10); lay.setSpacing(6)

        hdr = QHBoxLayout()
        console_lbl = QLabel("  LIVE RECONNAISSANCE CONSOLE")
        console_lbl.setStyleSheet(
            f"color:{t['CYAN']};font-size:10px;font-weight:bold;letter-spacing:2px;font-family:monospace;")
        self.indicator = QLabel("  IDLE")
        self.indicator.setStyleSheet(f"color:{t['TEXT3']};font-size:11px;font-family:monospace;letter-spacing:1px;")
        hdr.addWidget(console_lbl); hdr.addStretch(); hdr.addWidget(self.indicator)
        lay.addLayout(hdr)

        self.console = QTextEdit(); self.console.setReadOnly(True)
        lay.addWidget(self.console, stretch=1)

        self.search_bar = ConsoleSearchBar(self.console)
        lay.addWidget(self.search_bar)

        self._console_welcome()
        return panel

    def _console_welcome(self):
        t = Theme.current
        self.console.setHtml(f"""
        <div style="color:{t['TEXT2']};font-family:monospace;font-size:11.5px;padding:6px;">
        <div style="color:{t['CYAN']};font-size:13px;font-weight:bold;margin-bottom:8px;">
            DanishRecon &mdash; recon + vulnerability scan
        </div>
        <div style="color:{t['TEXT']};margin-top:6px;"><b>What a scan does</b></div>
        <div style="color:{t['GREEN']};margin:6px 0 6px 12px;line-height:1.8;">
           1. DNS, subdomains and live hosts<br>
           2. Ports, services and versions (fast path on CDN hosts)<br>
           3. TLS certificate, protocol and cipher checks<br>
           4. Known CVEs for the detected versions (NVD, KEV, EPSS)<br>
           5. Crawl, then injection tests on every parameter and form (nuclei DAST)<br>
           6. Exposed files / panels / misconfigurations, leaked secrets<br>
           7. DDoS amplification exposure, exploit references<br>
           8. HTML / JSON / CSV / Markdown / PDF report
        </div>
        <div style="color:{t['TEXT']};margin-top:6px;"><b>How to use</b></div>
        <div style="color:{t['TEXT2']};margin:6px 0 6px 12px;line-height:1.8;">
           Enter a target on the left, pick a profile, press START SCAN (Ctrl+N).<br>
           Findings appear in the tabs on the right while the scan runs.<br>
           Malware and traffic analysis run from the CLI: <span style="color:{t['CYAN']};">cli.py malware</span> / <span style="color:{t['CYAN']};">cli.py sniff</span>
        </div>
        <br>
        <div style="color:{t['ORANGE']};">Authorized use only: scan systems you own or have written permission to test.</div>
        </div>""")

    #  RIGHT PANEL 
    def _make_right_panel(self):
        t = Theme.current
        panel = QWidget(); panel.setObjectName("rightPanel")
        panel.setStyleSheet(f"#rightPanel{{background:{t['PANEL']};border-left:1px solid {t['BORDER']};}}")
        lay = QVBoxLayout(panel); lay.setContentsMargins(12,10,12,10); lay.setSpacing(6)

        hdr = QLabel("  SCAN RESULTS")
        hdr.setStyleSheet(
            f"color:{t['CYAN']};font-size:14.5px;font-weight:bold;letter-spacing:2px;font-family:monospace;padding:3px 0 7px 0;")
        lay.addWidget(hdr)

        tabs = QTabWidget(); lay.addWidget(tabs, stretch=1)
        tabs.tabBar().setElideMode(Qt.ElideNone)      # never cut tab titles
        tabs.tabBar().setExpanding(False)
        tabs.setUsesScrollButtons(True)
        # Style tab widget for larger text and better visibility
        tabs.setStyleSheet(f"""
            QTabBar::tab {{
                font-size: 12px;
                font-weight: bold;
                padding: 7px 14px;
                color: {t['TEXT2']};
                background: {t['CARD']};
                border: 1px solid {t['BORDER']};
                border-bottom: none;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                color: {t['CYAN']};
                background: {t['PANEL']};
                border-bottom: 2px solid {t['CYAN']};
            }}
            QTabWidget::pane {{
                border: 1px solid {t['BORDER']};
            }}
        """)

        # Tab: DISCOVERY
        disc = QWidget(); dl = QVBoxLayout(disc); dl.setSpacing(8)
        self.c_hosts    = ResultContainer("HOSTS DISCOVERED",  "")
        self.c_services = ResultContainer("OPEN SERVICES",     "")
        self.c_versions = ResultContainer("VERSIONS",          "")
        self.c_os       = ResultContainer("OS FINGERPRINT",    "")
        scroll1 = QScrollArea(); scroll1.setWidgetResizable(True); scroll1.setFrameShape(QFrame.NoFrame)
        inner1  = QWidget(); il1 = QVBoxLayout(inner1); il1.setSpacing(8)
        for c in (self.c_hosts,self.c_services,self.c_versions,self.c_os):
            il1.addWidget(c)
        il1.addStretch()
        scroll1.setWidget(inner1); dl.addWidget(scroll1)
        tabs.addTab(disc, "Discovery")

        # Tab: NETWORK
        net = QWidget(); nl = QVBoxLayout(net); nl.setSpacing(8)
        self.c_dns      = ResultContainer("DNS RECORDS",       "")
        self.c_ssl      = ResultContainer("SSL/TLS ISSUES",    "")
        self.c_waf      = ResultContainer("WAF / FIREWALL",    "")
        self.c_banners  = ResultContainer("SERVICE BANNERS",   "")
        self.c_subs     = ResultContainer("SUBDOMAINS",        "")
        scroll2 = QScrollArea(); scroll2.setWidgetResizable(True); scroll2.setFrameShape(QFrame.NoFrame)
        inner2  = QWidget(); il2 = QVBoxLayout(inner2); il2.setSpacing(8)
        for c in (self.c_dns,self.c_ssl,self.c_waf,self.c_banners,self.c_subs):
            il2.addWidget(c)
        il2.addStretch()
        scroll2.setWidget(inner2); nl.addWidget(scroll2)
        tabs.addTab(net, "Network")

        # Tab: THREATS
        thr = QWidget(); tl2 = QVBoxLayout(thr); tl2.setSpacing(8)
        self.c_vulns    = ResultContainer("RANKED VULNERABILITIES","")
        self.c_exploits = ResultContainer("EXPLOIT SUGGESTIONS",   "")
        self.c_mitre    = ResultContainer("MITRE ATT&ACK",          "")
        self.c_sqli     = ResultContainer("INJECTION FINDINGS (DAST)", "")
        self.c_amp      = ResultContainer("DDoS AMPLIFICATION VECTORS", "")
        self.c_idor     = ResultContainer("UNVERIFIED HEURISTICS (LEGACY)", "")
        scroll3 = QScrollArea(); scroll3.setWidgetResizable(True); scroll3.setFrameShape(QFrame.NoFrame)
        inner3  = QWidget(); il3 = QVBoxLayout(inner3); il3.setSpacing(8)
        for c in (self.c_vulns,self.c_sqli,self.c_amp,self.c_exploits,self.c_mitre,self.c_idor):
            il3.addWidget(c)
        il3.addStretch()
        scroll3.setWidget(inner3); tl2.addWidget(scroll3)
        tabs.addTab(thr, "Findings")

        # Tab: API / SECRETS
        api_tab = QWidget(); api_lay = QVBoxLayout(api_tab); api_lay.setSpacing(8)
        self.c_api_endpoints = ResultContainer("API ENDPOINTS & CRAWLED PARAMETERS", "")
        self.c_secret_findings = ResultContainer("SECRET FINDINGS", "")
        scroll_api = QScrollArea(); scroll_api.setWidgetResizable(True); scroll_api.setFrameShape(QFrame.NoFrame)
        inner_api = QWidget(); il_api = QVBoxLayout(inner_api); il_api.setSpacing(8)
        self.c_dirbuster = ResultContainer("DIRECTORY DISCOVERY", "")
        for c in (self.c_api_endpoints, self.c_secret_findings, self.c_dirbuster):
            il_api.addWidget(c)
        il_api.addStretch()
        scroll_api.setWidget(inner_api); api_lay.addWidget(scroll_api)
        tabs.addTab(api_tab, "Web / Secrets")

        # Tab: NUCLEI SCAN
        nuc_tab = QWidget(); nuc_lay = QVBoxLayout(nuc_tab); nuc_lay.setSpacing(8)
        self.c_nuclei_findings  = ResultContainer("NUCLEI TEMPLATE FINDINGS", "")
        self.c_nuclei_cve       = ResultContainer("NUCLEI CVE MATCHES", "")
        scroll_nuc = QScrollArea(); scroll_nuc.setWidgetResizable(True); scroll_nuc.setFrameShape(QFrame.NoFrame)
        inner_nuc  = QWidget(); il_nuc = QVBoxLayout(inner_nuc); il_nuc.setSpacing(8)
        for c in (self.c_nuclei_findings, self.c_nuclei_cve):
            il_nuc.addWidget(c)
        il_nuc.addStretch()
        scroll_nuc.setWidget(inner_nuc); nuc_lay.addWidget(scroll_nuc)
        tabs.addTab(nuc_tab, "Nuclei")

        # Tab: ATTACK
        atk = QWidget(); al = QVBoxLayout(atk); al.setSpacing(8)
        self.c_paths    = ResultContainer("POTENTIAL ATTACK PATHS (HYPOTHETICAL)", "")
        self.c_recs     = ResultContainer("RECOMMENDATIONS",  "")
        self.c_comply   = ResultContainer("COMPLIANCE",       "")
        scroll4 = QScrollArea(); scroll4.setWidgetResizable(True); scroll4.setFrameShape(QFrame.NoFrame)
        inner4  = QWidget(); il4 = QVBoxLayout(inner4); il4.setSpacing(8)
        for c in (self.c_paths,self.c_recs,self.c_comply):
            il4.addWidget(c)
        il4.addStretch()
        scroll4.setWidget(inner4); al.addWidget(scroll4)
        tabs.addTab(atk, "Analysis")

        # Tab: SCOUT AI ASSISTANT
        if SCOUT_PANEL_AVAILABLE:
            self.scout_panel = ScoutPanel(self)
            tabs.addTab(self.scout_panel, "Scout AI")
        else:
            fallback = QWidget()
            fb_lay = QVBoxLayout(fallback)
            fb_lbl = QLabel(
                "<div style='text-align:center;padding:40px;'>"
                "<div style='font-size:32px;'>🤖</div>"
                "<div style='color:#00e5ff;font-size:14px;font-weight:bold;margin-top:12px;'>Scout Not Available</div>"
                "<div style='color:#64748b;font-size:11px;margin-top:8px;'>"
                "Make sure scout_chatbot/ folder is next to DanishRecon/"
                "</div></div>"
            )
            fb_lbl.setTextFormat(Qt.RichText)
            fb_lbl.setAlignment(Qt.AlignCenter)
            fb_lay.addWidget(fb_lbl)
            tabs.addTab(fallback, "Scout AI")

        self._result_tabs = tabs
        return panel

    #  SIGNAL HANDLERS 
    def _append_log(self, msg: str, level: str):
        t = Theme.current
        ts   = datetime.now().strftime("%H:%M:%S")
        colors = {
            "stage":  t["CYAN"],
            "good":   t["GREEN"],
            "warn":   t["ORANGE"],
            "error":  t["RED"],
            "info":   t["TEXT"],
            "muted":  t["TEXT2"],
        }
        mc = colors.get(level, t["TEXT"])
        prefix_colors = {
            "stage":  t["PURPLE"],
            "error":  t["RED"],
            "warn":   t["ORANGE"],
        }
        pc = prefix_colors.get(level, t["TEXT2"])

        cursor = self.console.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(
            f'<span style="color:{t["TEXT2"]}">[{ts}]</span> '
            f'<span style="color:{mc}">{msg}</span><br>'
        )
        self.console.setTextCursor(cursor)
        self.console.ensureCursorVisible()

    def _update_progress(self, bar: str, val: int):
        mapping = {
            "host":    self.prog_host,
            "port":    self.prog_port,
            "service": self.prog_service,
            "vuln":    self.prog_vuln,
            "ai":      self.prog_ai,
            "misc":    self.prog_misc,
        }
        if bar in mapping:
            mapping[bar].set_value(val)

    def _add_result(self, container: str, item: str, color: str):
        mapping = {
            "Hosts":                    self.c_hosts,
            "Services":                 self.c_services,
            "Versions":                 self.c_versions,
            "OS Fingerprint":           self.c_os,
            "DNS Records":              self.c_dns,
            "SSL Issues":               self.c_ssl,
            "WAF/Firewall":             self.c_waf,
            "Banners":                  self.c_banners,
            "Subdomains":               self.c_subs,
            "Ranked Vulnerabilities":   self.c_vulns,
            "API Endpoints":            self.c_api_endpoints,
            "Secret Findings":          self.c_secret_findings,
            "Exploit Suggestions":      self.c_exploits,
            "MITRE ATT&CK":             self.c_mitre,
            "idor":                     self.c_idor,
            "sqli":                     self.c_sqli,
            "Attack Paths":             self.c_paths,
            "Security Recommendations": self.c_recs,
            "Compliance":               self.c_comply,
            # Nuclei containers
            "Nuclei Findings":          self.c_nuclei_findings,
            "Nuclei CVE Matches":       self.c_nuclei_cve,
            "DirBuster Findings":       self.c_dirbuster,
            # stages that previously had no place in the GUI
            "Amplification Vectors":    self.c_amp,
            "Cryptography Analysis":    self.c_ssl,
            "Crypto Issues":            self.c_ssl,
            "TLS Versions":             self.c_ssl,
            "Generated Configs":        self.c_recs,
            "Compliance Mapping":       self.c_comply,
        }
        if container in mapping:
            mapping[container].add_item(item, color)
        
        # Check for critical/high findings and send real-time alerts
        if container == "Ranked Vulnerabilities":
            # Extract severity from item text
            # (the old check was `"" in item`, which is always true - every finding
            #  fired a CRITICAL alert). Match the severity tag the labels actually carry.
            _sev = re.search(r"\[\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", item.upper())
            _sev = _sev.group(1) if _sev else ""
            if _sev == "CRITICAL":
                self.critical_findings.append(item)
                self._play_alert_sound("critical")
                self._send_desktop_notification(
                    " CRITICAL Vulnerability Found!",
                    item[:100],  # First 100 chars
                    "critical"
                )
            elif _sev == "HIGH":
                self.high_findings.append(item)
                self._play_alert_sound("high")
        
        elif container == "Exploit Suggestions":
            # One notification per scan is enough - not one per reference.
            if not getattr(self, "_exploit_alert_sent", False):
                self._exploit_alert_sent = True
                self._send_desktop_notification(
                    " Exploit Available",
                    item[:100],
                    "warning"
                )

    def _update_stage(self, stage: str):
        self.stage_indicator.set_stage(stage)
        self.statusBar().showMessage(f"    {stage} ...")

    def _set_live_indicator(self, state: str):
        """Update live scan indicator text and color based on scan state."""
        t = Theme.current
        mapping = {
            "idle":     ("  IDLE",      t["TEXT3"]),
            "live":     ("  LIVE",      t["CYAN"]),
            "paused":   ("  PAUSED",    t["PURPLE"]),
            "complete": ("  COMPLETE",  t["GREEN"]),
            "stopped":  ("  STOPPED",   t["ORANGE"]),
        }
        text, color = mapping.get(state, mapping["idle"])
        self.indicator.setText(text)
        self.indicator.setStyleSheet(
            f"color:{color};font-size:11px;font-family:monospace;letter-spacing:1px;")

    def _update_charts(self, data: dict):
        pass  # charts are embedded in attack graph

    def _scan_done(self, data: dict):
        self.scan_data = data
        self.stage_indicator.stop()
        self._blink_timer.stop()
        self._set_live_indicator("complete")
        t = Theme.current
        self.status_pill.setText(" COMPLETE")
        self.status_pill.setStyleSheet(
            f"color:{t['GREEN']};font-size:10px;font-family:monospace;letter-spacing:1px;"
            f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.report_btn.setEnabled(True)
        self.export_btn.setEnabled(True)

        rc = data.get("risk_counts", {})
        report_rel = data.get("report_path") or os.path.join(RESULTS_DIR, "report_v3.html")
        report_rel = os.path.relpath(report_rel, os.getcwd()).replace("\\", "/")
        self.statusBar().showMessage(
            f"    Scan complete  |  {len(data['hosts'])} hosts  |  "
            f"{len(data['services'])} services  |  "
            f"CRIT:{rc.get('CRITICAL',0)}  HIGH:{rc.get('HIGH',0)}  "
            f"MED:{rc.get('MEDIUM',0)}  |  Report: {report_rel}"
        )

        # Enhanced notification with summary
        crit_count = rc.get('CRITICAL', 0)
        high_count = rc.get('HIGH', 0)
        
        # Desktop notification
        severity = "critical" if crit_count > 0 else "warning" if high_count > 0 else "info"
        message = f"Target: {data.get('target', 'Unknown')}\n"
        message += f"Critical: {crit_count} | High: {high_count} | Services: {len(data.get('services', []))}"
        
        self._send_desktop_notification(
            " Scan Complete",
            message,
            severity
        )
        
        # Play completion sound
        if crit_count > 0:
            self._play_alert_sound("critical")
        elif high_count > 0:
            self._play_alert_sound("high")
        
        # Show summary popup dialog
        self._show_scan_summary_dialog(data)
        
        # Legacy system notifications (Linux/Mac)
        try:
            if sys.platform == "linux":
                subprocess.Popen(["notify-send", "DanishRecon",
                                  f"Scan complete: {data['target']}"])
            elif sys.platform == "darwin":
                tgt_name = data.get("target","")
                subprocess.Popen(["osascript", "-e",
                    f'display notification "Scan complete: {tgt_name}" with title "DanishRecon"'])
        except:
            pass

        # Inject scan target into Scout AI panel
        try:
            if SCOUT_PANEL_AVAILABLE and hasattr(self, 'scout_panel'):
                self.scout_panel.inject_scan_target(data.get('target', ''))
        except Exception as _e:
            print(f"[Scout] inject_scan_target failed: {_e}")

    def _scan_stopped(self):
        t = Theme.current
        self.status_pill.setText(" STOPPED")
        self.status_pill.setStyleSheet(
            f"color:{t['ORANGE']};font-size:10px;font-family:monospace;letter-spacing:1px;"
            f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._blink_timer.stop()
        self._set_live_indicator("stopped")
        self.stage_indicator.stop()

    def _blink_indicator(self):
        t = Theme.current
        self._blink_on = not self._blink_on
        self.indicator.setStyleSheet(
            f"color:{t['CYAN'] if self._blink_on else t['TEXT2']};font-size:11px;font-family:monospace;letter-spacing:1px;")

    #  ACTIONS 
    def _start_scan(self):
        pf = getattr(self, "_preflight", None)
        if pf and pf["summary"]["missing_critical"] > 0:
            missing = [c["name"] for c in pf["checks"]
                       if not c["ok"] and c["severity"] == "critical"]
            QMessageBox.warning(
                self, "Missing required tools",
                "Cannot start a scan. Missing: " + ", ".join(missing) +
                "\n\nRun `python preflight.py` for install instructions, then restart.")
            return
        target = self.target_input.text().strip()
        if not target:
            self.statusBar().showMessage("    Enter a target first."); return
        if self.scan_thread and self.scan_thread.isRunning():
            self.statusBar().showMessage("    Scan already running."); return

        # Validate the target before anything is launched against it.
        try:
            raw_target = target          # keeps an explicit scheme/port for the engine
            target = normalize_target(target)
        except ValueError as e:
            QMessageBox.warning(self, "Invalid target", str(e))
            return

        # Authorization gate: asked once per target per session.
        if not hasattr(self, "_authorized_targets"):
            self._authorized_targets = set()
        if target not in self._authorized_targets:
            answer = QMessageBox.question(
                self, "Confirm authorization",
                f"You are about to actively scan:\n\n    {target}\n\n"
                "Only scan systems you own or have explicit written permission to test. "
                "Unauthorized scanning is illegal in most jurisdictions.\n\n"
                "Do you confirm that you are authorized to test this target?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                self.statusBar().showMessage("    Scan cancelled - authorization not confirmed.")
                return
            self._authorized_targets.add(target)

        # Reset notification tracking
        self.critical_findings.clear()
        self._exploit_alert_sent = False
        self.high_findings.clear()
        
        self._reset_ui()
        profile = self.profile_combo.currentData()
        options = {
            "os_detect": self.chk_os.isChecked(),
            "scripts":   self.chk_scripts.isChecked(),
            "stealth":   self.chk_stealth.isChecked(),
            "secret_scan": True,
            "enable_web_vuln": self.chk_web_vuln.isChecked(),  # ✅ NEW: Add checkbox state
            "nuclei": self.chk_nuclei.isChecked(),  # ✅ Nuclei scanning toggle
            "dirbuster": self.chk_dirbuster.isChecked(), # ✅ DirBuster brute force toggle
            "auth_bearer": "",
            "auth_cookie": self.auth_cookie_input.text().strip(),
            "login_url": self.auth_login_url_input.text().strip(),
            "login_data": self.auth_login_data_input.text().strip(),
        }

        t = Theme.current
        self.status_pill.setText(" SCANNING")
        self.status_pill.setStyleSheet(
            f"color:{t['ORANGE']};font-size:10px;font-family:monospace;letter-spacing:1px;"
            f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.report_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self._set_live_indicator("live")
        self._blink_timer.start(500)

        self.scan_thread = ScanEngine(raw_target, profile, options)
        self.scan_thread.log_signal.connect(self._append_log)
        self.scan_thread.progress_signal.connect(self._update_progress)
        self.scan_thread.result_signal.connect(self._add_result)
        self.scan_thread.stage_signal.connect(self._update_stage)
        self.scan_thread.chart_signal.connect(self._update_charts)
        self.scan_thread.scan_complete.connect(self._scan_done)
        self.scan_thread.stopped.connect(self._scan_stopped)
        self.scan_thread.start()

    def _open_scout_tab(self):
        """Switch the right panel to the Scout AI tab and auto-start its backend."""
        try:
            if hasattr(self, '_result_tabs'):
                # Find Scout tab by title
                for i in range(self._result_tabs.count()):
                    if "SCOUT" in self._result_tabs.tabText(i).upper():
                        self._result_tabs.setCurrentIndex(i)
                        break
            # Auto-launch the Scout backend so the user doesn't have to run it manually
            if SCOUT_PANEL_AVAILABLE and hasattr(self, 'scout_panel'):
                self.scout_panel.ensure_backend()
        except Exception as _e:
            print(f"[Scout] Could not switch tab: {_e}")

    def _stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.statusBar().showMessage("    Stop signal sent...")

    def _clear(self):
        self.console.clear(); self._console_welcome()
        for c in (self.c_hosts,self.c_services,self.c_versions,self.c_os,
                  self.c_dns,self.c_ssl,self.c_waf,self.c_banners,self.c_subs,
                  self.c_vulns,self.c_exploits,self.c_mitre,
                  self.c_api_endpoints,self.c_secret_findings,
                  self.c_paths,self.c_recs,self.c_comply,
                  self.c_nuclei_findings,self.c_nuclei_cve,self.c_amp,
                  self.c_idor,self.c_sqli,self.c_dirbuster):
            c.clear()
        for pb in (self.prog_host,self.prog_port,self.prog_service,
                   self.prog_vuln,self.prog_ai,self.prog_misc):
            pb.reset()
        t = Theme.current
        self.status_pill.setText(" READY")
        self.status_pill.setStyleSheet(
            f"color:{t['GREEN']};font-size:10px;font-family:monospace;letter-spacing:1px;"
            f"padding:4px;background:{t['CARD']};border-radius:4px;border:1px solid {t['BORDER']};")
        self._set_live_indicator("idle")
        self.stage_indicator.lbl.setText("IDLE")

    def _reset_ui(self):
        self._clear()

    def _change_app_pin(self):
        cfg = _load_pin_config()

        if cfg is not None:
            verified = False
            for attempt in range(3):
                attempts_left = 3 - attempt
                old_pin = AppPinDialog(setup_mode=False, attempts_left=attempts_left, parent=self)
                if old_pin.exec_() != QDialog.Accepted:
                    self.statusBar().showMessage("    PIN change cancelled")
                    return
                if _verify_pin(old_pin.pin_value, cfg):
                    verified = True
                    break
                if attempts_left > 1:
                    QMessageBox.warning(self, "Wrong PIN", f"Incorrect PIN. Attempts left: {attempts_left - 1}")

            if not verified:
                QMessageBox.critical(self, "Access Denied", "Could not verify existing PIN.")
                self.statusBar().showMessage("    PIN change failed")
                return

        new_pin = AppPinDialog(setup_mode=True, parent=self)
        if new_pin.exec_() != QDialog.Accepted:
            self.statusBar().showMessage("    PIN change cancelled")
            return

        try:
            _save_pin_config(new_pin.pin_value)
            QMessageBox.information(self, "PIN Updated", "App PIN has been changed successfully.")
            self.statusBar().showMessage("    App PIN updated successfully")
        except Exception as e:
            QMessageBox.critical(self, "PIN Update Failed", f"Could not update PIN: {e}")
            self.statusBar().showMessage("    PIN update failed")

    def _open_report(self):
        path = ""
        if self.scan_data:
            path = self.scan_data.get("report_path", "")
        if not path:
            path = os.path.join(RESULTS_DIR, "report_v3.html")
        path = os.path.abspath(path)
        if os.path.exists(path):
            import webbrowser; webbrowser.open(f"file://{path}")
        else:
            self.statusBar().showMessage("    Report not found. Run a scan first.")

    def _show_export_menu(self):
        if not self.scan_data: return
        menu = QMenu(self)
        t = Theme.current
        menu.setStyleSheet(f"QMenu{{background:{t['CARD']};color:{t['TEXT']};border:1px solid {t['BORDER']};border-radius:5px;padding:4px;}}"
                           f"QMenu::item{{padding:7px 20px;}}"
                           f"QMenu::item:selected{{background:{t['SELECTED']};color:{t['CYAN']};}}")
        a_html = menu.addAction("  Open HTML Report")
        a_pdf  = menu.addAction("  Export Professional PDF")
        menu.addSeparator()
        a_json = menu.addAction("  Export JSON")
        a_csv  = menu.addAction("  Export CSV")
        a_md   = menu.addAction("  Export Markdown")
        menu.addSeparator()
        a_graph= menu.addAction("  Open Attack Graph")

        action = menu.exec_(self.export_btn.mapToGlobal(QPoint(0, self.export_btn.height())))
        import webbrowser

        def _open_local_file(path):
            if not path or not os.path.exists(path):
                self.statusBar().showMessage("    Export file not found")
                return
            try:
                if sys.platform == 'win32':
                    os.startfile(path)
                elif sys.platform == 'darwin':
                    subprocess.Popen(['open', path])
                else:
                    subprocess.Popen(['xdg-open', path])
            except Exception:
                webbrowser.open(f"file://{path}")

        def _notify_export_success(label, path):
            QMessageBox.information(
                self,
                f"{label} Export Complete",
                f"{label} exported successfully!\n\nLocation: {path}",
                QMessageBox.Ok,
            )

        if action == a_html:
            p = self.scan_data.get("report_path", "") if self.scan_data else ""
            if not p:
                p = os.path.abspath(os.path.join(RESULTS_DIR, "report_v3.html"))
            _open_local_file(p)
        elif action == a_pdf:
            if REPORTLAB_AVAILABLE:
                if self.scan_thread:
                    self.statusBar().showMessage("    Generating PDF report...")
                    p = self.scan_thread.export_pdf()
                    if p:
                        self.statusBar().showMessage(f"    PDF exported  {p}")
                        # Ask to open the PDF
                        reply = QMessageBox.question(self, 'PDF Generated', 
                                                     f'PDF report generated successfully!\\n\\nLocation: {p}\\n\\nOpen now?',
                                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
                        if reply == QMessageBox.Yes:
                            try:
                                if sys.platform == 'win32':
                                    os.startfile(p)
                                elif sys.platform == 'darwin':
                                    subprocess.Popen(['open', p])
                                else:
                                    subprocess.Popen(['xdg-open', p])
                            except:
                                webbrowser.open(f"file://{p}")
                    else:
                        self.statusBar().showMessage("    PDF generation failed")
            else:
                QMessageBox.warning(self, 'PDF Export Unavailable',
                                    'ReportLab library not installed.\\n\\nInstall with:\\npip install reportlab')
        elif action == a_json:
            p = ""
            if self.scan_thread:
                p = self.scan_thread.export_json()
            else:
                p = self.scan_data.get("json_path", "")
            if p:
                self.statusBar().showMessage(f"  JSON exported  {p}")
                _open_local_file(p)
                _notify_export_success("JSON", p)
        elif action == a_csv:
            p = ""
            if self.scan_thread:
                p = self.scan_thread.export_csv()
            elif self.scan_data.get("scan_id"):
                p = os.path.join(RESULTS_DIR, f"vulns_{self.scan_data['scan_id']}.csv")
            if p:
                self.statusBar().showMessage(f"  CSV exported  {p}")
                _open_local_file(p)
                _notify_export_success("CSV", p)
        elif action == a_md:
            p = ""
            if self.scan_thread:
                p = self.scan_thread.export_markdown()
            elif self.scan_data.get("scan_id"):
                p = os.path.join(RESULTS_DIR, f"report_{self.scan_data['scan_id']}.md")
            if p:
                self.statusBar().showMessage(f"  Markdown exported  {p}")
                _open_local_file(p)
                _notify_export_success("Markdown", p)
        elif action == a_graph:
            p = os.path.abspath(os.path.join(RESULTS_DIR,"attack_graph_v3.png"))
            _open_local_file(p)

    def _show_history(self):
        dlg = HistoryDialog(self); dlg.exec_()


# 
#  ENTRY POINT
# 
def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    app = QApplication(sys.argv)
    app.setApplicationName("DanishRecon")
    app.setApplicationVersion("")
    app.setStyle("Fusion")

    # Dark palette for non-styled elements
    pal = QPalette()
    pal.setColor(QPalette.Window,       QColor("#080C18"))
    pal.setColor(QPalette.WindowText,   QColor("#F1F5F9"))
    pal.setColor(QPalette.Base,         QColor("#0C1220"))
    pal.setColor(QPalette.Text,         QColor("#F1F5F9"))
    pal.setColor(QPalette.Highlight,    QColor("#00E5FF"))
    pal.setColor(QPalette.HighlightedText, QColor("#000000"))
    app.setPalette(pal)

    if not enforce_app_pin():
        sys.exit(0)

    # Scans left 'running' by a previous crash / forced close can never finish.
    try:
        DB.mark_stale_scans()
    except Exception as _e:
        print(f"[DB] Could not mark stale scans: {_e}")

    win = DanishReconMain()
    win.show()
    start_gui_login_alert_async()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()



