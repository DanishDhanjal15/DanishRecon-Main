#!/usr/bin/env python3
"""
DanishRecon scan engine (no GUI dependencies).

Contains the database layer, target validation, the CVE rules and the ScanEngine
pipeline. It is used by:
  * cli.py              - headless runs
  * webapp/server.py    - the web dashboard
  * gui.py  - the PyQt5 desktop GUI (wraps ScanEngine in a QThread)

Progress is reported through lightweight Signal objects (connect/emit) so any front-end
can subscribe without Qt.
"""


import sys, os, re, json, csv, sqlite3, base64, hashlib, socket, ssl, hmac, getpass, platform, urllib.parse
import subprocess, threading, time, traceback, shutil
import html as _html
import xml.etree.ElementTree as ET
import networkx as nx
import matplotlib
import requests
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Import API Scanner
try:
    from danishrecon.api_scanner_module import APIScanner
    API_SCANNER_AVAILABLE = True
except ImportError:
    API_SCANNER_AVAILABLE = False

# Import Web Vulnerability Scanner for IDOR, SQLi, XSS detection
try:
    from danishrecon.web_vulnerability_scanner import WebVulnerabilityScanner, ScanProfile
    import asyncio
    WEB_VULN_SCANNER_AVAILABLE = True
except ImportError:
    WEB_VULN_SCANNER_AVAILABLE = False

# Import Cryptography Analysis Module
try:
    from danishrecon.cryptography_analyzer import CryptographyAnalyzer, fetch_certificate
    CRYPTO_ANALYZER_AVAILABLE = True
except ImportError:
    CRYPTO_ANALYZER_AVAILABLE = False

# Structured findings + OSS tool orchestration (httpx / katana / nuclei DAST / NVD / Exploit-DB)
from danishrecon.findings import Finding, severity_from_cvss
try:
    from danishrecon import recon_tools
    RECON_TOOLS_AVAILABLE = True
except ImportError:
    RECON_TOOLS_AVAILABLE = False
try:
    from danishrecon import cve_lookup
    CVE_LOOKUP_AVAILABLE = True
except ImportError:
    CVE_LOOKUP_AVAILABLE = False
try:
    from danishrecon import exploit_search
    EXPLOIT_SEARCH_AVAILABLE = True
except ImportError:
    EXPLOIT_SEARCH_AVAILABLE = False
try:
    from danishrecon import amplification
    AMPLIFICATION_AVAILABLE = True
except ImportError:
    AMPLIFICATION_AVAILABLE = False

# Import Nuclei Scanner Module
try:
    from danishrecon.nuclei_scanner import NucleiScanner, find_nuclei
    NUCLEI_AVAILABLE = True
except ImportError:
    NUCLEI_AVAILABLE = False

# Import Recommendation Engine
try:
    from danishrecon.recommendation_engine import RecommendationEngine, generate_all_recommendations
    RECOMMENDATION_ENGINE_AVAILABLE = True
except ImportError:
    RECOMMENDATION_ENGINE_AVAILABLE = False

# Import OpenVAS Scanner Module
try:
    from danishrecon.openvas_scanner import OpenVASScanner, OpenVASReportGenerator
    OPENVAS_AVAILABLE = True
except ImportError:
    OPENVAS_AVAILABLE = False

# Import Gemini Analyzer for AI-powered vulnerability analysis
import sys
import os as _os_import
try:
    from danishrecon.gemini_analyzer import GeminiAnalyzer
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

try:
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv(usecwd=True))   # .env in the working directory or a parent
except ImportError:
    pass
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
# Import DirBuster Scanner
try:
    from danishrecon.dirbuster_scanner import DirBusterScanner
    DIRBUSTER_AVAILABLE = True
except ImportError:
    DIRBUSTER_AVAILABLE = False

from matplotlib.colors import LinearSegmentedColormap
from datetime import datetime
from collections import defaultdict

# PDF generation libraries
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("Warning: ReportLab not installed. PDF export will be disabled.")
    print("Install with: pip install reportlab")


class Signal:
    """Minimal stand-in for a Qt signal: connect(callable) / emit(*args).

    emit() runs subscribers synchronously on the engine thread; a failing subscriber
    never breaks the scan.
    """

    def __init__(self, *_types):
        self._subscribers = []

    def connect(self, fn):
        self._subscribers.append(fn)

    def emit(self, *args):
        for fn in list(self._subscribers):
            try:
                fn(*args)
            except Exception:
                traceback.print_exc()


class Theme:
    DARK = {
        "BG":          "#080C18",
        "PANEL":       "#0C1220",
        "CARD":        "#111827",
        "CARD2":       "#0F172A",
        "CYAN":        "#00E5FF",
        "GREEN":       "#10B981",
        "RED":         "#EF4444",
        "ORANGE":      "#F59E0B",
        "PURPLE":      "#8B5CF6",
        "PINK":        "#EC4899",
        "BLUE":        "#3B82F6",
        "TEXT":        "#F1F5F9",
        "TEXT2":       "#94A3B8",
        "TEXT3":       "#64748B",
        "BORDER":      "#1E293B",
        "BORDER2":     "#334155",
        "SELECTED":    "#1D4ED8",
        "CONSOLE_BG":  "#050912",
        "CONSOLE_FG":  "#22D3EE",
        "ACCENT":      "#00E5FF",
    }
    LIGHT = {
        "BG":          "#F8FAFC",
        "PANEL":       "#FFFFFF",
        "CARD":        "#F1F5F9",
        "CARD2":       "#E2E8F0",
        "CYAN":        "#0284C7",
        "GREEN":       "#059669",
        "RED":         "#DC2626",
        "ORANGE":      "#D97706",
        "PURPLE":      "#7C3AED",
        "PINK":        "#DB2777",
        "BLUE":        "#2563EB",
        "TEXT":        "#0F172A",
        "TEXT2":       "#475569",
        "TEXT3":       "#64748B",
        "BORDER":      "#CBD5E1",
        "BORDER2":     "#94A3B8",
        "SELECTED":    "#DBEAFE",
        "CONSOLE_BG":  "#1E293B",
        "CONSOLE_FG":  "#22D3EE",
        "ACCENT":      "#0284C7",
    }
    current = DARK

# Where scans write their database and reports. Relative to the working directory by
# default; nothing is created until a scan (or the database) is actually used.
RESULTS_DIR = os.environ.get("DANISHRECON_RESULTS", "results")
DB_PATH     = os.path.join(RESULTS_DIR, "danishrecon.db")
PIN_CONFIG_PATH = os.path.join(RESULTS_DIR, "app_pin.json")
PIN_HASH_ITERATIONS = 120000
TWILIO_ENABLED_ENV = "DANISHRECON_TWILIO_ENABLED"
TWILIO_ACCOUNT_SID_ENV = "DANISHRECON_TWILIO_ACCOUNT_SID"
TWILIO_AUTH_TOKEN_ENV = "DANISHRECON_TWILIO_AUTH_TOKEN"
TWILIO_WHATSAPP_FROM_ENV = "DANISHRECON_TWILIO_WHATSAPP_FROM"
TWILIO_WHATSAPP_TO_ENV = "DANISHRECON_TWILIO_WHATSAPP_TO"

# Nikto configuration - using local nikto installation
# Search for nikto.pl in multiple locations (nikto_official first, then fallbacks)
# Nikto: the per-user tools folder (danishrecon setup nikto), NIKTO_PATH, a checkout in the
# working directory, or a system install. See danishrecon/tools.py.
from danishrecon.tools import find_nikto as _find_nikto_tool, bin_path as _tool_bin
NIKTO_PATH = _find_nikto_tool()
NIKTO_AVAILABLE = NIKTO_PATH is not None

# Perl executable - try PATH first, then use absolute Strawberry Perl path as fallback
def _perl_can_run_nikto(perl_exe):
    """True if this Perl has the module Nikto needs (XML::Writer is the usual missing one).

    A bare `perl` on PATH — e.g. Git Bash / msys perl — often lacks XML::Writer and
    makes Nikto abort immediately, so we test before trusting it.
    """
    try:
        r = subprocess.run([perl_exe, "-MXML::Writer", "-e", "1"],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _find_perl():
    """Find a Perl that can actually run Nikto (i.e. one that has XML::Writer).

    Order of preference:
      1. Any candidate Perl that passes the Nikto-module check (Strawberry on Windows)
      2. Otherwise the first Perl that merely exists (best effort — Nikto may warn)
    This prevents silently selecting Git Bash's module-less perl, which makes Nikto
    fail with "Required module not found: XML::Writer" and scan nothing.
    """
    import glob
    candidates = []
    which_perl = shutil.which("perl")
    if which_perl:
        candidates.append(which_perl)
    # Common Strawberry Perl install locations (Windows)
    candidates += [
        r"C:\Strawberry\perl\bin\perl.exe",
        r"C:\Program Files\Strawberry Perl\perl\bin\perl.exe",
    ]
    # Any Strawberry Perl unpacked under the user's Downloads (version-agnostic glob)
    candidates += glob.glob(os.path.expanduser(r"~\Downloads\strawberry-perl*\perl\bin\perl.exe"))

    # 1) Prefer a Perl that can actually run Nikto
    for c in candidates:
        if c and os.path.exists(c) and _perl_can_run_nikto(c):
            return c
    # 2) Fallback: any Perl that exists (Nikto may warn about missing modules)
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return "perl"  # Last resort - rely on PATH

PERL_EXECUTABLE = _find_perl()
NIKTO_LEGACY_COMPAT_MODE = True
NIKTO_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

# Searchsploit configuration - try multiple options (bash script, wrappers, or system PATH)
EXPLOIT_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exploit-database")
SEARCHSPLOIT_BASH = os.path.join(EXPLOIT_DB_DIR, "searchsploit")  # Actual bash script
SEARCHSPLOIT_PS1 = os.path.join(EXPLOIT_DB_DIR, "searchsploit.ps1")
SEARCHSPLOIT_BAT = os.path.join(EXPLOIT_DB_DIR, "searchsploit.bat")
# Check what's available: PS1 > BAT > BASH script
SEARCHSPLOIT_PATH = None
if os.path.exists(SEARCHSPLOIT_PS1):
    SEARCHSPLOIT_PATH = SEARCHSPLOIT_PS1
elif os.path.exists(SEARCHSPLOIT_BAT):
    SEARCHSPLOIT_PATH = SEARCHSPLOIT_BAT
elif os.path.exists(SEARCHSPLOIT_BASH):
    SEARCHSPLOIT_PATH = SEARCHSPLOIT_BASH

# Helper function to detect available bash environments
def _find_bash():
    """Find available bash (Git Bash, WSL, or system bash)"""
    candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
        "bash",
        "bash.exe"
    ]
    for bash_path in candidates:
        try:
            subprocess.run([bash_path, "--version"], capture_output=True, timeout=2, check=False)
            return bash_path
        except:
            continue
    return None

AVAILABLE_BASH = _find_bash()

# 
#  DATABASE LAYER
# 
class Database:
    def __init__(self):
        os.makedirs(RESULTS_DIR, exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._lock = threading.Lock()
        self._init()

    def _init(self):
        c = self.conn.cursor()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            target    TEXT NOT NULL,
            profile   TEXT,
            started   TEXT,
            finished  TEXT,
            status    TEXT DEFAULT 'running',
            summary   TEXT,
            scan_type TEXT DEFAULT 'recon'
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id  INTEGER,
            address  TEXT,
            hostname TEXT,
            os_guess TEXT,
            status   TEXT
        );
        CREATE TABLE IF NOT EXISTS ports (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id  INTEGER,
            host     TEXT,
            port     TEXT,
            proto    TEXT,
            service  TEXT,
            version  TEXT,
            state    TEXT,
            banner   TEXT
        );
        CREATE TABLE IF NOT EXISTS vulns (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER,
            host       TEXT,
            service    TEXT,
            port       TEXT,
            risk       TEXT,
            cve        TEXT,
            cvss       REAL,
            title      TEXT,
            mitre_id   TEXT,
            mitre_tech TEXT,
            compliance TEXT
        );
        CREATE TABLE IF NOT EXISTS timeline (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id  INTEGER,
            ts       TEXT,
            stage    TEXT,
            message  TEXT,
            level    TEXT
        );
        CREATE TABLE IF NOT EXISTS finding_evidence (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id          INTEGER,
            finding_type     TEXT,
            title            TEXT,
            source_url       TEXT,
            status_code      INTEGER,
            response_headers TEXT,
            method           TEXT,
            surface          TEXT,
            ts               TEXT,
            notes            TEXT
        );
        CREATE TABLE IF NOT EXISTS api_endpoints (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id          INTEGER,
            url              TEXT NOT NULL,
            path             TEXT,
            status_code      INTEGER,
            api_type         TEXT,
            auth_surface     TEXT,
            found_at         TEXT,
            source_url       TEXT,
            response_headers TEXT,
            method           TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER,
            target      TEXT,
            fingerprint TEXT,
            severity    TEXT,
            confidence  TEXT,
            source      TEXT,
            category    TEXT,
            title       TEXT,
            host        TEXT,
            port        TEXT,
            url         TEXT,
            parameter   TEXT,
            cve         TEXT,
            cvss        REAL,
            kev         INTEGER DEFAULT 0,
            epss        REAL DEFAULT 0,
            data        TEXT,
            created     TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target, fingerprint);
        CREATE TABLE IF NOT EXISTS finding_triage (
            target      TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            status      TEXT NOT NULL,
            note        TEXT,
            updated     TEXT,
            PRIMARY KEY (target, fingerprint)
        );
        CREATE TABLE IF NOT EXISTS api_vulnerabilities (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER,
            url          TEXT,
            vuln_type    TEXT,
            severity     TEXT,
            description  TEXT,
            discovered_at TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        """)
        # Migration: add scan_type to a scans table created before this column existed.
        cols = [r[1] for r in c.execute("PRAGMA table_info(scans)").fetchall()]
        if "scan_type" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN scan_type TEXT DEFAULT 'recon'")
        self.conn.commit()

    def new_scan(self, target: str, profile: str, scan_type: str = "recon") -> int:
        with self._lock:
            c = self.conn.cursor()
            c.execute("INSERT INTO scans(target,profile,started,status,scan_type) VALUES(?,?,?,?,?)",
                      (target, profile, datetime.now().isoformat(), "running", scan_type))
            self.conn.commit()
            return c.lastrowid

    def finish_scan(self, scan_id: int, summary: dict):
        with self._lock:
            c = self.conn.cursor()
            c.execute("UPDATE scans SET finished=?,status=?,summary=? WHERE id=?",
                      (datetime.now().isoformat(), "complete",
                       json.dumps(summary), scan_id))
            self.conn.commit()

    def set_scan_status(self, scan_id: int, status: str):
        """Finalise a scan that did not complete (stopped / failed)."""
        with self._lock:
            self.conn.execute("UPDATE scans SET finished=?,status=? WHERE id=?",
                              (datetime.now().isoformat(), status, scan_id))
            self.conn.commit()

    def mark_stale_scans(self) -> int:
        """Mark scans left in 'running' by a previous crashed/closed session as interrupted.

        Call once at application start-up, before any new scan is created.
        """
        with self._lock:
            cur = self.conn.execute(
                "UPDATE scans SET status='interrupted' WHERE status='running'")
            self.conn.commit()
            return cur.rowcount

    def add_host(self, scan_id, addr, hostname="", os_guess="", status="up"):
        with self._lock:
            self.conn.execute(
                "INSERT INTO hosts(scan_id,address,hostname,os_guess,status) VALUES(?,?,?,?,?)",
                (scan_id, addr, hostname, os_guess, status))
            self.conn.commit()

    def add_port(self, scan_id, host, port, proto, service, version, state, banner=""):
        with self._lock:
            self.conn.execute(
                "INSERT INTO ports(scan_id,host,port,proto,service,version,state,banner) VALUES(?,?,?,?,?,?,?,?)",
                (scan_id, host, port, proto, service, version, state, banner))
            self.conn.commit()

    def add_vuln(self, scan_id, host, service, port, risk, cve, cvss, title, mitre_id="", mitre_tech="", compliance=""):
        with self._lock:
            self.conn.execute(
                "INSERT INTO vulns(scan_id,host,service,port,risk,cve,cvss,title,mitre_id,mitre_tech,compliance) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, host, service, port, risk, cve, cvss, title, mitre_id, mitre_tech, compliance))
            self.conn.commit()

    def add_timeline(self, scan_id, stage, message, level="info"):
        with self._lock:
            self.conn.execute(
                "INSERT INTO timeline(scan_id,ts,stage,message,level) VALUES(?,?,?,?,?)",
                (scan_id, datetime.now().isoformat(), stage, message, level))
            self.conn.commit()

    def add_evidence(self, scan_id, finding_type, title, source_url="", status_code=0,
                     response_headers="", method="GET", surface="public", notes=""):
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO finding_evidence(
                    scan_id,finding_type,title,source_url,status_code,response_headers,
                    method,surface,ts,notes
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    scan_id,
                    finding_type,
                    title,
                    source_url,
                    status_code,
                    response_headers,
                    method,
                    surface,
                    datetime.now().isoformat(),
                    notes,
                ),
            )
            self.conn.commit()

    # ── structured findings, triage and scan-to-scan diff ──────────────────
    TRIAGE_STATUSES = ("open", "fixed", "accepted", "false_positive")

    def add_finding(self, scan_id: int, target: str, f: dict):
        with self._lock:
            self.conn.execute(
                "INSERT INTO findings(scan_id,target,fingerprint,severity,confidence,source,category,"
                "title,host,port,url,parameter,cve,cvss,kev,epss,data,created) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, target, f.get("fingerprint", ""), f.get("severity", "INFO"),
                 f.get("confidence", ""), f.get("source", ""), f.get("category", ""),
                 f.get("title", ""), f.get("host", ""), str(f.get("port", "")), f.get("url", ""),
                 f.get("parameter", ""), f.get("cve", ""), float(f.get("cvss") or 0.0),
                 1 if f.get("kev") else 0, float(f.get("epss") or 0.0),
                 json.dumps(f, ensure_ascii=False), datetime.now().isoformat()))
            self.conn.commit()

    def get_scan(self, scan_id: int):
        with self._lock:
            row = self.conn.execute(
                "SELECT id,target,profile,started,finished,status,summary,scan_type FROM scans WHERE id=?",
                (scan_id,)).fetchone()
        if not row:
            return None
        try:
            summary = json.loads(row[6]) if row[6] else {}
        except Exception:
            summary = {}
        return {"id": row[0], "target": row[1], "profile": row[2], "started": row[3],
                "finished": row[4], "status": row[5], "summary": summary, "scan_type": row[7] or "recon"}

    def list_scans(self, limit: int = 200):
        with self._lock:
            rows = self.conn.execute(
                "SELECT s.id,s.target,s.profile,s.started,s.finished,s.status,"
                " (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id),"
                " (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id AND f.severity IN ('CRITICAL','HIGH')"
                "         AND f.confidence='confirmed'), s.scan_type"
                " FROM scans s ORDER BY s.id DESC LIMIT ?", (int(limit),)).fetchall()
        return [{"id": r[0], "target": r[1], "profile": r[2], "started": r[3], "finished": r[4],
                 "status": r[5], "findings": r[6], "confirmed_high": r[7], "scan_type": r[8] or "recon"} for r in rows]

    def get_findings(self, scan_id: int):
        """Structured findings of one scan, each with its triage status for that target."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT f.data, f.target, f.fingerprint, COALESCE(t.status,'open'), COALESCE(t.note,'')"
                " FROM findings f LEFT JOIN finding_triage t"
                "   ON t.target=f.target AND t.fingerprint=f.fingerprint"
                " WHERE f.scan_id=? ORDER BY f.id", (scan_id,)).fetchall()
        out = []
        for data, target, fp, status, note in rows:
            try:
                d = json.loads(data)
            except Exception:
                d = {"fingerprint": fp}
            d.update(target=target, fingerprint=fp, triage=status, triage_note=note)
            out.append(d)
        return out

    def set_triage(self, target: str, fingerprint: str, status: str, note: str = ""):
        if status not in self.TRIAGE_STATUSES:
            raise ValueError(f"status must be one of {self.TRIAGE_STATUSES}")
        with self._lock:
            self.conn.execute(
                "INSERT INTO finding_triage(target,fingerprint,status,note,updated) VALUES(?,?,?,?,?) "
                "ON CONFLICT(target,fingerprint) DO UPDATE SET status=excluded.status,"
                " note=excluded.note, updated=excluded.updated",
                (target, fingerprint, status, (note or "")[:500], datetime.now().isoformat()))
            self.conn.commit()

    def previous_scan_id(self, target: str, before_id: int):
        """Most recent *completed* scan of the same target before ``before_id`` (or None)."""
        with self._lock:
            row = self.conn.execute(
                "SELECT id FROM scans WHERE target=? AND id<? AND status='complete' "
                "ORDER BY id DESC LIMIT 1", (target, before_id)).fetchone()
        return row[0] if row else None

    def diff_scans(self, old_id: int, new_id: int):
        """Compare two scans by finding fingerprint -> {'new', 'fixed', 'persisting'}."""
        old = {f["fingerprint"]: f for f in self.get_findings(old_id)}
        new = {f["fingerprint"]: f for f in self.get_findings(new_id)}
        return {
            "old_scan": old_id, "new_scan": new_id,
            "new": [new[k] for k in new if k not in old],
            "fixed": [old[k] for k in old if k not in new],
            "persisting": [new[k] for k in new if k in old],
        }

    def get_all_scans(self):
        c = self.conn.cursor()
        c.execute("SELECT id,target,profile,started,finished,status FROM scans ORDER BY id DESC")
        return c.fetchall()

    def get_scan_vulns(self, scan_id):
        c = self.conn.cursor()
        c.execute("SELECT * FROM vulns WHERE scan_id=?", (scan_id,))
        return c.fetchall()

    def get_scan_ports(self, scan_id):
        c = self.conn.cursor()
        c.execute("SELECT * FROM ports WHERE scan_id=?", (scan_id,))
        return c.fetchall()
    
    def get_scan_data(self, scan_id):
        """Get all scan data for comparison"""
        c = self.conn.cursor()
        
        # Get scan info
        c.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
        scan_info = c.fetchone()
        
        # Get hosts
        c.execute("SELECT address, hostname, os_guess, status FROM hosts WHERE scan_id=?", (scan_id,))
        hosts = c.fetchall()
        
        # Get ports/services
        c.execute("SELECT host, port, proto, service, version, state, banner FROM ports WHERE scan_id=?", (scan_id,))
        services = c.fetchall()
        
        # Get vulnerabilities
        c.execute("SELECT host, service, port, risk, cve, cvss, title FROM vulns WHERE scan_id=?", (scan_id,))
        vulns = c.fetchall()
        
        return {
            'scan_info': scan_info,
            'hosts': hosts,
            'services': services,
            'vulns': vulns
        }

class _LazyDatabase:
    """Opens the SQLite database on first use, so importing the package has no side effects."""
    _instance = None

    def __getattr__(self, name):
        if _LazyDatabase._instance is None:
            _LazyDatabase._instance = Database()
        return getattr(_LazyDatabase._instance, name)


DB = _LazyDatabase()

# 
#  CVE / VULN KNOWLEDGE BASE
# 
# Each entry may carry a "match" regex that is tested against the detected
# product/version/banner text. A CVE is only reported when its rule matches (or when a
# tool such as an nmap vuln script names the CVE id in its output) - see matched_cves().
# Entries without "match" cannot be confirmed from a version string alone and are never
# asserted just because a port is open.
CVE_DB = {
    "ftp": [
        {"cve":"CVE-2011-2523","cvss":10.0,"title":"vsftpd 2.3.4 Backdoor RCE",
         "match": r"vsftpd\s*2\.3\.4\b",
         "mitre":"T1190","tech":"Exploit Public-Facing Application",
         "compliance":"PCI-DSS:6.3.3,NIST:SI-2"},
        {"cve":"CVE-1999-0497","cvss":7.5,"title":"FTP Anonymous Login Enabled",
         "match": r"anonymous ftp login allowed",
         "mitre":"T1078","tech":"Valid Accounts",
         "compliance":"PCI-DSS:8.2,CIS:4.1"},
    ],
    "ssh": [
        {"cve":"CVE-2018-15473","cvss":5.3,"title":"OpenSSH Username Enumeration",
         "match": r"openssh[ _/]?(?:[1-6]\.\d|7\.[0-6])(?!\d)",
         "mitre":"T1592","tech":"Gather Victim Identity Information",
         "compliance":"NIST:IA-3,HIPAA:164.312(d)"},
        {"cve":"CVE-2023-38408","cvss":9.8,"title":"OpenSSH Remote Code Execution via ssh-agent",
         "mitre":"T1021.004","tech":"Remote Services: SSH",
         "compliance":"PCI-DSS:6.3.3,NIST:SI-2"},
    ],
    "http": [
        {"cve":"CVE-2021-41773","cvss":9.8,"title":"Apache 2.4.49 Path Traversal & RCE",
         "match": r"apache(?: httpd)?[ /]2\.4\.49\b",
         "mitre":"T1190","tech":"Exploit Public-Facing Application",
         "compliance":"PCI-DSS:6.4,OWASP:A01"},
        {"cve":"CVE-2021-42013","cvss":9.8,"title":"Apache 2.4.50 RCE (Bypass of CVE-2021-41773)",
         "match": r"apache(?: httpd)?[ /]2\.4\.(?:49|50)\b",
         "mitre":"T1059","tech":"Command and Scripting Interpreter",
         "compliance":"PCI-DSS:6.3.3,NIST:SI-2"},
    ],
    "https": [
        {"cve":"CVE-2014-0160","cvss":7.5,"title":"OpenSSL Heartbleed Memory Disclosure",
         "match": r"openssl[ /]1\.0\.1[a-f]?(?![\w.])",
         "mitre":"T1552","tech":"Unsecured Credentials",
         "compliance":"PCI-DSS:4.2.1,HIPAA:164.312(e)"},
        {"cve":"CVE-2016-2107","cvss":5.9,"title":"OpenSSL AES-NI Padding Oracle (POODLE)",
         "mitre":"T1557","tech":"Adversary-in-the-Middle",
         "compliance":"PCI-DSS:4.2.1"},
    ],
    "mysql": [
        {"cve":"CVE-2012-2122","cvss":7.5,"title":"MySQL Authentication Bypass",
         "mitre":"T1078","tech":"Valid Accounts",
         "compliance":"PCI-DSS:8.3,CIS:5.4"},
        {"cve":"CVE-2016-6662","cvss":9.8,"title":"MySQL Remote Code Execution via Config",
         "mitre":"T1190","tech":"Exploit Public-Facing Application",
         "compliance":"PCI-DSS:6.3.3"},
    ],
    "rdp": [
        {"cve":"CVE-2019-0708","cvss":9.8,"title":"BlueKeep  RDP Pre-Auth RCE",
         "mitre":"T1210","tech":"Exploitation of Remote Services",
         "compliance":"PCI-DSS:6.3.3,NIST:SI-2"},
        {"cve":"CVE-2019-1182","cvss":9.8,"title":"DejaBlue  RDP Wormable RCE",
         "mitre":"T1210","tech":"Exploitation of Remote Services",
         "compliance":"PCI-DSS:6.3.3"},
    ],
    "smb": [
        {"cve":"CVE-2017-0144","cvss":9.3,"title":"EternalBlue  SMBv1 RCE (WannaCry)",
         "mitre":"T1210","tech":"Exploitation of Remote Services",
         "compliance":"PCI-DSS:6.3.3,CIS:3.3"},
        {"cve":"CVE-2020-0796","cvss":10.0,"title":"SMBGhost  SMBv3 RCE",
         "mitre":"T1210","tech":"Exploitation of Remote Services",
         "compliance":"PCI-DSS:6.3.3,NIST:SI-2"},
    ],
    "http-alt": [
        {"cve":"CVE-2020-1938","cvss":9.8,"title":"Ghostcat  Apache Tomcat AJP File RCE",
         "mitre":"T1190","tech":"Exploit Public-Facing Application",
         "compliance":"PCI-DSS:6.3.3,OWASP:A05"},
    ],
    "telnet": [
        {"cve":"CVE-2011-4862","cvss":10.0,"title":"BSD Telnet Remote Command Execution",
         "mitre":"T1021","tech":"Remote Services",
         "compliance":"PCI-DSS:2.2.1,NIST:CM-7"},
    ],
}

def matched_cves(service: str, version: str = "", banner: str = "") -> list:
    """Return only the CVE_DB entries that the evidence actually supports.

    A CVE is returned when its "match" rule matches the detected product/version/banner,
    or when the CVE id itself appears in tool output (e.g. an nmap vuln script). An open
    port on its own is never enough.
    """
    haystack = f"{version or ''} {banner or ''}".lower()
    if not haystack.strip():
        return []
    # Apache httpd rules apply to any web port, whatever nmap called the service.
    names = [service.lower()]
    if names[0] in ("https", "http-alt", "http-proxy", "ssl/http"):
        names.append("http")
    seen, out = set(), []
    for name in names:
        for entry in CVE_DB.get(name, []):
            if entry["cve"] in seen:
                continue
            rule = entry.get("match")
            if entry["cve"].lower() in haystack or (rule and re.search(rule, haystack)):
                seen.add(entry["cve"])
                out.append(entry)
    return out


_TARGET_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                             r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_TARGET_IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/(\d{1,2}))?$")


def normalize_target(raw: str) -> str:
    """Validate a user-supplied target and return it as a bare hostname / IPv4 / CIDR.

    Accepts an optional scheme, port and path (which are stripped). Raises ValueError for
    anything else - in particular values starting with '-' that external tools such as
    nmap would interpret as command-line options.
    """
    t = (raw or "").strip()
    if not t:
        raise ValueError("Target is empty.")
    if "://" in t:
        t = t.split("://", 1)[1]
    m = _TARGET_IP_RE.match(t.split("?")[0].rstrip("/"))
    if m:
        if any(int(o) > 255 for o in m.groups()[:4]) or (m.group(6) and int(m.group(6)) > 32):
            raise ValueError(f"'{raw}' is not a valid IPv4 address / CIDR range.")
        return m.group(0)
    t = t.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in t:
        raise ValueError("Targets with embedded credentials (user@host) are not supported.")
    t = t.rsplit(":", 1)[0] if re.search(r":\d{1,5}$", t) else t
    if not _TARGET_HOST_RE.match(t):
        raise ValueError(f"'{raw}' is not a valid hostname, IPv4 address or CIDR range.")
    return t.lower()


def seed_url_from_target(raw: str):
    """If the user named an explicit scheme and/or port, return ('http'|'https', host, port).

    'http://app.local:3000/shop' -> ('http', 'app.local', 3000). A bare hostname returns
    None. Without this the port in the target would be thrown away and an application on
    a non-standard port would never be scanned.
    """
    t = (raw or "").strip()
    try:
        if "://" in t:
            parts = urllib.parse.urlsplit(t)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                return None
            port = parts.port or (443 if parts.scheme == "https" else 80)
            scheme, host = parts.scheme, parts.hostname
        else:
            m = re.match(r"^([A-Za-z0-9.-]+):(\d{1,5})(?:/.*)?$", t)
            if not m:
                return None
            host, port = m.group(1), int(m.group(2))
            scheme = "https" if port in (443, 8443, 4443) else "http"
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None
    return scheme, host.lower(), port


def esc(value) -> str:
    """HTML-escape any value that originates from a scan before it goes into a report."""
    return _html.escape("" if value is None else str(value), quote=True)


MITRE_TACTICS = {
    "T1190": "Initial Access",  "T1078": "Defense Evasion",
    "T1592": "Reconnaissance",  "T1021.004": "Lateral Movement",
    "T1552": "Credential Access","T1557": "Collection",
    "T1210": "Lateral Movement","T1059": "Execution",
    "T1021": "Lateral Movement",
}

# 
#  SCAN PROFILES
# 
# SYN scan (default, no --unprivileged) is used for standard Ethernet/Wi-Fi adapters.
# If nmap fails with "Only ethernet devices..." (e.g. VPN/WARP active), the pipeline
# automatically falls back to socket-based TCP connect scan.
SCAN_PROFILES = {
    "Quick":   {"nmap_flags": ["-sV", "-T4", "--top-ports", "100"], "timeout": 180,  "nikto": True, "desc": "Top 100 ports, fast, with Nikto"},
    "Full":    {"nmap_flags": ["-sV", "-T4", "-p-"],                 "timeout": 1200, "nikto": True,  "desc": "All 65535 ports, scripts"},
    "Stealth": {"nmap_flags": ["-sT", "-T2", "--top-ports", "1000"], "timeout": 600,  "nikto": False, "desc": "TCP-connect stealth, slow"},
    "Custom":  {"nmap_flags": ["-sV", "-T3", "--top-ports", "500"],  "timeout": 600,  "nikto": True,  "desc": "Report-7 compatible: reliable scan"},
}

# 
#  STYLESHEET BUILDER
# 
def build_stylesheet(t: dict) -> str:
    return f"""
* {{ outline:none; }}
QMainWindow,QWidget {{ background:{t['BG']};color:{t['TEXT']};font-family:monospace;font-size:9.5px; }}
QGroupBox {{ border:1px solid {t['BORDER']};border-radius:4px;margin-top:10px;padding:12px 8px 8px;
background:{t['CARD']};font-weight:bold;font-size:10px;color:{t['CYAN']};letter-spacing:1.5px; }}
QGroupBox::title {{ subcontrol-origin:margin;subcontrol-position:top left;left:8px;top:0;padding:0 4px;
background:{t['CARD']};color:{t['CYAN']}; }}
QLabel {{ font-size:11px;color:{t['TEXT']}; }}
QLineEdit,QSpinBox,QComboBox {{ background:{t['CARD']};border:1px solid {t['BORDER']};border-radius:3px;
padding:5px 8px;color:{t['TEXT']};font-size:12px;selection-background-color:{t['CYAN']}; }}
QLineEdit:focus,QComboBox:focus {{ border-color:{t['CYAN']}; }}
QComboBox::drop-down {{ border:none;width:16px; }}
QComboBox::down-arrow {{ image:none;border-left:3px solid transparent;border-right:3px solid transparent;
border-top:4px solid {t['TEXT2']}; }}
QComboBox QAbstractItemView {{ background:{t['CARD']};border:1px solid {t['BORDER']};color:{t['TEXT']};
selection-background-color:{t['CYAN']};padding:2px; }}
QPushButton {{ border-radius:4px;padding:6px 12px;font-weight:bold;font-size:10px; }}
QPushButton#startBtn {{ background-color:{t['CYAN']};color:#FFFFFF;font-weight:bold; }}
QPushButton#startBtn:hover {{ background-color:{t['BLUE']}; }}
QPushButton#startBtn:disabled {{ background:{t['BORDER']};color:{t['TEXT3']}; }}
QPushButton#stopBtn {{ background-color:{t['RED']};color:#FFFFFF; }}
QPushButton#exportBtn,QPushButton#histBtn,QPushButton#diffBtn {{ background:{t['CARD']};
color:{t['TEXT']};border:1px solid {t['BORDER']}; }}
QPushButton#exportBtn:hover,QPushButton#histBtn:hover,QPushButton#diffBtn:hover {{ border-color:{t['CYAN']}; }}
QPushButton#reportBtn {{ background-color:{t['GREEN']};color:#FFFFFF; }}
QPushButton#themeBtn {{ background:{t['CARD']};color:{t['TEXT2']};border:1px solid {t['BORDER']};
border-radius:3px;padding:4px 8px;font-size:8px; }}
QProgressBar {{ border:1px solid {t['BORDER']};border-radius:3px;background:{t['CARD2']};
height:6px;text-align:center;color:{t['TEXT']};font-size:7px; }}
QProgressBar::chunk {{ border-radius:3px;background-color:{t['CYAN']}; }}
QTextEdit {{ background-color:{t['CONSOLE_BG']};border:1px solid {t['BORDER']};border-radius:4px;
color:{t['CONSOLE_FG']};font-family:monospace;font-size:9.5px;padding:6px;selection-background-color:#1E3A5F; }}
QListWidget {{ background:{t['CARD']};border:1px solid {t['BORDER']};border-radius:4px;color:{t['TEXT']};
font-size:9.5px;padding:4px; }}
QListWidget::item {{ padding:4px; }}
QListWidget::item:selected {{ background:{t['CYAN']};color:#000000; }}
QTableWidget {{ background:{t['CARD']};gridline-color:{t['BORDER']};border:1px solid {t['BORDER']};
color:{t['TEXT']};font-size:9px; }}
QTableWidget::item {{ padding:4px; }}
QTableWidget::item:selected {{ background:{t['CYAN']};color:#000000; }}
QHeaderView::section {{ background:{t['BG']};color:{t['TEXT2']};padding:4px;border:none;
border-bottom:1px solid {t['BORDER']};font-size:8px;font-weight:bold;letter-spacing:1px; }}
QScrollBar:vertical {{ background:transparent;width:8px;margin:0; }}
QScrollBar::handle:vertical {{ background:{t['BORDER']};border-radius:4px;min-height:20px; }}
QScrollBar::handle:vertical:hover {{ background:{t['CYAN']}; }}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{ height:0;border:none; }}
QScrollBar:horizontal {{ background:transparent;height:8px;margin:0; }}
QScrollBar::handle:horizontal {{ background:{t['BORDER']};border-radius:4px;min-width:20px; }}
QScrollBar::handle:horizontal:hover {{ background:{t['CYAN']}; }}
QSplitter::handle {{ background:{t['BORDER']};width:1px; }}
QTabWidget::pane {{ border:1px solid {t['BORDER']};background:{t['CARD']}; }}
QTabBar::tab {{ background:{t['CARD2']};color:{t['TEXT2']};padding:4px 12px;border:1px solid transparent;
font-size:8.5px;font-weight:bold;min-width:60px; }}
QTabBar::tab:selected {{ background:{t['CARD']};color:{t['CYAN']};border:1px solid {t['BORDER']}; }}
QTreeWidget {{ background:{t['CARD']};border:1px solid {t['BORDER']};color:{t['TEXT']}; }}
QTreeWidget::item {{ padding:3px; }}
QTreeWidget::item:selected {{ background:{t['CYAN']};color:#000000; }}
QCheckBox {{ color:{t['TEXT']};font-size:11px;spacing:6px; }}
QCheckBox::indicator {{ width:16px;height:16px;border-radius:2px;border:1px solid {t['BORDER']};
background:{t['CARD']}; }}
QCheckBox::indicator:checked {{ background:{t['CYAN']};border-color:{t['CYAN']}; }}
QToolTip {{ background:{t['CARD']};color:{t['TEXT']};border:1px solid {t['BORDER']};padding:4px;
border-radius:3px;font-size:8.5px; }}
"""

class CmdResult(str):
    """Result of ScanEngine.run_cmd().

    It IS the command's combined stdout+stderr text (a plain ``str`` subclass), so
    legacy checks like ``"__NOTFOUND__" in out`` keep working unchanged. It also
    carries a structured ``status`` plus convenience flags so new code can branch
    cleanly instead of sniffing magic strings:

        out = self.run_cmd([...])
        if out.not_found:   ...      # instead of: if "__NOTFOUND__" in out
        if out.timed_out:   ...
        if out.ok:          ...
    """
    def __new__(cls, text, status="ok", cmd=None):
        obj = super().__new__(cls, text)
        obj.status = status          # ok | not_found | timeout | error
        obj.cmd = cmd
        return obj

    @property
    def ok(self):         return self.status == "ok"
    @property
    def failed(self):     return self.status != "ok"
    @property
    def not_found(self):  return self.status == "not_found"
    @property
    def timed_out(self):  return self.status == "timeout"
    @property
    def errored(self):    return self.status == "error"


#
#  ADVANCED SCAN ENGINE
#
def openvas_unavailable_reason() -> str:
    """Explain precisely why the OpenVAS stage cannot run, with the fix."""
    try:
        from danishrecon import openvas_scanner as _ov
        gvm_ok = bool(getattr(_ov, "GVM_AVAILABLE", False))
        host, port = getattr(_ov, "GVM_HOST", "127.0.0.1"), getattr(_ov, "GVM_PORT", 9390)
    except Exception:
        gvm_ok, host, port = False, "127.0.0.1", 9390
    if not gvm_ok:
        return 'the GMP client is not installed (pip install "danishrecon[openvas]")'
    try:
        with socket.create_connection((host, port), timeout=2):
            return f"{host}:{port} is open but GMP login failed (check GVM_USER / GVM_PASSWORD in .env)"
    except OSError:
        pass
    from danishrecon.tools import docker_running
    if not shutil.which("docker"):
        return "Docker is not installed (OpenVAS runs as a container - install Docker Desktop)"
    if not docker_running():
        return "Docker is not running (start Docker Desktop, then: danishrecon setup openvas)"
    return f"no OpenVAS container is listening on {host}:{port} (start one: danishrecon setup openvas)"


def find_rustscan():
    """Locate the RustScan binary (optional fast port discovery). Returns a path or None.

    RustScan is NOT required: when absent, the engine uses nmap for port discovery as before.
    """
    exe = "rustscan" + (".exe" if os.name == "nt" else "")
    cand = [str(_tool_bin("rustscan")), shutil.which("rustscan"),
            os.path.join(os.path.expanduser("~"), ".cargo", "bin", exe),
            r"C:\Program Files\RustScan\rustscan.exe" if os.name == "nt" else "/usr/local/bin/rustscan",
            "/usr/bin/rustscan"]
    for p in cand:
        if p and os.path.isfile(p):
            return p
    return None


def parse_rustscan_ports(text: str) -> list:
    """Parse RustScan greppable output ('1.2.3.4 -> [80,443,8080]') into a sorted port list."""
    ports = set()
    for m in re.finditer(r"->\s*\[([0-9,\s]+)\]", text):
        for p in m.group(1).split(","):
            p = p.strip()
            if p.isdigit() and 0 < int(p) < 65536:
                ports.add(int(p))
    return sorted(ports)


def parse_ssl_enum_ciphers(text: str) -> dict:
    """Parse nmap ssl-enum-ciphers output -> least strength, weak suites (grade C or worse), warnings."""
    least = re.search(r"least strength:\s*([A-F])", text)
    weak, warnings, proto = [], [], ""
    for line in text.splitlines():
        line = line.strip().lstrip("|_ ").strip()
        m = re.match(r"^(SSLv\d(?:\.\d)?|TLSv\d\.\d):", line)
        if m:
            proto = m.group(1)
            continue
        m = re.match(r"^(TLS_\S+|SSL_\S+)\s.*-\s([A-F])$", line)
        if m and m.group(2) in "CDEF":
            entry = f"{proto} {m.group(1)} ({m.group(2)})".strip()
            if entry not in weak:
                weak.append(entry)
            continue
        if proto and line and not line.startswith(("ciphers", "compressors", "cipher preference", "warnings",
                                                   "NULL", "TLS_", "SSL_", "least strength")) \
                and re.search(r"vulnerable|deprecated|weak|insecure|broken|SWEET32|64-bit block|RC4|lower strength", line, re.I):
            if line not in warnings:
                warnings.append(line)
    return {"least_strength": least.group(1) if least else "", "weak_ciphers": weak, "warnings": warnings}


class _ScanStopped(Exception):
    """Raised inside the pipeline when the user stops the scan."""


class ScanEngine:

    def __init__(self, target: str, profile: str = "Custom", options: dict = None):
        for _sig in ('log_signal', 'progress_signal', 'result_signal', 'stage_signal', 'chart_signal', 'scan_complete', 'stopped'):
            setattr(self, _sig, Signal())
        # Validate + normalise the target (raises ValueError on anything that is not a
        # hostname / IPv4 / CIDR, so nothing unvalidated ever reaches nmap, nikto, etc.)
        _raw_target = target
        target = normalize_target(target)
        # explicit scheme/port given by the user (e.g. http://host:3000) - always scanned
        self.seed = seed_url_from_target(_raw_target)
        if self.seed and self.seed[1] != target:
            self.seed = None

        self.target   = target
        self.original_target = target  # Preserve original hostname for SNI/CDN support
        self.profile  = profile
        self.opts     = options or {}
        self._stop    = False
        self._paused  = False
        self.started_at = datetime.now()
        self.ended_at = None
        self.scan_id  = DB.new_scan(target, profile)
        self.cfg      = SCAN_PROFILES.get(profile, SCAN_PROFILES["Custom"])
        self.data = {
            "scan_id":   self.scan_id,
            "target":    target,
            "profile":   profile,
            "timestamp": self.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "started_at": self.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "ended_at": "",
            "generated_at": "",
            "duration": "00:00:00",
            "duration_seconds": 0,
            "hosts": [], "services": [], "versions": [], "banners": [],
            "os_guesses": [], "dns_records": [], "ssl_issues": [],
            "vulnerabilities": [], "exploits": [], "attack_paths": [],
            "recommendations": [], "compliance": [],
            "api_endpoints": [], "api_count": 0,
            "auth_api_endpoints": [], "auth_api_count": 0,
            "secret_findings": [],
            "findings": [],          # structured findings (see findings.py)
            "crawled_urls": [], "param_urls": [], "forms": [], "technologies": [],
            "stage_errors": [],
            "authenticated": False, "post_request_count": 0, "tls_cipher_audit": [], "diff": None,
            "evidence": [],
            "port_states": {}, "risk_counts": {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0},
            "mitre_techniques": [],
            "gemini_analyses": {},  # AI-powered vulnerability explanations
            "crypto_analysis": {},  # NEW: Cryptography analysis results
            "nuclei_findings": [],  # Nuclei vulnerability scan results
            "compliance_recommendations": {},  # NEW: Compliance mapping
        }
        
        # Initialize Gemini Analyzer
        self.gemini_analyzer = None
        # Allow disabling Gemini via environment variable (useful if quota exhausted)
        disable_gemini = os.getenv('DISABLE_GEMINI', '').lower() in ('true', '1', 'yes')
        if GEMINI_AVAILABLE and not disable_gemini:
            try:
                self.gemini_analyzer = GeminiAnalyzer()
                if self.gemini_analyzer.enabled:
                    self.log("✓ Gemini API initialized for AI-powered analysis", "good")
                else:
                    self.log(f"⚠ Gemini API unavailable: {self.gemini_analyzer.error_message}", "warn")
            except Exception as e:
                self.log(f"⚠ Failed to initialize Gemini: {str(e)}", "warn")
        else:
            if disable_gemini:
                self.log("ℹ Gemini analysis disabled (DISABLE_GEMINI=true)", "info")
            else:
                self.log("ℹ Gemini module not available. AI analysis disabled.", "info")
        
        # Track which hosts have WAF protection (for Nikto hostname-first strategy)
        self.waf_hosts = set()  # Stores (host, port) tuples
        self.cdn_detected = False   # set by DNS recon / port scan when the target is behind a CDN
        self.cdn_provider = ""

        # Results directory for per-scan log files (used by OpenVAS stage, etc.)
        self.results_dir = RESULTS_DIR

        os.makedirs(RESULTS_DIR, exist_ok=True)

    def _format_dt(self, value):
        return value.strftime("%Y-%m-%d %H:%M:%S") if value else ""

    def _format_duration(self, total_seconds: int):
        total_seconds = max(int(total_seconds), 0)
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _sync_timing_data(self, ended_at=None, generated_at=None):
        effective_end = ended_at or self.ended_at
        effective_generated = generated_at or datetime.now()
        duration_base = effective_end or effective_generated
        duration_seconds = max(int((duration_base - self.started_at).total_seconds()), 0)

        self.data.update({
            "timestamp": self._format_dt(self.started_at),
            "started_at": self._format_dt(self.started_at),
            "ended_at": self._format_dt(effective_end),
            "generated_at": self._format_dt(effective_generated),
            "duration": self._format_duration(duration_seconds),
            "duration_seconds": duration_seconds,
        })

    def _mark_scan_completed(self):
        self.ended_at = datetime.now()
        self._sync_timing_data(ended_at=self.ended_at, generated_at=self.ended_at)

    def stop(self):
        self._stop = True
        if hasattr(self, 'dirbuster_engine') and self.dirbuster_engine:
            self.dirbuster_engine.stop()
    
    def pause(self):
        self._paused = True
        self.log_signal.emit("    Scan paused", "warn")
    
    def resume(self):
        self._paused = False
        self.log_signal.emit("    Scan resumed", "good")
    
    def is_paused(self):
        return self._paused
    
    def _wait_if_paused(self):
        """Block execution while paused"""
        while self._paused and not self._stop:
            time.sleep(0.1)

    def log(self, msg, level="info"):
        if self._stop: return
        DB.add_timeline(self.scan_id, self.current_stage if hasattr(self,'current_stage') else "init", msg, level)
        self.log_signal.emit(msg, level)

    def prog(self, bar, val):
        self.progress_signal.emit(bar, val)

    def run_cmd(self, cmd, timeout=120):
        """Run an external command and return a CmdResult (a str carrying status).

        Backward-compatible: the returned value still contains the __NOTFOUND__ /
        __TIMEOUT__ / __ERROR__ sentinels in its text, so existing `in out` checks
        keep working. Prefer the structured flags (out.not_found / out.timed_out /
        out.ok) in new code.
        """
        if self._stop:
            return CmdResult("", status="ok", cmd=cmd)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, errors='replace')
            return CmdResult(r.stdout + r.stderr, status="ok", cmd=cmd)
        except FileNotFoundError:
            return CmdResult(f"__NOTFOUND__{cmd[0]}", status="not_found", cmd=cmd)
        except subprocess.TimeoutExpired as e:
            # Capture any partial output before timeout
            partial_out = ""
            if e.stdout:
                # Already a string due to text=True in subprocess.run()
                partial_out += e.stdout if isinstance(e.stdout, str) else e.stdout.decode('utf-8', errors='replace')
            if e.stderr:
                partial_out += e.stderr if isinstance(e.stderr, str) else e.stderr.decode('utf-8', errors='replace')
            # Return timeout marker but preserve partial output for diagnostics
            return CmdResult(f"__TIMEOUT__{partial_out}", status="timeout", cmd=cmd)
        except Exception as e:
            # An unexpected failure — previously swallowed silently. Log it so it's visible.
            try:
                self.log(f"  command error ({cmd[0] if cmd else '?'}): {e}", "error")
            except Exception:
                pass
            return CmdResult(f"__ERROR__{e}", status="error", cmd=cmd)

    #  SSL/TLS Analysis 
    def _record_finding(self, risk, text, host="", service="", port="", cvss=None, title=None):
        """Add one finding to the report list, the risk counters and the database."""
        label = f"[{risk}] {text}"
        if label in self.data["vulnerabilities"]:
            return
        self.data["vulnerabilities"].append(label)
        self.data["risk_counts"][risk] = self.data["risk_counts"].get(risk, 0) + 1
        if cvss is None:
            cvss = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0}.get(risk, 3.0)
        DB.add_vuln(self.scan_id, host or self.target, service, str(port), risk, "", cvss, title or text)

    def stage_ssl_analysis(self, hosts):
        self.current_stage = "ssl"
        self.log(" SSL/TLS CERTIFICATE ANALYSIS ", "stage")
        self.stage_signal.emit("SSL/TLS Analysis")
        self.prog("misc", 40)  # Continue from DNS
        issues = []
        total_hosts = len(hosts) if hosts else 1
        progress_increment = 15 // max(total_hosts, 1)  # 40% to 55%

        if not CRYPTO_ANALYZER_AVAILABLE:
            self.log("  TLS analyzer module not available - skipping certificate checks", "warn")
            self.data["ssl_issues"] = issues
            return issues

        for idx, host in enumerate(hosts):
            if self._stop:
                break
            for port in (443, 8443):
                info = fetch_certificate(host, port, timeout=5)
                if not info["reachable"]:
                    continue  # no TLS service on this port - nothing to report

                where = f"{host}:{port}"
                self.log(f"  SSL {where}  {info['protocol']}, cipher={info['cipher'] or '?'}", "info")
                found = []  # (risk, message)

                days = info["days_remaining"]
                if info["expired"]:
                    found.append(("HIGH", f"EXPIRED CERT on {where} (expired {-days}d ago)"))
                elif not info["trusted"]:
                    found.append(("MEDIUM", f"UNTRUSTED CERT on {where}: {info['trust_error'] or 'verification failed'}"))
                elif days is not None and days < 30:
                    found.append(("LOW", f"CERT EXPIRING SOON: {where} ({days}d)"))
                elif days is not None:
                    self.log(f"  SSL cert valid: {where}, {days}d remaining", "good")

                cipher_name = (info["cipher"] or "").upper()
                if any(x in cipher_name for x in ("RC4", "3DES", "DES-CBC", "EXPORT", "NULL", "ANON")):
                    found.append(("HIGH", f"WEAK CIPHER negotiated on {where}: {info['cipher']}"))

                if info["protocol"] in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    found.append(("MEDIUM", f"OLD TLS negotiated on {where}: {info['protocol']}"))

                for risk, msg in found:
                    issues.append(msg)
                    color = "#EF4444" if risk == "HIGH" else "#F59E0B"
                    self.result_signal.emit("SSL Issues", f" {msg}", color)
                    self._record_finding(risk, msg, host=host, service="tls", port=port)

            # Increment progress per host
            self.prog("misc", 40 + ((idx + 1) * progress_increment))

        self.data["ssl_issues"] = issues
        return issues

    def stage_dns_recon(self):
        self.current_stage = "dns"
        self.log(" DNS RECONNAISSANCE ", "stage")
        self.stage_signal.emit("DNS Recon")
        self.prog("misc", 10)
        
        # Early CDN detection based on hostname patterns
        hostname_cdn_patterns = {
            "vercel": ["vercel", ".app"],
            "cloudflare": ["cloudflare", "cf.workers.dev"],
            "netlify": ["netlify"],
            "github": ["github.io", "pages.github.com"],
            "railway": ["railway"],
            "heroku": ["herokuapp.com"],
        }
        
        for cdn_name, patterns in hostname_cdn_patterns.items():
            if any(pattern in self.original_target.lower() for pattern in patterns):
                self.log(f"   CDN detected (hostname): {cdn_name.title()}  port scanning may not work", "warn")
                self.result_signal.emit("WAF/Firewall", f" {cdn_name.title()} CDN detected (via hostname)", Theme.current["ORANGE"])
                break
        
        is_domain = not re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d+)?$', self.target)
        records = []

        if not is_domain:
            self.log("  Target is IP  skipping DNS recon", "muted")
            self.prog("misc", 40)
            return records

        record_types = ["A","AAAA","MX","NS","TXT","CNAME","SOA"]
        cdn_detected = False
        cdn_provider = ""
        
        for rtype in record_types:
            out = self.run_cmd(["dig", "+short", rtype, self.target], timeout=10)
            if "__NOTFOUND__" in out:
                out = self.run_cmd(["nslookup", f"-type={rtype}", self.target], timeout=10)
            if out and "__" not in out:
                for line in out.splitlines():
                    line = line.strip()
                    if line:
                        entry = f"{rtype}: {line}"
                        records.append(entry)
                        self.log(f"  DNS {entry}", "info")
                        self.result_signal.emit("DNS Records", entry, Theme.current["TEXT"])
                        
                        # CDN detection
                        cdn_indicators = {
                            "vercel": ["vercel", "cname.vercel-dns.com"],
                            "cloudflare": ["cloudflare", "cdn.cloudflare"],
                            "fastly": ["fastly"],
                            "akamai": ["akamai", "edgesuite.net", "edgekey.net"],
                            "cloudfront": ["cloudfront", "amazonaws"],
                            "netlify": ["netlify"],
                        }
                        for cdn, indicators in cdn_indicators.items():
                            if any(ind in line.lower() for ind in indicators):
                                cdn_detected = True
                                cdn_provider = cdn.title()
                        
                        # SPF / DMARC / DKIM checks
                        if rtype == "TXT":
                            if "v=spf1" in line.lower():
                                self.result_signal.emit("DNS Records", "   SPF record found", Theme.current["GREEN"])
                            if "v=dmarc1" in line.lower():
                                self.result_signal.emit("DNS Records", "   DMARC policy found", Theme.current["GREEN"])
                            if "v=dkim1" in line.lower():
                                self.result_signal.emit("DNS Records", "   DKIM record found", Theme.current["GREEN"])
                            if "v=spf1" not in line.lower() and rtype == "TXT" and len(records) > 3:
                                pass  # not a SPF warn here
        
        # CDN warning
        if cdn_detected:
            self.cdn_detected = True
            self.cdn_provider = cdn_provider
            self.log(f"   CDN detected: {cdn_provider} — only web ports are exposed; OS fingerprinting is not possible", "warn")
            self.result_signal.emit("WAF/Firewall", f" {cdn_provider} CDN detected", Theme.current["ORANGE"])
            self.result_signal.emit("WAF/Firewall", "   Only 80/443 are reachable — using a fast web-port scan", Theme.current["CYAN"])
            self.result_signal.emit("WAF/Firewall", f"   {cdn_provider} provides DDoS protection and WAF", Theme.current["GREEN"])

        # Check missing SPF / DMARC
        has_spf   = any("v=spf1" in r.lower() for r in records)
        has_dmarc = any("v=dmarc1" in r.lower() for r in records)
        if not has_spf:
            records.append(" NO SPF RECORD  email spoofing possible")
            self.result_signal.emit("DNS Records", " NO SPF  email spoofing risk", Theme.current["ORANGE"])
            self.data["vulnerabilities"].append("[MEDIUM] Missing SPF record - email spoofing possible")
        if not has_dmarc:
            records.append(" NO DMARC RECORD  phishing risk")
            self.result_signal.emit("DNS Records", " NO DMARC  phishing risk", Theme.current["ORANGE"])

        self.data["dns_records"] = records
        self.prog("misc", 40)
        return records

    #  Subdomain Discovery 
    def stage_subdomain_discovery(self):
        self.current_stage = "subdomain"
        self.log(" STAGE 1: SUBDOMAIN DISCOVERY ", "stage")
        self.stage_signal.emit("Subdomain Discovery")
        self.prog("host", 5)

        is_domain = not re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d+)?$', self.target)
        if not is_domain:
            self.log("  IP target  skipping subdomain enum", "muted")
            return [self.target]

        out = self.run_cmd(["subfinder", "-d", self.target, "-silent", "-t", "50"], timeout=60)
        if "__NOTFOUND__" in out:
            self.log("  subfinder not found  using target only", "warn")
            # Fallback: try common subdomains via DNS
            subs = self._brute_common_subdomains()
        else:
            subs = [s.strip() for s in out.splitlines() if s.strip() and "." in s]
            if not subs:
                subs = self._brute_common_subdomains()

        for s in subs[:25]:
            self.log(f"   Subdomain: {s}", "info")
            self.result_signal.emit("Subdomains", s, Theme.current["PURPLE"])

        self.prog("host", 15)
        return list(dict.fromkeys([self.target] + subs))

    def _brute_common_subdomains(self):
        common = ["www","mail","ftp","vpn","api","dev","staging","admin","portal","remote"]
        found = []
        for sub in common:
            fqdn = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(fqdn)
                found.append(fqdn)
                self.log(f"   Resolved: {fqdn}", "info")
            except:
                pass
        return found

    #  Host Discovery 
    def _is_host_reachable(self, t: str) -> bool:
        """Fast socket-based reachability check — works on any Windows network adapter.
        Tries common ports (80, 443, 22, 8080) with a short timeout.
        Returns True if any port responds (open or rejected = host is alive)."""
        check_ports = [80, 443, 22, 8080, 21, 3389]
        for p in check_ports:
            try:
                with socket.create_connection((t, p), timeout=3):
                    return True
            except ConnectionRefusedError:
                # Port closed but HOST is alive — count as reachable
                return True
            except (socket.timeout, OSError):
                continue
        # Also try DNS resolution as a last proof of existence
        try:
            socket.gethostbyname(t)
            # DNS resolves → host likely exists, treat as reachable
            return True
        except Exception:
            pass
        return False

    def stage_host_discovery(self, targets):
        self.current_stage = "host"
        self.log(" STAGE 2: HOST DISCOVERY ", "stage")
        self.stage_signal.emit("Host Discovery")
        live = []

        for i, t in enumerate(targets):
            if self._stop: break
            self.log(f"  Probing {t}...", "muted")

            # PRIMARY: Fast socket-based check (works on ALL Windows network adapters)
            # nmap -sn uses raw ICMP/TCP SYN which fails on non-ethernet adapters
            is_up = self._is_host_reachable(t)

            if not is_up:
                # SECONDARY: Try nmap --unprivileged ping as a fallback
                out = self.run_cmd(["nmap", "--unprivileged", "-sn", "-T4", t], timeout=20)
                if "__NOTFOUND__" in out:
                    self.log("  nmap not found — using socket check only", "warn")
                elif "Host is up" in out or "1 host up" in out.lower():
                    is_up = True

            if is_up:
                # Hostname resolution
                try:
                    hostname = socket.gethostbyaddr(t)[0]
                except Exception:
                    hostname = ""
                live.append(t)
                DB.add_host(self.scan_id, t, hostname=hostname, status="up")
                label = f" {t}" + (f"  ({hostname})" if hostname else "  [UP]")
                self.result_signal.emit("Hosts", label, Theme.current["GREEN"])
                self.data["hosts"].append(t)
                self.log(f"   UP: {t}" + (f" ({hostname})" if hostname else ""), "good")
            else:
                self.log(f"   DOWN/filtered: {t}", "muted")

            self.prog("host", 15 + int((i+1)/max(len(targets),1)*35))

        if not live:
            # Force-add primary target so scanning always continues
            live = [self.target]
            self.data["hosts"].append(self.target)
            DB.add_host(self.scan_id, self.target, status="forced")
            self.result_signal.emit("Hosts", f" {self.target}  [assumed live — ICMP blocked]", Theme.current["ORANGE"])
            self.log(f"  All hosts appeared filtered — forcing {self.target} as live (ICMP may be blocked)", "warn")

        self.prog("host", 100)
        return live

    #  Port / Service / Version Scan 
    # CDN edge signatures seen in HTTP Server / CDN headers (custom domains that the DNS
    # stage can't flag by name still identify themselves here).
    _CDN_SERVER_SIGS = ("cloudflare", "vercel", "netlify", "akamai", "fastly", "cloudfront",
                        "amazons3", "awselb", "google frontend", "gws", "azureedge", "fly.io",
                        "render", "sucuri", "incapsula", "imperva", "bunnycdn", "keycdn")
    _CDN_HEADERS = ("cf-ray", "x-vercel-id", "x-nf-request-id", "x-amz-cf-id", "x-fastly-request-id",
                    "x-served-by", "x-sucuri-id", "x-cdn", "fly-request-id")

    def _host_behind_cdn(self, host):
        """Quick check: is this host served by a CDN/edge? Returns the provider or ''.

        Uses a short HTTPS/HTTP HEAD and looks at the Server header and CDN-specific headers.
        Catches custom domains (e.g. a site on Vercel) that DNS-name matching misses.
        """
        for scheme, port in (("https", 443), ("http", 80)):
            try:
                resp = requests.head(f"{scheme}://{host}", timeout=5, allow_redirects=True,
                                     verify=False, headers={"User-Agent": NIKTO_BROWSER_UA})
            except Exception:
                continue
            hdrs = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
            server = hdrs.get("server", "")
            for sig in self._CDN_SERVER_SIGS:
                if sig in server:
                    return sig.split()[0].title()
            for h in self._CDN_HEADERS:
                if h in hdrs:
                    return {"cf-ray": "Cloudflare", "x-vercel-id": "Vercel", "x-nf-request-id": "Netlify",
                            "x-amz-cf-id": "Cloudfront", "fly-request-id": "Fly.io"}.get(h, "CDN")
        return ""

    def _rustscan_ports(self, host, timeout=320):
        """Discover open TCP ports with RustScan (fast). Returns a sorted port list, or None
        when RustScan is unavailable or failed (the caller then falls back to nmap)."""
        rs = find_rustscan()
        if not rs:
            return None
        # greppable output, all ports, ignore user config; batch/timeout tuned for reliability
        cmd = [rs, "-a", host, "--greppable", "--no-config", "--range", "1-65535",
               "-b", "1500", "-t", "2500"]
        out = self.run_cmd(cmd, timeout=timeout)
        if out.not_found:
            return None
        if out.timed_out or out.errored:
            self.log(f"  RustScan did not finish on {host} ({out.status}) — falling back to nmap", "warn")
            return None
        return parse_rustscan_ports(str(out))

    def stage_port_scan(self, hosts):
        self.current_stage = "portscan"
        self.log("━━━ STAGE 3-5: PORT / SERVICE / VERSION / OS SCAN ━━━", "stage")
        self.stage_signal.emit("Port + Service Scan")
        services = []

        for idx, host in enumerate(hosts):
            if self._stop: break

            # Is this host behind a CDN? (DNS stage, or a live header check for custom domains)
            cdn = self.cdn_provider if self.cdn_detected else self._host_behind_cdn(host)
            if cdn and not self.cdn_detected:
                self.cdn_detected, self.cdn_provider = True, cdn

            if cdn:
                # A CDN edge only exposes web ports and cannot be OS-fingerprinted. A full
                # -sV/-O scan here just burns ~95s/host on no-response probes, so use a fast
                # connect scan of the web ports; httpx fingerprints the service afterwards.
                self.log(f"  nmap (CDN fast path: {cdn}) → {host}  [web ports only, no -sV/-O]", "info")
                flags = ["-Pn", "-sT", "-T4", "-p", "80,443,8080,8443,8000,8888",
                         "--max-retries", "2", "--host-timeout", "120s"]
                actual_timeout = 150
                if self.opts.get("os_detect"):
                    self.log(f"   Skipping OS detection on {host}: {cdn} is a CDN edge and cannot be fingerprinted", "muted")
            else:
                # Optional fast path: for an all-ports scan (Full profile), let RustScan find
                # the open ports across 1-65535 in seconds, then run nmap -sV only on those.
                # RustScan never does version detection itself, so nmap still identifies the
                # services. Falls back to a plain nmap scan when RustScan is missing or fails.
                rs_ports = None
                if "-p-" in self.cfg["nmap_flags"]:
                    rs_ports = self._rustscan_ports(host)
                if rs_ports is not None:
                    if rs_ports:
                        self.log(f"  RustScan → {host}: {len(rs_ports)} open port(s) found fast; "
                                 f"running nmap -sV on those only", "good")
                        flags = ["-Pn", "-sV", "-T4", "-p", ",".join(str(p) for p in rs_ports)]
                        if self.opts.get("os_detect"): flags += ["-O", "--osscan-guess"]
                        if self.opts.get("scripts"):   flags += ["--script", "vuln,auth,default"]
                        flags += ["--host-timeout", "480s"]
                    else:
                        self.log(f"  RustScan → {host}: no open ports found", "info")
                        flags = None   # nothing to version-scan; socket fallback below still runs
                    actual_timeout = 600
                else:
                    self.log(f"  nmap {self.profile} scan → {host}", "info")
                    flags = self.cfg["nmap_flags"].copy()
                    if self.opts.get("os_detect"): flags += ["-O", "--osscan-guess"]  # guess even on non-ideal conditions
                    if self.opts.get("scripts"):   flags += ["--script", "vuln,auth,default"]
                    flags += ["--host-timeout", "480s"]
                    actual_timeout = 600
                    self.log(f"   Scan timeout: {actual_timeout}s, Host timeout: 480s", "info")
            self.prog("port", 10 + idx * 5)

            # RustScan found no open ports -> skip nmap for this host, go to socket fallback.
            if flags is None:
                parsed = self._socket_port_scan(host)
                if parsed:
                    services.extend(parsed)
                self.prog("port", 30 + idx * 15)
                continue

            safe_host = host.replace('/', '_').replace(':', '_')
            xml_out = os.path.join(RESULTS_DIR, f"nmap_{safe_host}.xml")
            txt_out = os.path.join(RESULTS_DIR, f"nmap_{safe_host}.txt")
            cmd = ["nmap"] + flags + ["-oX", xml_out, "-oN", txt_out, host]
            out = self.run_cmd(cmd, timeout=actual_timeout)

            parsed = []
            if "__NOTFOUND__" in out:
                if self.opts.get("demo_mode"):
                    self.log("  nmap not found – using DEMO mock data (demo_mode enabled)", "warn")
                    services.extend(self._mock_services(host))
                else:
                    # Never fabricate services on a real scan: fall back to a real TCP socket scan
                    self.log("  nmap not found – falling back to TCP socket scan (real results)", "warn")
                    sock_svcs = self._socket_port_scan(host)
                    if sock_svcs:
                        services.extend(sock_svcs)
                        self.log(f"  Socket scan found {len(sock_svcs)} open port(s) on {host}", "good")
                    else:
                        self.log(f"  Socket scan found no open ports on {host}", "info")
                self.prog("port", 30 + idx * 15)
                continue

            elif "__TIMEOUT__" in out:
                self.log(f"  nmap timed out after {actual_timeout}s – checking partial results", "warn")
                parsed = self._parse_nmap_xml(xml_out, host)
                if not parsed and os.path.exists(txt_out):
                    try:
                        with open(txt_out, "r", encoding="utf-8", errors="replace") as f:
                            parsed = self._parse_nmap_text(f.read(), host)
                    except Exception:
                        parsed = []

            else:
                # ── BUG FIX 1: Detect nmap raw-socket failure on WiFi/VPN ──────
                _eth_err = ("Only ethernet devices" in out or
                            "not an ethernet device" in out or
                            "QUITTING" in out and "ethernet" in out.lower())
                if _eth_err:
                    self.log("  ⚠ nmap blocked: non-ethernet adapter (VPN/WARP active) — switching to TCP connect fallback", "warn")
                    self.result_signal.emit("Services", "⚠ nmap adapter error — using socket fallback scan", Theme.current["ORANGE"])
                else:
                    parsed = self._parse_nmap_xml(xml_out, host)
                    # OS-detection feedback: explain WHY -O produced nothing instead of staying silent
                    if self.opts.get("os_detect"):
                        _low = out.lower()
                        if not any(host in g for g in self.data.get("os_guesses", [])):
                            if "requires root privileges" in _low or "requires npcap" in _low or "requires administrator" in _low:
                                self.log("  OS detection needs elevated privileges — run the app as Administrator (Windows) / root (Linux)", "warn")
                            elif "least 1 open and 1 closed port" in _low or "too many fingerprints" in _low:
                                self.log(f"  OS detection inconclusive on {host}: needs ≥1 open + ≥1 closed port (filtered/CDN hosts can't be fingerprinted)", "muted")
                    if not parsed:
                        parsed = self._parse_nmap_text(out, host)
                    if parsed:
                        self._extract_banners(out, host)

            # ── BUG FIX 2: Socket fallback when nmap gives 0 results ──────────
            # Covers: (a) ethernet error, (b) host-timeout with no partial data,
            # (c) CDN/firewall blocking nmap probes on domain targets
            if not parsed:
                _reason = ""
                if "Only ethernet devices" in out or "not an ethernet device" in out:
                    _reason = "non-ethernet adapter"
                elif "__TIMEOUT__" in out:
                    _reason = "subprocess timeout"
                elif "QUITTING" in out:
                    _reason = "nmap error"
                elif "timedout" in open(xml_out, encoding="utf-8", errors="replace").read() if os.path.exists(xml_out) else "":
                    _reason = "host-timeout"
                else:
                    _reason = "all ports filtered/closed"
                self.log(f"  nmap: 0 open ports ({_reason}) — trying TCP socket fallback on {host}", "warn")
                parsed = self._socket_port_scan(host)
                if parsed:
                    self.log(f"  Socket fallback found {len(parsed)} open port(s) on {host}", "good")
                else:
                    self.log(f"  No open ports found on {host} via nmap or socket scan", "muted")

            services.extend(parsed)
            self.prog("port", 30 + idx * 15)

        # Correct service type misidentification based on standard port-to-protocol mappings
        https_ports = {"443", "465", "585", "636", "989", "990", "992", "993", "995", 
                       "1443", "1883", "2484", "3306", "3389", "5985", "5986", "6516", "6666",
                       "8443", "8883", "8884", "8886"}
        for svc in services:
            port = str(svc.get("port", ""))
            current_service = svc.get("service", "").lower()
            if port in https_ports and current_service == "http":
                svc["service"] = "https"
                self.log(f"   Corrected port {port}: http → https (standard HTTPS port)", "info")

        # Port state heatmap data
        state_counts = defaultdict(int)
        for s in services:
            state_counts[s.get("service","unknown")] += 1
        self.data["port_states"] = dict(state_counts)

        for svc in services:
            DB.add_port(self.scan_id, svc["host"], svc["port"], svc["proto"],
                        svc["service"], svc["version"], "open", svc.get("banner",""))
            self.result_signal.emit("Services",
                f"⬡ {svc['port']}/{svc['proto']}  {svc['service']}", Theme.current["CYAN"])
            self.result_signal.emit("Versions",
                f"◈ {svc['service']}  {svc['version']}", Theme.current["TEXT"])
            self.data["services"].append(f"{svc['port']}/{svc['proto']} {svc['service']}")
            self.data["versions"].append(f"{svc['service']} {svc['version']}")

        self.prog("port", 100)
        self.prog("service", 100)
        return services

    def _extract_banners(self, nmap_output: str, host: str):
        for line in nmap_output.splitlines():
            if "Service Info:" in line or "| banner:" in line or "_http-title:" in line:
                clean = line.strip()
                if clean:
                    self.data["banners"].append(f"{host}: {clean}")
                    self.result_signal.emit("Banners", f"◉ {host}: {clean[:70]}", Theme.current["TEXT2"])

                    # Try to extract OS info from Service Info line
                    if "Service Info:" in line and "OS:" in line:
                        os_match = re.search(r'OS:\s*([^;]+)', line)
                        if os_match:
                            os_guess = os_match.group(1).strip()
                            if os_guess and host not in str(self.data["os_guesses"]):
                                self.data["os_guesses"].append(f"{host} → {os_guess} (from service)")
                                self.result_signal.emit("OS Fingerprint", f"◈ {host}: {os_guess} (from service)", Theme.current["CYAN"])

    def _parse_nmap_xml(self, xml_path: str, host: str):
        if not os.path.exists(xml_path): return []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            results = []
            for h in root.findall("host"):
                addr_el = h.find("address[@addrtype='ipv4']") or h.find("address")
                addr = addr_el.get("addr", host) if addr_el is not None else host
                
                # OS detection
                os_str = ""
                osmatch = h.find(".//osmatch")
                if osmatch is not None:
                    os_str = osmatch.get("name","")
                    accuracy = osmatch.get("accuracy", "0")
                    if os_str:
                        os_str = f"{os_str} ({accuracy}% match)"
                
                # Fallback: Try CPE
                if not os_str:
                    cpe_els = h.findall(".//cpe")
                    os_cpes = []
                    for cpe in cpe_els:
                        cpe_text = cpe.text or ""
                        if cpe_text.startswith("cpe:/o:"):
                            os_cpes.append(cpe_text)
                    if os_cpes:
                        cpe_parts = os_cpes[0].split(":")
                        if len(cpe_parts) >= 4:
                            vendor = cpe_parts[2].replace("_", " ").title()
                            product = cpe_parts[3].replace("_", " ").title()
                            version = cpe_parts[4] if len(cpe_parts) > 4 else ""
                            os_str = f"{vendor} {product} {version}".strip() + " (CPE)"

                if os_str and addr not in str(self.data["os_guesses"]):
                    self.data["os_guesses"].append(f"{addr} → {os_str}")
                    self.result_signal.emit("OS Fingerprint", f"◈ {addr}: {os_str}", Theme.current["CYAN"])
                
                for port_el in h.findall(".//port"):
                    state = port_el.find("state")
                    if state is None or state.get("state") != "open": continue
                    svc_el = port_el.find("service")
                    svc_name = svc_el.get("name","unknown") if svc_el is not None else "unknown"
                    svc_ver  = ""
                    if svc_el is not None:
                        parts = [svc_el.get("product",""), svc_el.get("version",""), svc_el.get("extrainfo","")]
                        svc_ver = " ".join(p for p in parts if p).strip()
                    banner = ""
                    for script in port_el.findall("script"):
                        out_val = script.get("output","")[:200]
                        if out_val: banner = out_val; break
                    cpes = [c.text.strip() for c in svc_el.findall("cpe") if c.text] if svc_el is not None else []
                    results.append({
                        "host": host,  # Keep target hostname for CDN/SNI/Host headers support in downstreams
                        "ip": addr,    # Resolved IP
                        "cpe": cpes,   # nmap CPEs for this service (used for the NVD lookup)
                        "port": port_el.get("portid","?"),
                        "proto": port_el.get("protocol","tcp"),
                        "service": svc_name, "version": svc_ver, "banner": banner,
                        "state": "open"
                    })
            return results
        except Exception as e:
            self.log(f"  XML parse error: {e}", "warn")
            return []

    def _parse_nmap_text(self, text: str, host: str):
        results = []
        seen = set()

        def _push(port, proto, service, version):
            key = (str(port), str(proto))
            if key in seen:
                return
            seen.add(key)
            results.append({
                "host": host,
                "port": str(port),
                "proto": str(proto),
                "service": (service or "unknown").strip() or "unknown",
                "version": (version or "").strip(),
                "banner": "",
                "state": "open"
            })

        for line in text.splitlines():
            m = re.match(r'\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
            if m:
                _push(m.group(1), m.group(2), m.group(3), m.group(4))
                continue

            for g in re.finditer(r'(\d+)/open/(tcp|udp)//([^/\s]*)//([^,]*)', line):
                _push(g.group(1), g.group(2), g.group(3), g.group(4))

            x = re.search(r'<port\s+protocol="(tcp|udp)"\s+portid="(\d+)"', line)
            if x and 'state="open"' in line:
                svc = re.search(r'<service[^>]*name="([^"]+)"[^>]*>', line)
                _push(x.group(2), x.group(1), svc.group(1) if svc else "unknown", "")
        return results

    def _socket_port_scan(self, host: str):
        """TCP connect scan fallback used when nmap fails (WiFi/VPN adapter, CDN, host-timeout).
        Checks a curated list of common service ports and returns open ones."""
        COMMON_PORTS = [
            (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
            (53, "dns"), (80, "http"), (110, "pop3"), (143, "imap"),
            (443, "https"), (445, "smb"), (465, "smtps"), (587, "smtp"),
            (993, "imaps"), (995, "pop3s"), (1433, "mssql"), (3306, "mysql"),
            (3389, "rdp"), (5432, "postgresql"), (5900, "vnc"),
            (6379, "redis"), (8080, "http-alt"), (8443, "https-alt"),
            (8888, "http-alt"), (27017, "mongodb"),
        ]
        results = []
        for port, svc_name in COMMON_PORTS:
            if self._stop:
                break
            try:
                with socket.create_connection((host, port), timeout=3):
                    results.append({
                        "host": host, "port": str(port), "proto": "tcp",
                        "service": svc_name, "version": "(socket-detected)",
                        "banner": "", "state": "open"
                    })
                    self.log(f"  [Socket] {port}/tcp open  ({svc_name})", "info")
            except ConnectionRefusedError:
                pass  # Host alive, port closed — not open
            except (socket.timeout, OSError):
                pass  # Filtered or unreachable
        return results

    def _mock_services(self, host: str):
        return [
            {"host":host,"port":"22",  "proto":"tcp","service":"ssh",    "version":"OpenSSH 8.4p1","banner":"SSH-2.0-OpenSSH_8.4"},
            {"host":host,"port":"80",  "proto":"tcp","service":"http",   "version":"Apache httpd 2.4.49","banner":"Apache/2.4.49 (Unix)"},
            {"host":host,"port":"443", "proto":"tcp","service":"https",  "version":"nginx 1.21.3","banner":"nginx/1.21.3"},
            {"host":host,"port":"21",  "proto":"tcp","service":"ftp",    "version":"vsftpd 3.0.3","banner":"220 (vsFTPd 3.0.3)"},
            {"host":host,"port":"3306","proto":"tcp","service":"mysql",  "version":"MySQL 5.7.36","banner":"5.7.36-log"},
            {"host":host,"port":"8080","proto":"tcp","service":"http-alt","version":"Apache Tomcat 9.0.54","banner":""},
            {"host":host,"port":"25",  "proto":"tcp","service":"smtp",   "version":"Postfix smtpd","banner":"220 mail ESMTP Postfix"},
            {"host":host,"port":"3389","proto":"tcp","service":"rdp",    "version":"Microsoft Terminal Services","banner":""},
        ]

    #  WAF / Firewall Detection 
    def stage_waf_detection(self, services):
        self.current_stage = "waf"
        self.log(" WAF / FIREWALL DETECTION ", "stage")
        self.stage_signal.emit("WAF Detection")
        self.prog("misc", 70)  # Continue from SSL analysis
        web_svcs = [s for s in services if s["service"] in ("http","https","http-alt")]

        for idx, svc in enumerate(web_svcs):  # Check ALL services, not just [:2]
            host = svc["host"]; port = svc["port"]
            out = self.run_cmd(["wafw00f", f"http://{host}:{port}", "-a"], timeout=30)
            if "__NOTFOUND__" in out:
                # Manual WAF detection via nmap http headers
                out2 = self.run_cmd(["curl","-sk","-I",f"http://{host}:{port}",
                                     "--max-time","5"], timeout=10)
                if "__NOTFOUND__" not in out2 and out2:
                    waf_headers = ["x-sucuri","x-firewall","x-waf","cf-ray","server: cloudflare",
                                   "x-amz","akamai","incapsula","imperva","barracuda"]
                    detected = [h for h in waf_headers if h in out2.lower()]
                    if detected:
                        msg = f"WAF detected on {host}:{port}: {', '.join(detected)}"
                        self.log(f"   {msg}", "good")
                        self.result_signal.emit("WAF/Firewall", f" {msg}", Theme.current["GREEN"])
                        # Track WAF-protected hosts for Nikto (use hostname instead of IP)
                        self.waf_hosts.add((host, int(port)))
                    else:
                        # Informational only: the absence of a WAF is not a vulnerability.
                        self.result_signal.emit("WAF/Firewall", f" No WAF detected on {host}:{port}", Theme.current["TEXT2"])
            elif "No WAF detected" in out:
                self.result_signal.emit("WAF/Firewall", f" No WAF: {host}:{port}", Theme.current["ORANGE"])
            elif out.strip():
                # Filter out ASCII art banners and sanitize for encoding issues
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                # Skip version banners, ASCII art, and empty lines
                skip_patterns = ['wafw00f', 'v2.', 'v1.', '~', '404', 'hack not found']
                meaningful_lines = []
                for l in lines:
                    # Must be long enough and contain detection keywords
                    if len(l) > 20 and not any(pat in l.lower() for pat in skip_patterns):
                        keywords = ['detected', 'behind', 'protected', 'firewall', 'cloudflare', 'incapsula', 'akamai', 'imperva', 'sucuri']
                        if any(kw in l.lower() for kw in keywords):
                            meaningful_lines.append(l)
                
                if meaningful_lines:
                    clean_out = meaningful_lines[0]  # Take first meaningful line
                    clean_out = clean_out.encode('ascii', 'ignore').decode('ascii').strip()
                    if clean_out and len(clean_out) > 20:
                        self.log(f"  wafw00f: {clean_out[:80]}", "info")
                        self.result_signal.emit("WAF/Firewall", f" {clean_out[:60]}", Theme.current["GREEN"])
                        # Track detected WAF host
                        self.waf_hosts.add((host, int(port)))
            
            # Increment progress - spread across all services
            self.prog("misc", 70 + ((idx % 3 + 1) * 10))  # Limit progress bar to avoid overflow
        
        self.prog("misc", 100)  # Complete MISC stage

    def _run_nikto(self, cmd, cwd, timeout=300):
        """
        Run Perl+Nikto with cwd set to the nikto program directory.
        This is the KEY fix for Windows: passing 'nikto.pl' as a plain filename
        (relative to cwd) avoids the 'Invalid argument' error Perl throws when
        the script path contains spaces (e.g. 'cyber security main project').
        """
        if self._stop:
            return ""
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                errors='replace',
                cwd=cwd,          # <-- run from nikto's own directory
            )
            return r.stdout + r.stderr
        except FileNotFoundError:
            return f"__NOTFOUND__{cmd[0]}"
        except subprocess.TimeoutExpired as e:
            partial = ""
            if e.stdout:
                partial += e.stdout if isinstance(e.stdout, str) else e.stdout.decode('utf-8', errors='replace')
            if e.stderr:
                partial += e.stderr if isinstance(e.stderr, str) else e.stderr.decode('utf-8', errors='replace')
            return f"__TIMEOUT__{partial}"
        except Exception as e:
            return f"__ERROR__{e}"

    #  Web Vulnerability Scan 
    def stage_web_scan(self, services):
        self.current_stage = "nikto"
        self.log(" STAGE 6: WEB VULNERABILITY SCAN (NIKTO) ", "stage")
        self.stage_signal.emit("Web Vuln Scan")
        self.prog("vuln", 10)
        findings = []
        seen_findings = set()  # Track unique findings to avoid duplicates
        web_svcs = [s for s in services if s["service"] in ("http","https","http-alt","tcpwrapped")]

        if not web_svcs:
            # Fallback: always try port 80 and 443 on primary target even if nmap found nothing
            self.log("  No HTTP services detected by nmap — falling back to port 80/443 on primary target", "warn")
            web_svcs = [
                {"service": "http",  "host": self.original_target, "port": 80},
                {"service": "https", "host": self.original_target, "port": 443},
            ]

        if not self.cfg["nikto"]:
            self.log("  Nikto disabled in current profile", "muted")
            self.prog("vuln", 35)
            return findings

        if not NIKTO_AVAILABLE:
            self.log("  Nikto not installed - Nikto stage skipped (install it: danishrecon setup nikto)", "warn")
            self.prog("vuln", 35)
            return findings

        # Deduplicate by (host, port): every distinct web service is scanned exactly once,
        # and only ports that were actually found open (no forced 80/443).
        seen_endpoints = set()
        unique_svcs = []
        for svc in web_svcs:
            key = (str(svc.get("host", "")).lower(), str(svc.get("port", "")))
            if key[0] and key not in seen_endpoints:
                unique_svcs.append(svc)
                seen_endpoints.add(key)

        self.log(f"  Deduped {len(web_svcs)} services → {len(unique_svcs)} unique host:port endpoints", "info")
        web_svcs = unique_svcs or web_svcs
        nikto_failed = 0

        for svc in web_svcs:
            if self._stop: break
            _p = str(svc.get("port", ""))
            proto = "https" if (svc["service"] == "https" or _p in ("443", "8443", "4443")) else "http"
            host = svc["host"]
            port = str(svc["port"])
            
            # Determine if this host is behind a WAF
            has_waf = (host, int(port)) in self.waf_hosts
            
            # Use hostname for Nikto target (not IP) - critical for WAF bypass and SNI
            nikto_target = host
            
            self.log(f"  nikto → {proto}://{nikto_target}:{port}", "info")
            
            # Timeout: 1200s for HTTPS, 300s for HTTP
            nikto_timeout = 1200 if proto == "https" else 300
            
            # Nikto command with proper options
            # Build URL: omit default ports (80 for HTTP, 443 for HTTPS) from -h parameter
            # NOTE: port is a string here, so compare to string literals
            is_default_port = (proto == "http" and str(port) == "80") or (proto == "https" and str(port) == "443")
            nikto_url = f"{proto}://{nikto_target}" if is_default_port else f"{proto}://{nikto_target}:{port}"
            
            # KEY FIX: Run Perl with cwd=nikto_dir so we pass 'nikto.pl' as a plain filename.
            # This avoids the Windows 'Invalid argument' error caused by spaces in the project path.
            nikto_dir = os.path.normpath(os.path.dirname(NIKTO_PATH))
            nikto_basename = os.path.basename(NIKTO_PATH)  # 'nikto.pl'
            nikto_cmd = [
                PERL_EXECUTABLE, nikto_basename,
                "-h", nikto_url,
                "-ask", "no",
                "-Display", "P",
                "-config", "nikto.conf.default",  # relative to cwd=nikto_dir
                # let Nikto stop itself cleanly inside the profile's time budget
                "-maxtime", "120s" if self.profile == "Quick" else "900s",
            ]

            # If this host is behind a WAF, enable Nikto evasion + a real browser UA
            # so the scan is less likely to be blocked or fingerprinted by the WAF.
            if has_waf:
                self.log(f"  {host}:{port} is behind a WAF — enabling Nikto evasion (URI encoding) + browser UA", "warn")
                nikto_cmd += ["-evasion", "1", "-useragent", NIKTO_BROWSER_UA]

            # Run with working directory set to the nikto program folder
            out = self._run_nikto(nikto_cmd, cwd=nikto_dir, timeout=nikto_timeout)
            
            if "__NOTFOUND__" in out:
                self.log("  perl/nikto not found – skipping", "warn")
                break

            # A Nikto run that could not reach the target produced no results - say so
            # instead of silently reporting "0 findings".
            if "Unable to connect" in out or "No web server found" in out or "__ERROR__" in out:
                nikto_failed += 1
                self.log(f"  Nikto could not scan {nikto_url} (connection/tool error) - no Nikto results for this endpoint", "warn")
                self.result_signal.emit("Ranked Vulnerabilities",
                                        f"⚠ Nikto could not scan {nikto_url} - not tested", Theme.current["ORANGE"])
                continue
            if "__TIMEOUT__" in out:
                self.log(f"  Nikto timed out on {nikto_url} after {nikto_timeout}s - results below are partial", "warn")

            # Parse vulnerabilities from Nikto output with severity detection
            for line in out.splitlines():
                if re.match(r'\+ ', line):
                    # Skip non-vulnerability messages and errors
                    if any(skip in line for skip in ["OSVDB", "[FAIL]", "[ERROR]", "ERROR:", "out of date", "git pull",
                                                     "Unable to connect", "Target IP:", "Target Hostname:",
                                                     "Target Port:", "Start Time:", "End Time:", "host(s) tested",
                                                     "requests:", "SSL Info:"]):
                        continue
                    clean = line.strip().lstrip("+ ")
                    if len(clean) > 10:
                        # Auto-detect severity from keywords
                        vuln_severity = "LOW"
                        clean_lower = clean.lower()
                        
                        # Nikto output carries no severity, so this is a conservative
                        # heuristic on whole words. Informational notes stay LOW.
                        def _has(*words):
                            return any(re.search(rf"\b{re.escape(w)}\b", clean_lower) for w in words)

                        if "uncommon header" in clean_lower:
                            vuln_severity = "LOW"
                        elif _has("remote code execution", "rce", "sql injection", "command injection",
                                  "authentication bypass", "backdoor"):
                            vuln_severity = "HIGH"
                        elif _has("xss", "cross-site scripting", "csrf", "directory traversal",
                                  "default credentials", "directory indexing", "information disclosure"):
                            vuln_severity = "MEDIUM"
                        
                        # Normalize finding text for deduplication (remove host:port patterns)
                        # This removes patterns like "on example.com:443" or "Target Hostname: example.com"
                        normalized_clean = re.sub(
                            r'\s+on\s+[\w\.-]+\.[\w\.-]*:\d+',
                            '',
                            clean,
                            flags=re.IGNORECASE
                        )
                        # Remove "Target Hostname: example.com:port" patterns
                        normalized_clean = re.sub(
                            r'Target\s+Hostname:\s+[\w\.-]+',
                            'Target',
                            normalized_clean,
                            flags=re.IGNORECASE
                        )
                        # Remove "Target IP: 1.2.3.4" patterns
                        normalized_clean = re.sub(
                            r'Target\s+IP:\s+[\d\.]+',
                            'Target',
                            normalized_clean,
                            flags=re.IGNORECASE
                        )
                        # Remove trailing IP addresses and port numbers
                        normalized_clean = re.sub(
                            r'\s+[\d\.]+$',
                            '',
                            normalized_clean
                        )
                        # Normalize path references like /server-status, /trace.axd, etc
                        normalized_clean = re.sub(
                            r'(x-vercel-id.*?):\s+[\da-f\.:]+',
                            r'\1',
                            normalized_clean,
                            flags=re.IGNORECASE
                        )
                        
                        # Store finding with severity marker using normalized text
                        finding = f"[{vuln_severity}] {normalized_clean}"
                        
                        # Deduplicate: only add if not seen before (cross-host deduplication)
                        if finding not in seen_findings:
                            findings.append(finding)
                            seen_findings.add(finding)
                            self.log(f"  Nikto: {clean}", "warn")

        if len(findings) == 0:
            # Nikto found no vulnerabilities - could be connection issue or clean target
            # Check if target is private IP and suggest Nuclei
            if any(host.startswith(prefix) for prefix in ["192.168", "10.", "172."]):
                self.log(f"  ⚠ Nikto found 0 vulnerabilities on private IP - may be connection issue", "muted")
                self.log(f"  → Check Nuclei results for comprehensive findings", "muted")
        
        if nikto_failed:
            self.log(f"  Nikto failed on {nikto_failed}/{len(web_svcs)} endpoint(s) - those were NOT tested", "warn")
        self.log(f"  Total unique findings: {len(findings)} (deduplicated)", "good")
        self.prog("vuln", 35)
        return findings

    #  OpenVAS Vulnerability Scanning 
    def stage_openvas_scan(self, services):
        """
        Stage 6a: OpenVAS Vulnerability Scanning
        Runs after Nikto to perform deep vulnerability scanning on discovered services
        Falls back to demo mode if daemon not available (Windows compatibility)
        """
        
        self.current_stage = "openvas"
        self.log(" STAGE 6A: VULNERABILITY SCANNING (OpenVAS) ", "stage")
        
        self.stage_signal.emit("OpenVAS Scan")
        self.prog("vuln", 40)
        findings = []
        
        if not OPENVAS_AVAILABLE:
            self.log(f"  OpenVAS not available - stage skipped: {openvas_unavailable_reason()}", "warn")
            self.prog("vuln", 45)
            return findings
        
        
        # Initialize OpenVAS scanner
        try:
            scanner = OpenVASScanner(timeout=1800)  # 30 minute timeout
        except Exception as e:
            self.log(f"  OpenVAS initialization failed: {str(e)}", "error")
            self.prog("vuln", 45)
            return findings
        
        # Get unique hosts from services
        seen_hosts = set()
        unique_hosts = []
        for svc in services:
            host = svc.get("host", "").lower()
            if host and host not in seen_hosts:
                unique_hosts.append(host)
                seen_hosts.add(host)
        
        
        if not unique_hosts:
            # Fall back to the original scan target (same as Nuclei does)
            self.log("  No services found – falling back to original target for OpenVAS", "info")
            unique_hosts = [self.target]
        
        # Check if daemon is available. Only fabricate DEMO findings when the user
        # explicitly opts in (demo_mode); otherwise skip the stage entirely so real
        # reports never contain fake OpenVAS vulnerabilities.
        scanner_available = scanner.is_available()
        allow_demo = self.opts.get("demo_mode", False)
        use_demo_mode = (not scanner_available) and allow_demo
        if not scanner_available and not allow_demo:
            self.log(f"  OpenVAS not available - stage skipped: {openvas_unavailable_reason()}", "warn")
            self.prog("vuln", 45)
            return findings
        
        # Check if port 9390 or 9392 is listening to give a more accurate message
        ports_open = False
        import socket as _socket_test
        for _p in (9390, 9392):
            try:
                with _socket_test.create_connection(("127.0.0.1", _p), timeout=1):
                    ports_open = True
                    break
            except Exception:
                pass
        
        if use_demo_mode:
            if ports_open:
                self.log("  Greenbone Docker container detected running (ports 9390/9392 open)", "good")
                self.log("  ⏳ OpenVAS is busy syncing vulnerability feeds (NVTs) or starting database.", "warn")
                self.log("  → Please wait ~15 minutes for feed sync to complete. Progress: http://localhost:9392", "muted")
                self.log("  → Running in DEMO MODE fallback for this scan.", "warn")
            else:
                self.log("  Greenbone/OpenVAS Docker container not detected (ports closed)", "info")
                self.log("  Running in DEMO MODE  [DEMO] labels shown on findings", "warn")
                self.log("  For REAL scans: docker run -d --name greenbone -p 9390:9390 -p 9392:9392 securecompliance/gvm", "muted")
                self.log("  Then: pip install python-gvm  and restart CyberRecon", "muted")
        else:
            self.log("  Greenbone Docker detected  running REAL OpenVAS vulnerability scan", "good")
            self.log(f"  Connected to GVM at {os.getenv('GVM_HOST','127.0.0.1')}:{os.getenv('GVM_PORT','9390')}", "info")
        
        # Scan each unique host
        total_hosts = len(unique_hosts)
        for idx, host in enumerate(unique_hosts):
            if self._stop:
                break
            
            try:
                self.log(f"  Scanning {host} with OpenVAS ({idx+1}/{total_hosts})...", "info")
                
                # Get ports for this host
                host_ports = []
                for svc in services:
                    if svc.get("host", "").lower() == host:
                        port = str(svc.get("port", ""))
                        if port and port not in host_ports:
                            host_ports.append(port)
                
                # Run OpenVAS scan (with demo mode fallback for Windows)
                # Pass self.log so feed-sync wait progress shows in the UI
                result = scanner.scan_target(
                    host,
                    ports=host_ports if host_ports else None,
                    demo_mode=use_demo_mode,
                    log_fn=self.log,
                )
                
                if "error" in result and result["error"]:
                    err_msg = result['error']
                    # Distinguish feed-not-ready vs real errors
                    if "feed not ready" in err_msg.lower() or "scan configs not loaded" in err_msg.lower():
                        self.log(f"  ⏳ OpenVAS NVT feed still syncing for {host}", "warn")
                        self.log("  → Wait 5-10 min then retry. Check: http://localhost:9392", "muted")
                        if not allow_demo:
                            self.log(f"  {host}: OpenVAS feed not ready — skipping "
                                     "(enable demo_mode for sample data)", "warn")
                            continue
                        self.log("  → Running DEMO results in the meantime...", "muted")
                        # Fall back to demo for this host (demo_mode explicitly enabled)
                        from danishrecon.openvas_scanner import OpenVASScanner as _OVS
                        demo_result = _OVS().scan_target(host, ports=host_ports if host_ports else None, demo_mode=True)
                        result = demo_result
                    else:
                        self.log(f"  OpenVAS error for {host}: {err_msg}", "warn")
                        continue
                
                # Process vulnerabilities
                vulns = result.get("vulnerabilities", [])
                
                for vuln in vulns:
                    # Determine severity color
                    severity = vuln.severity if hasattr(vuln, 'severity') else vuln.get("severity", "LOW")
                    
                    # Create finding entry
                    finding = f"[{severity}] {vuln.name if hasattr(vuln, 'name') else vuln.get('name')} (CVSS: {vuln.cvss_score if hasattr(vuln, 'cvss_score') else vuln.get('cvss_score', 0.0)})"
                    
                    findings.append(finding)
                    
                    # Log finding with appropriate styling
                    if severity == "CRITICAL":
                        self.log(f"  CRITICAL: {vuln.name if hasattr(vuln, 'name') else vuln.get('name')}", "crit")
                    elif severity == "HIGH":
                        self.log(f"  HIGH: {vuln.name if hasattr(vuln, 'name') else vuln.get('name')}", "warn")
                    else:
                        self.log(f"  {severity}: {vuln.name if hasattr(vuln, 'name') else vuln.get('name')}", "info")
                    
                    # Store in database with OpenVAS source marker
                    # Use only valid Theme keys (YELLOW does not exist - use ORANGE for HIGH, CYAN for others)
                    if severity == "CRITICAL":
                        _ov_color = Theme.current["RED"]
                    elif severity == "HIGH":
                        _ov_color = Theme.current["ORANGE"]
                    else:
                        _ov_color = Theme.current["CYAN"]
                    self.result_signal.emit(
                        "OpenVAS Vulnerability",
                        finding,
                        _ov_color
                    )
                    
                    # Store detailed evidence
                    evidence = {
                        "type": "vulnerability",
                        "source": "OpenVAS",
                        "title": vuln.name if hasattr(vuln, 'name') else vuln.get("name"),
                        "severity": severity,
                        "cvss_score": vuln.cvss_score if hasattr(vuln, 'cvss_score') else vuln.get("cvss_score"),
                        "host": host,
                        "port": vuln.port if hasattr(vuln, 'port') else vuln.get("port"),
                        "service": vuln.service if hasattr(vuln, 'service') else vuln.get("service"),
                        "description": vuln.description if hasattr(vuln, 'description') else vuln.get("description"),
                        "solution": vuln.solution if hasattr(vuln, 'solution') else vuln.get("solution"),
                        "oid": vuln.oid if hasattr(vuln, 'oid') else vuln.get("oid"),
                        "timestamp": time.time(),
                        "demo_mode": use_demo_mode,
                    }

                    # Persist the rich evidence (description/solution/oid) — previously built and dropped
                    self.data.setdefault("evidence", []).append(evidence)
                    try:
                        DB.add_evidence(
                            self.scan_id,
                            "vulnerability",
                            evidence["title"],
                            source_url=f"{host}:{evidence['port']}",
                            method="OpenVAS",
                            surface="demo" if use_demo_mode else "openvas",
                            notes=json.dumps({
                                "severity": evidence["severity"],
                                "cvss_score": evidence["cvss_score"],
                                "service": evidence["service"],
                                "description": evidence["description"],
                                "solution": evidence["solution"],
                                "oid": evidence["oid"],
                            }, ensure_ascii=False, default=str)[:2000],
                        )
                    except Exception as _ev_err:
                        self.log(f"  DB error storing OpenVAS evidence: {str(_ev_err)}", "muted")

                    try:
                        # Use the global thread-safe DB object (self.db was never defined)
                        DB.add_vuln(
                            self.scan_id,
                            host,
                            "openvas",
                            vuln.port if hasattr(vuln, 'port') else vuln.get("port", "0"),
                            severity,
                            "",   # cve
                            vuln.cvss_score if hasattr(vuln, 'cvss_score') else vuln.get("cvss_score", 0.0),
                            vuln.name if hasattr(vuln, 'name') else vuln.get("name"),
                        )
                    except Exception as db_err:
                        self.log(f"  DB error storing OpenVAS vulnerability: {str(db_err)}", "muted")
                
                self.log(f"  Found {len(vulns)} vulnerabilities on {host}", "good")
                
            except Exception as e:
                self.log(f"  OpenVAS scan error for {host}: {str(e)}", "warn")
            
            # Update progress
            self.prog("vuln", 40 + ((idx + 1) * 5 // max(total_hosts, 1)))
        
        self.log(f"  OpenVAS: {len(findings)} total findings", "good")
        self.log(f"  *** STAGE 6A: OpenVAS scan completed ***", "good")
        self.prog("vuln", 45)
        return findings

    #  Exploit Lookup 
    #  API ENDPOINT DISCOVERY 
    def stage_api_discovery(self, services):
        self.current_stage = "api"
        self.log(" STAGE 6.5: API ENDPOINT DISCOVERY ", "stage")
        self.stage_signal.emit("API Discovery")
        self.prog("vuln", 30)
        
        api_endpoints = []
        
        if not API_SCANNER_AVAILABLE:
            self.log("  API Scanner module not available  skipping", "warn")
            self.prog("vuln", 35)
            return api_endpoints
        
        # Scan all identified HTTP services for API endpoints
        web_svcs = [s for s in services if s["service"] in ("http","https","http-alt")]
        if not web_svcs:
            # Try original target if no services found
            web_svcs = [{"host": self.original_target, "port": "443", "service": "https"}]

        auth_bearer = (self.opts.get("auth_bearer") or "").strip()
        auth_cookie = (self.opts.get("auth_cookie") or "").strip()
        has_auth_context = bool(auth_bearer or auth_cookie)

        if has_auth_context:
            self.log("  Auth context detected: scanning public and authenticated surfaces", "info")
        else:
            self.log("  No auth context provided: scanning public surface only", "muted")

        def scan_surface(surface_name, bearer_token=None, cookie_header=None):
            local_count = 0
            for svc in web_svcs:
                if self._stop:
                    break

                # 'https' → https, everything else (http, http-alt) → http
                proto = "https" if svc["service"] == "https" else "http"
                host = svc.get("host", self.original_target)
                port = str(svc.get("port", ""))
                if (proto == "https" and port == "443") or (proto == "http" and port == "80") or not port:
                    base_url = f"{proto}://{host}"
                else:
                    base_url = f"{proto}://{host}:{port}"

                try:
                    self.log(f"  [{surface_name}] Scanning API endpoints on {base_url}", "info")
                    scanner = APIScanner(
                        DB_PATH,
                        base_url,
                        self.scan_id,
                        callback=self.log,
                        deep_mode=True,
                        auth_bearer=bearer_token,
                        auth_cookie=cookie_header,
                        auth_surface=surface_name,
                    )
                    results = scanner.scan()

                    for endpoint in results['endpoints']:
                        api_endpoints.append(endpoint)
                        local_count += 1
                        self.result_signal.emit("API Endpoints", f" [{surface_name}] {endpoint['path']}", Theme.current["CYAN"])

                        evidence = {
                            "type": "api_endpoint",
                            "title": endpoint.get("path", "endpoint"),
                            "source_url": endpoint.get("url", base_url),
                            "status_code": endpoint.get("status_code", 0),
                            "response_headers": endpoint.get("headers", {}),
                            "method": endpoint.get("method", "GET"),
                            "surface": endpoint.get("auth_surface", surface_name),
                            "timestamp": endpoint.get("timestamp", datetime.now().isoformat()),
                            "notes": endpoint.get("discovery_source", "path-list"),
                        }
                        self.data["evidence"].append(evidence)
                        DB.add_evidence(
                            self.scan_id,
                            evidence["type"],
                            evidence["title"],
                            evidence["source_url"],
                            evidence["status_code"],
                            json.dumps(evidence["response_headers"], ensure_ascii=False),
                            evidence["method"],
                            evidence["surface"],
                            evidence["notes"],
                        )

                    # The API scanner also flags CORS misconfig / broken-auth on the
                    # endpoints it finds - route those into the structured findings store
                    # so they reach the report, dashboard, SARIF and the diff.
                    for v in results.get("vulnerabilities", []):
                        vtype = (v.get("type") or "").lower()
                        category = "cors" if "cors" in vtype else "broken-auth" if "auth" in vtype else "misconfig"
                        self._add_finding(Finding(
                            title=v.get("type", "API issue"), severity=v.get("severity", "MEDIUM"),
                            source="api-scanner", confidence="confirmed", category=category,
                            host=host, url=v.get("url", base_url),
                            description=v.get("description", ""),
                            remediation="Restrict CORS to trusted origins / require authentication on this endpoint."))

                except Exception as e:
                    self.log(f"  Error during {surface_name} API scan: {str(e)}", "warn")

            return local_count
        
        public_count = scan_surface("public")
        auth_count = 0
        if has_auth_context and not self._stop:
            auth_count = scan_surface("authenticated", bearer_token=auth_bearer, cookie_header=auth_cookie)

        self.data["api_count"] = public_count
        self.data["auth_api_count"] = auth_count
        self.data["api_endpoints"] = [e for e in api_endpoints if e.get("auth_surface") == "public"]
        self.data["auth_api_endpoints"] = [e for e in api_endpoints if e.get("auth_surface") == "authenticated"]
        self.log(f"  API endpoints found -> public: {public_count}, authenticated: {auth_count}", "good")
        
        self.prog("vuln", 35)
        return api_endpoints

    #  WEB VULNERABILITY TESTING (IDOR + SQLi) 
    def stage_web_vulnerability_testing(self, services):
        """Test discovered URLs for IDOR and SQL Injection vulnerabilities"""
        self.current_stage = "web_vuln"
        
        # ✅ NEW: Check if user enabled web vulnerability testing via checkbox
        if not self.opts.get("enable_web_vuln", True):
            self.log(" Web Vulnerability Testing (IDOR + SQLi) DISABLED - Skipping stage", "muted")
            self.prog("vuln", 40)
            return
        
        self.log(" STAGE 6.6: WEB VULNERABILITY TESTING (IDOR + SQLi) ", "stage")
        self.stage_signal.emit("Web Vuln Testing")
        self.prog("vuln", 35)
        
        if not WEB_VULN_SCANNER_AVAILABLE:
            self.log("  Web Vulnerability Scanner not available - skipping", "warn")
            self.prog("vuln", 40)
            return
        
        # Build URLs from discovered services
        web_svcs = [s for s in services if s["service"] in ("http", "https", "http-alt")]
        if not web_svcs:
            # Fallback: always try the primary target directly
            self.log("  No web services from nmap — falling back to original target", "warn")
            web_svcs = [{"host": self.original_target, "port": "443", "service": "https"}]
        
        self.log(f"  Found {len(web_svcs)} web service(s) - scanning for vulnerabilities...", "info")
        
        # Build URLs to test with REAL vulnerable endpoints
        urls_to_test = []
        
        # Mapping of known vulnerable sites to their actual vulnerable endpoints
        known_vuln_sites = {
            "httpbin.org": [
                "/get?q=test",              # Reflects parameter
                "/anything?id=1",           # Reflects parameter
                "/status/200?user_id=1",    # Returns 200 with parameter
            ],
            "rest.vulnweb.com": [
                "/rest/api/search?query=test",   # Real endpoint
            ],
            "vulnweb.com": [
                "/search?q=test",           # Real endpoint
            ],
        }
        
        for svc in web_svcs:
            proto = "https" if svc["service"] in ("https", "http-alt") else "http"
            host = svc.get("host", self.original_target)
            port = svc.get("port")
            
            # Build base URL
            if port and ((proto == "https" and port != 443) or (proto == "http" and port != 80)):
                base_url = f"{proto}://{host}:{port}"
            else:
                base_url = f"{proto}://{host}"
            
            # Use KNOWN vulnerable endpoints if target matches known site
            host_lower = host.lower()
            test_paths = []
            
            for known_site, endpoints in known_vuln_sites.items():
                if known_site in host_lower:
                    test_paths = endpoints
                    self.log(f"    Using real vulnerable endpoints for {known_site}", "info")
                    break
            
            # If not a known site, use generic but real-world endpoints
            if not test_paths:
                test_paths = [
                    "/get?id=1",               # httpbin-style
                    "/anything?id=1",
                    "/search?q=test",
                    "/",                       # Root with parameter
                ]
            
            urls_to_test.extend([base_url + p for p in test_paths])
        
        if not urls_to_test:
            self.log("  No URLs generated for testing", "muted")
            self.prog("vuln", 40)
            return
        
        # Remove duplicates
        urls_to_test = list(set(urls_to_test))
        
        # Filter out URLs that return 404/400 (endpoints don't exist)
        # This saves time and prevents false negatives
        self.log(f"  Pre-filtering {len(urls_to_test)} URLs (checking if they exist)...", "info")
        valid_urls = []
        
        try:
            for url in urls_to_test:
                try:
                    resp = requests.head(url, timeout=3, verify=False, allow_redirects=True)
                    # Valid if 200-299 (success) or 400/401 (auth required = endpoint exists)
                    if 200 <= resp.status_code < 400 or resp.status_code in (401, 403):
                        valid_urls.append(url)
                        self.log(f"    ✓ Valid: {url} ({resp.status_code})", "debug")
                    else:
                        self.log(f"    ✗ Skip: {url} ({resp.status_code})", "debug")
                except Exception as e:
                    # If HEAD fails, try direct GET (some servers don't support HEAD)
                    try:
                        resp = requests.get(url, timeout=3, verify=False, allow_redirects=True, stream=True)
                        if 200 <= resp.status_code < 400 or resp.status_code in (401, 403):
                            valid_urls.append(url)
                            self.log(f"    ✓ Valid: {url} ({resp.status_code})", "debug")
                        else:
                            self.log(f"    ✗ Skip: {url} ({resp.status_code})", "debug")
                    except:
                        self.log(f"    ✗ Unreachable: {url}", "debug")
        except Exception as e:
            self.log(f"  Pre-filtering error: {str(e)[:100]}", "warn")
            valid_urls = urls_to_test  # Fall back to all URLs if filtering fails
        
        self.log(f"  Pre-filter result: {len(valid_urls)}/{len(urls_to_test)} endpoints are valid", "info")
        
        if not valid_urls:
            self.log("  No valid endpoints found for testing", "muted")
            self.prog("vuln", 40)
            return
        
        self.log(f"  Testing {len(valid_urls)} valid URLs for IDOR/SQLi vulnerabilities...", "info")
        
        # Use STEALTH profile by default to avoid triggering IDS/WAF
        profile = ScanProfile.STEALTH
        if self.profile.lower() in ("full", "thorough"):
            profile = ScanProfile.NORMAL
        elif self.profile.lower() == "quick":
            profile = ScanProfile.QUICK
        
        try:
            # Run async scan on VALID URLs only
            scanner = WebVulnerabilityScanner(self.original_target, profile)
            results = asyncio.run(scanner.scan(valid_urls))
            
            # Process IDOR findings
            idor_count = 0
            for idor in results.get("idor", []):
                idor_count += 1
                color = "red" if idor.severity in ("CRITICAL", "HIGH") else "orange"
                finding_text = f"[UNVERIFIED heuristic] {idor.url} | param={idor.parameter}"
                self.result_signal.emit("idor", finding_text, color)
                self.log(f"  ? Possible IDOR (unverified, needs manual check): {finding_text}", "warn")
            
            # Process SQLi findings  
            sqli_count = 0
            for sqli in results.get("sqli", []):
                sqli_count += 1
                color = "red" if sqli.severity in ("CRITICAL", "HIGH") else "orange"
                finding_text = f"[UNVERIFIED heuristic] {sqli.url} | param={sqli.parameter}"
                self.result_signal.emit("sqli", finding_text, color)
                self.log(f"  ? Possible SQLi (unverified, needs manual check): {finding_text}", "warn")
            
            total_found = idor_count + sqli_count
            if total_found > 0:
                self.log(f"  COMPLETE: {idor_count} possible IDOR + {sqli_count} possible SQLi - "
                         f"heuristic signals only, NOT included in the report until verified", "warn")
            else:
                self.log(f"  COMPLETE: Tested {len(valid_urls)} valid URLs - no vulnerabilities found", "muted")
            
        except Exception as e:
            self.log(f"  Web vulnerability testing error: {str(e)[:150]}", "error")
        
        self.prog("vuln", 40)

    def stage_secret_scanning(self, services):
        self.current_stage = "secrets"
        self.log(" STAGE 6.6: SECRET SCANNING ", "stage")
        self.stage_signal.emit("Secret Scanning")

        findings = []
        secret_patterns = [
            ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "HIGH"),
            ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "HIGH"),
            ("Stripe Live Key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), "HIGH"),
            ("GitHub Token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "HIGH"),
            ("GitHub PAT", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{20,}\b"), "HIGH"),
            ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "HIGH"),
            ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "CRITICAL"),
            ("JWT-like Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "MEDIUM"),
            ("AWS Temporary Access Key", re.compile(r"\bASIA[0-9A-Z]{16}\b"), "HIGH"),
            ("GitHub OAuth/App Token", re.compile(r"\bgh[ousr]_[0-9A-Za-z]{36}\b"), "HIGH"),
            ("GitLab Personal Access Token", re.compile(r"\bglpat-[0-9A-Za-z_-]{20,}\b"), "HIGH"),
            ("Stripe Restricted Key", re.compile(r"\brk_live_[0-9A-Za-z]{20,}\b"), "HIGH"),
            ("SendGrid API Key", re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b"), "HIGH"),
            ("Slack Webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9A-Za-z]{20,}"), "HIGH"),
            ("Twilio API Key", re.compile(r"\bSK[0-9a-f]{32}\b"), "HIGH"),
            ("Anthropic API Key", re.compile(r"\bsk-ant-[0-9A-Za-z_-]{20,}\b"), "HIGH"),
            ("OpenAI API Key", re.compile(r"\bsk-(?:proj-)?[0-9A-Za-z_-]{40,}\b"), "HIGH"),
            ("npm Access Token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"), "HIGH"),
            ("Google OAuth Client Secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_-]{28}\b"), "HIGH"),
            ("DB Connection String with Password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@\"']{1,64}:[^\s@\"']{3,128}@[A-Za-z0-9.-]+"), "HIGH"),
        ]

        def mask_secret(value):
            value = value.strip()
            if len(value) <= 10:
                return "[REDACTED]"
            return f"{value[:4]}...{value[-4:]}"

        # Track (secret_value, host_base) to avoid duplicate reporting across protocols
        reported_secrets = set()

        urls_to_scan = set()
        # Build URLs from detected services (preserving actual protocols/ports)
        for svc in services:
            if svc.get("service") not in ("http", "https", "http-alt"):
                continue
            proto = "https" if svc.get("service") in ("https", "http-alt") else "http"
            host = svc.get("host", self.original_target)
            port = str(svc.get("port", ""))
            if (proto == "https" and port == "443") or (proto == "http" and port == "80") or not port:
                root = f"{proto}://{host}"
            else:
                root = f"{proto}://{host}:{port}"
            urls_to_scan.add(root + "/")
            urls_to_scan.add(root + "/robots.txt")
            urls_to_scan.add(root + "/.env")
            urls_to_scan.add(root + "/.well-known/security.txt")

        # Fallback: if nmap found no HTTP services, always scan the primary target
        if not urls_to_scan:
            self.log("  No HTTP services from nmap — using original target for secret scan", "warn")
            for _fallback_root in [f"https://{self.original_target}", f"http://{self.original_target}"]:
                urls_to_scan.add(_fallback_root + "/")
                urls_to_scan.add(_fallback_root + "/robots.txt")
                urls_to_scan.add(_fallback_root + "/.env")
                urls_to_scan.add(_fallback_root + "/.well-known/security.txt")

        for endpoint in self.data.get("api_endpoints", []):
            ep_url = endpoint.get("url", "")
            if ep_url:
                urls_to_scan.add(ep_url)

        # Crawled pages and scripts are where leaked keys usually live (JS bundles first).
        crawled = [u for u in self.data.get("crawled_urls", []) if "?" not in u]
        crawled.sort(key=lambda u: not u.lower().split("#")[0].endswith((".js", ".json", ".map", ".env", ".txt")))
        ordered = sorted(urls_to_scan) + [u for u in crawled if u not in urls_to_scan]

        scanned = 0
        for url in ordered[:80]:
            if self._stop:
                break
            scanned += 1
            try:
                resp = requests.get(url, timeout=6, verify=False, allow_redirects=True)
                if resp.status_code >= 400:
                    continue
                response_headers = {
                    "content-type": resp.headers.get("content-type", ""),
                    "server": resp.headers.get("server", ""),
                    "cache-control": resp.headers.get("cache-control", ""),
                }
                content_type = (resp.headers.get("content-type") or "").lower()
                if any(x in content_type for x in ["image/", "font/", "application/octet-stream"]):
                    continue

                body = resp.text or ""
                if len(body) > 250000:
                    body = body[:250000]

                # Extract host from URL for grouping
                from urllib.parse import urlparse
                url_host = urlparse(url).hostname or "unknown"

                for label, pattern, risk in secret_patterns:
                    for match in pattern.findall(body):
                        token = match[0] if isinstance(match, tuple) else match
                        token_str = str(token).strip()
                        masked = mask_secret(token_str)
                        
                        # Dedup key: (secret_value, host) - report each unique secret once per host
                        dedup_key = (token_str, url_host)
                        if dedup_key in reported_secrets:
                            continue
                        reported_secrets.add(dedup_key)

                        finding = f"[{risk}] Potential {label} exposed at {url} ({masked})"
                        findings.append(finding)
                        self.result_signal.emit("Secret Findings", f" {label} at {url}", Theme.current["RED"] if risk in ("HIGH", "CRITICAL") else Theme.current["ORANGE"])
                        self.log(f"  Secret scan: {label} pattern matched at {url}", "warn")
                        self._add_finding(Finding(
                            title=f"Potential {label} exposed", severity=risk, source="secret-scan",
                            confidence="confirmed" if risk in ("HIGH", "CRITICAL") else "heuristic",
                            category="secret", host=url_host, url=url,
                            evidence=f"pattern match, value masked: {masked}",
                            remediation="Revoke and rotate the credential, then remove it from the published content."),
                            container="")

                        evidence = {
                            "type": "secret_pattern",
                            "title": label,
                            "source_url": url,
                            "status_code": resp.status_code,
                            "response_headers": response_headers,
                            "method": "GET",
                            "surface": "public",
                            "timestamp": datetime.now().isoformat(),
                            "notes": f"masked={masked}",
                        }
                        self.data["evidence"].append(evidence)
                        DB.add_evidence(
                            self.scan_id,
                            evidence["type"],
                            evidence["title"],
                            evidence["source_url"],
                            evidence["status_code"],
                            json.dumps(evidence["response_headers"], ensure_ascii=False),
                            evidence["method"],
                            evidence["surface"],
                            evidence["notes"],
                        )
            except Exception:
                continue

        self.log(f"  Secret scan checked {scanned} URLs, findings: {len(findings)}", "info")
        self.data["secret_findings"] = findings
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    #  STRUCTURED FINDINGS + OSS TOOL ORCHESTRATION (httpx / katana / nuclei / NVD)
    # ─────────────────────────────────────────────────────────────────────────
    def _add_finding(self, finding, container="Ranked Vulnerabilities"):
        """Record one structured Finding everywhere a finding has to appear.

        Returns False when the same finding was already recorded in this scan.
        """
        store = self.data.setdefault("findings", [])
        fp = finding.fingerprint
        if any(f.get("fingerprint") == fp for f in store):
            return False
        store.append(finding.to_dict())
        DB.add_finding(self.scan_id, self.target, store[-1])
        label = finding.label()
        self.data["vulnerabilities"].append(label)
        if finding.severity in self.data["risk_counts"]:
            self.data["risk_counts"][finding.severity] += 1
        DB.add_vuln(self.scan_id, finding.host or self.target, finding.source, finding.port,
                    finding.severity, finding.cve, finding.cvss, finding.title,
                    "", finding.category, "")
        color = (Theme.current["RED"] if finding.severity in ("CRITICAL", "HIGH")
                 else Theme.current["ORANGE"] if finding.severity == "MEDIUM"
                 else Theme.current["TEXT"])
        self.result_signal.emit(container, label, color)
        return True

    def _auth_headers(self):
        """Headers that carry the user's session into the crawl and the fuzzing."""
        headers = []
        cookie = (self.opts.get("auth_cookie") or "").strip()
        bearer = (self.opts.get("auth_bearer") or "").strip()
        if cookie:
            headers.append(f"Cookie: {cookie}")
        if bearer:
            headers.append(f"Authorization: Bearer {bearer}")
        for h in self.opts.get("auth_headers") or []:
            if ":" in str(h):
                headers.append(str(h).strip())
        return headers

    def _login_if_configured(self):
        """Form login (opts login_url + login_data) -> session cookie for the rest of the scan."""
        url, data = (self.opts.get("login_url") or "").strip(), (self.opts.get("login_data") or "").strip()
        if not url or not data or (self.opts.get("auth_cookie") or "").strip():
            return
        res = recon_tools.login_for_cookie(url, data, self._scope_hosts())
        if res["ok"]:
            self.opts["auth_cookie"] = res["cookie"]
            names = ", ".join(c.split("=")[0] for c in res["cookie"].split("; "))
            self.log(f"  Logged in at {url} - session cookie(s) obtained: {names}", "good")
        else:
            self.log(f"  Login at {url} failed: {res['error']} - continuing UNAUTHENTICATED", "warn")

    def _scope_hosts(self):
        """Hosts this scan is allowed to send web requests to."""
        hosts = {str(h).lower() for h in self.data.get("hosts", [])}
        hosts.add(self.target.split("/")[0].lower())
        return hosts

    def _ensure_seed_service(self, services):
        """Make sure the port the user explicitly asked for is part of the scan."""
        seed = getattr(self, "seed", None)
        if not seed:
            return services
        scheme, host, port = seed
        for svc in services:
            if str(svc.get("port")) == str(port) and svc.get("host") == host:
                if "http" not in str(svc.get("service", "")).lower():
                    svc["service"] = scheme        # the user told us this port speaks HTTP(S)
                return services
        try:
            with socket.create_connection((host, port), timeout=5):
                pass
        except OSError as e:
            self.log(f"  Port {port} from the target URL is not reachable ({e}) - cannot scan it", "warn")
            return services
        svc = {"host": host, "port": str(port), "proto": "tcp", "service": scheme, "version": "",
               "banner": "", "state": "open", "cpe": []}
        services.append(svc)
        DB.add_port(self.scan_id, host, str(port), "tcp", scheme, "", "open", "")
        self.data["services"].append(f"{port}/tcp {scheme}")
        self.result_signal.emit("Services", f"⬡ {port}/tcp  {scheme} (from target URL)", Theme.current["CYAN"])
        self.log(f"  Added {scheme}://{host}:{port} from the target URL (outside the profile's port range)", "info")
        return services

    def _web_base_urls(self, services):
        """Base URLs of every web service found by the port scan (deduplicated)."""
        urls = []
        for svc in services:
            name = str(svc.get("service", "")).lower()
            port = str(svc.get("port", ""))
            if not ("http" in name or port in ("80", "443", "8080", "8443", "8000", "8888")):
                continue
            https = ("https" in name or "ssl" in name or port in ("443", "8443", "4443"))
            scheme = "https" if https else "http"
            host = svc.get("host") or self.original_target
            default = (scheme == "https" and port == "443") or (scheme == "http" and port == "80")
            url = f"{scheme}://{host}" if (default or not port) else f"{scheme}://{host}:{port}"
            if url not in urls:
                urls.append(url)
        if not urls and "/" not in self.target:
            urls = [f"https://{self.original_target}", f"http://{self.original_target}"]
        return urls

    def stage_web_discovery(self, services):
        """Probe web services (httpx) and crawl them (katana) to find real URLs + parameters."""
        self.current_stage = "crawl"
        self.log(" STAGE 5B: WEB DISCOVERY (httpx + katana crawl) ", "stage")
        self.stage_signal.emit("Web Crawl")
        self.data.setdefault("crawled_urls", [])
        self.data.setdefault("param_urls", [])
        self.data.setdefault("forms", [])
        self.data.setdefault("technologies", [])

        if not RECON_TOOLS_AVAILABLE:
            self.log("  recon_tools module not available - crawl skipped", "warn")
            return []
        bases = self._web_base_urls(services)
        if not bases:
            self.log("  No web services to crawl", "muted")
            return []
        stop = lambda: self._stop
        scope = self._scope_hosts()
        self._login_if_configured()
        auth = self._auth_headers()
        self.data["authenticated"] = bool(auth)
        self._post_requests = []      # raw requests may contain session cookies: never exported
        if auth:
            self.log(f"  Authenticated scan: sending {len(auth)} auth header(s) with crawl and fuzzing", "info")

        live = bases
        probe = recon_tools.httpx_probe(bases, stop_check=stop, headers=auth)
        if not probe["available"]:
            self.log("  httpx (ProjectDiscovery) not found - skipping technology fingerprinting", "warn")
        else:
            live = []
            for r in probe["results"]:
                if not recon_tools.in_scope(r["url"], scope):
                    continue
                live.append(r["url"])
                tech = ", ".join(r["tech"][:8])
                line = f"{r['url']} [{r['status']}] {r['server'] or 'unknown server'}" + (f" | {tech}" if tech else "")
                self.data["technologies"].append(line)
                self.result_signal.emit("Banners", f"◉ {line[:110]}", Theme.current["TEXT2"])
                self.log(f"  httpx: {line}", "info")
            if not live:
                self.log("  httpx: no web service answered - nothing to crawl", "warn")
                return []

        if not recon_tools.find_tool("katana"):
            self.log("  katana not found - crawl skipped (install: go install github.com/projectdiscovery/katana/cmd/katana@latest)", "warn")
            return []

        duration = {"Quick": 60, "Full": 300, "Stealth": 180}.get(self.profile, 120)
        rate = 10 if self.profile == "Stealth" else 50
        for base in live[:5]:
            if self._stop:
                break
            self.log(f"  katana → {base} (max {duration}s, depth 3, same-host scope)", "info")
            c = recon_tools.katana_crawl(base, depth=3, duration=duration, rate=rate, stop_check=stop,
                                         headers=auth, submit_forms=self.opts.get("submit_forms", True))
            if c["status"] == "error":
                self.log(f"  katana failed on {base}: {c.get('stderr_tail', '')[:200]}", "warn")
                continue
            for u in c["urls"]:
                if u not in self.data["crawled_urls"]:
                    self.data["crawled_urls"].append(u)
            for u in c["param_urls"]:
                if u not in self.data["param_urls"] and len(self.data["param_urls"]) < 300:
                    self.data["param_urls"].append(u)
            self.data["forms"].extend(c["forms"])
            for raw in c.get("post_requests", []):
                if len(self._post_requests) < 100:
                    self._post_requests.append(raw)
            self.log(f"  katana: {len(c['urls'])} URLs, {len(c['param_urls'])} with parameters, "
                     f"{len(c['forms'])} forms, {len(c.get('post_requests', []))} submitted form request(s) "
                     f"({c['status']}, {c.get('seconds', 0)}s)", "good")
        self.data["post_request_count"] = len(self._post_requests)

        for u in self.data["param_urls"][:40]:
            self.result_signal.emit("API Endpoints", f" [crawl] {u[:110]}", Theme.current["CYAN"])
        return self.data["crawled_urls"]

    def stage_amplification_check(self, services):
        """Detect UDP services that can be abused as DDoS amplification/reflection vectors.

        Defensive: one small probe per vector per host (not a flood). A service that answers
        an unauthenticated UDP probe with a larger reply is a confirmed reflector the owner
        should lock down.
        """
        self.current_stage = "amplification"
        if not self.opts.get("amplification", True) or not AMPLIFICATION_AVAILABLE:
            return []
        hosts = list(dict.fromkeys(self.data.get("hosts", []) or [self.target]))[:5]
        if not hosts:
            return []
        self.log(" STAGE 5F: DDoS AMPLIFICATION / REFLECTION EXPOSURE ", "stage")
        self.stage_signal.emit("Amplification Check")
        total = 0
        for host in hosts:
            if self._stop:
                break
            hits = amplification.check_host(host, timeout=3.0, stop_check=lambda: self._stop)
            for h in hits:
                factor = h["amplification_factor"]
                sev = "HIGH" if (h["severity"] == "HIGH" or factor >= 100) else "MEDIUM"
                self._add_finding(Finding(
                    title=f"{h['name']} (amplification ~{factor}x)", severity=sev,
                    source="amplification", confidence="confirmed", category="ddos-reflector",
                    host=host, port=h["port"],
                    evidence=f"{h['request_bytes']}-byte UDP probe -> {h['response_bytes']}-byte reply "
                             f"(factor {factor}x) on {host}:{h['port']}/udp",
                    description=h["note"],
                    remediation="Restrict this UDP service to trusted networks, disable it, or enable "
                                "source-address validation (BCP38) so it cannot reflect traffic at others."),
                    container="Amplification Vectors")
                total += 1
        self.log(f"  Amplification check: {total} reflector(s) across {len(hosts)} host(s)",
                 "warn" if total else "good")
        return total

    def stage_tls_cipher_audit(self, services):
        """Cipher-suite level TLS audit with nmap's ssl-enum-ciphers script."""
        self.current_stage = "tls_ciphers"
        ports = []
        for svc in services:
            name, port = str(svc.get("service", "")).lower(), str(svc.get("port", ""))
            if ("https" in name or "ssl" in name or "tls" in name or port in ("443", "8443", "4443", "993", "995", "465")) \
                    and (svc.get("host"), port) not in ports:
                ports.append((svc.get("host") or self.target, port))
        if not ports:
            return []
        self.log(" STAGE 5D: TLS CIPHER AUDIT (nmap ssl-enum-ciphers) ", "stage")
        self.stage_signal.emit("TLS Cipher Audit")
        results = []
        for host, port in ports[:6]:
            if self._stop:
                break
            out = self.run_cmd(["nmap", "-Pn", "-p", port, "--script", "ssl-enum-ciphers", host], timeout=180)
            if not out.ok or "ssl-enum-ciphers" not in out:
                self.log(f"  cipher audit: no result for {host}:{port} ({out.status})", "muted")
                continue
            audit = parse_ssl_enum_ciphers(str(out))
            results.append({"host": host, "port": port, **audit})
            self.log(f"  {host}:{port} least cipher strength: {audit['least_strength'] or '?'} "
                     f"({len(audit['weak_ciphers'])} weak suite(s), {len(audit['warnings'])} warning(s))", "info")
            strength = audit["least_strength"]
            if strength in ("C", "D", "E", "F") or audit["weak_ciphers"]:
                sev = "HIGH" if strength in ("D", "E", "F") else "MEDIUM"
                self._add_finding(Finding(
                    title=f"Weak TLS cipher suites accepted (least strength {strength or 'n/a'})",
                    severity=sev, source="nmap-ssl-enum-ciphers", confidence="confirmed", category="tls",
                    host=host, port=port,
                    evidence="; ".join(audit["weak_ciphers"][:8]) + ((" | " + "; ".join(audit["warnings"][:4])) if audit["warnings"] else ""),
                    remediation="Disable the listed cipher suites; allow only AEAD suites (AES-GCM / ChaCha20) on TLS 1.2+."))
        self.data["tls_cipher_audit"] = results
        return results

    def stage_takeover_check(self, services):
        """Check discovered (sub)domains for dangling DNS / takeover with nuclei templates."""
        self.current_stage = "takeover"
        hosts = [h for h in self.data.get("hosts", []) if not re.match(r"^\d{1,3}(\.\d{1,3}){3}", str(h))]
        if not hosts or not RECON_TOOLS_AVAILABLE or not recon_tools.find_tool("nuclei"):
            return []
        self.log(" STAGE 5E: SUBDOMAIN TAKEOVER CHECK (nuclei takeover templates) ", "stage")
        self.stage_signal.emit("Takeover Check")
        urls = [f"https://{h}" for h in hosts[:50]] + [f"http://{h}" for h in hosts[:50]]
        r = recon_tools.nuclei_run(urls, budget=240, rate=30, extra=["-tags", "takeover"],
                                   stop_check=lambda: self._stop)
        if r["status"] in ("timeout", "error"):
            self.log(f"  takeover check ended with status '{r['status']}'", "warn")
        for f in r["findings"]:
            self._add_finding(Finding(
                title=f["name"], severity=f["severity"] if f["severity"] != "INFO" else "HIGH",
                source="nuclei", confidence="confirmed", category="takeover",
                host=recon_tools.host_of(f["matched_at"]) or f["host"], url=f["matched_at"],
                description=f["description"], evidence=f["evidence"], references=f["references"],
                remediation="Remove the dangling DNS record or re-claim the external resource it points to."))
        self.log(f"  takeover check: {len(r['findings'])} finding(s) across {len(hosts[:50])} host(s)",
                 "warn" if r["findings"] else "good")
        return r["findings"]

    def _diff_against_previous(self):
        """Compare this scan with the last completed scan of the same target."""
        prev = DB.previous_scan_id(self.target, self.scan_id)
        if prev is None:
            self.data["diff"] = None
            return
        d = DB.diff_scans(prev, self.scan_id)
        brief = lambda items: [{"severity": f.get("severity"), "title": f.get("title"),
                                "where": f.get("url") or f"{f.get('host')}:{f.get('port')}",
                                "fingerprint": f.get("fingerprint")} for f in items]
        self.data["diff"] = {"previous_scan": prev, "new": brief(d["new"]), "fixed": brief(d["fixed"]),
                             "persisting": len(d["persisting"])}
        self.log(f" Compared with scan #{prev}: {len(d['new'])} new, {len(d['fixed'])} no longer present, "
                 f"{len(d['persisting'])} still present", "warn" if d["new"] else "good")
        for f in d["new"][:10]:
            self.log(f"   NEW   [{f.get('severity')}] {f.get('title')}", "warn")
        for f in d["fixed"][:10]:
            self.log(f"   GONE  [{f.get('severity')}] {f.get('title')}", "good")

    def stage_dast_scan(self, services):
        """Fuzz every crawled parameter with nuclei's DAST templates (SQLi, XSS, SSTI, LFI...)."""
        self.current_stage = "dast"
        if not self.opts.get("enable_web_vuln", True):
            self.log(" Web vulnerability testing (DAST) disabled - skipping stage", "muted")
            return []
        self.log(" STAGE 6.6: WEB VULNERABILITY TESTING (nuclei DAST on crawled parameters) ", "stage")
        self.stage_signal.emit("Web Vuln Testing")
        self.prog("vuln", 35)

        if not RECON_TOOLS_AVAILABLE or not recon_tools.find_tool("nuclei"):
            self.log("  nuclei not found - DAST skipped. Injection flaws were NOT tested.", "warn")
            return []
        urls = [u for u in self.data.get("param_urls", []) if recon_tools.in_scope(u, self._scope_hosts())]
        posts = list(getattr(self, "_post_requests", []))
        if not urls and not posts:
            self.log("  No parameterised URLs or submitted forms were discovered - nothing to fuzz", "muted")
            self.prog("vuln", 40)
            return []

        budget = 300 if self.profile == "Quick" else 900
        rate = 10 if self.profile == "Stealth" else 50
        auth = self._auth_headers()
        r = {"findings": [], "seconds": 0.0, "status": "ok"}
        runs = []
        if urls:
            runs.append((f"{len(urls)} parameterised GET URL(s)", dict(urls=urls)))
        if posts:
            runs.append((f"{len(posts)} submitted form request(s) (POST bodies)", dict(urls=[], input_jsonl=posts)))
        for what, kwargs in runs:
            if self._stop:
                break
            self.log(f"  nuclei -dast on {what} (budget {budget}s)", "info")
            part = recon_tools.nuclei_run(dast=True, budget=budget, rate=rate, headers=auth,
                                          stop_check=lambda: self._stop, **kwargs)
            if part["status"] in ("timeout", "error"):
                self.log(f"  nuclei DAST ended with status '{part['status']}' - results may be partial "
                         f"{part.get('stderr_tail', '')[-160:]}", "warn")
            if "input_jsonl" in kwargs:
                for f in part["findings"]:
                    f["evidence"] = ("POST body; " + f["evidence"]).strip("; ")
            r["findings"] += part["findings"]
            r["seconds"] += part.get("seconds", 0.0)

        added = 0
        for f in r["findings"]:
            tid = f["template_id"].lower()
            category = next((c for c in ("sqli", "xss", "ssti", "lfi", "rfi", "ssrf", "xxe", "cmdi",
                                         "crlf", "redirect", "csti") if c in tid or c in f["tags"]), "injection")
            finding = Finding(
                title=f["name"], severity=f["severity"], source="nuclei-dast", confidence="confirmed",
                category=category, host=recon_tools.host_of(f["matched_at"]), url=f["matched_at"],
                parameter=f["parameter"], cve=f["cve"], cvss=f["cvss"], description=f["description"],
                evidence=f["evidence"], remediation=f["remediation"], references=f["references"])
            if self._add_finding(finding, container="sqli" if category == "sqli" else "Ranked Vulnerabilities"):
                added += 1
                self.log(f"  DAST: {finding.label()}", "warn")
        self.log(f"  DAST complete: {added} confirmed finding(s) on {len(urls)} URL(s) + {len(posts)} form request(s) "
                 f"in {round(r.get('seconds', 0), 1)}s",
                 "warn" if added else "good")
        self.prog("vuln", 40)
        return r["findings"]

    def stage_cve_lookup(self, services):
        """Look up CVEs for each detected product version in the NVD (by nmap CPE)."""
        self.current_stage = "cve"
        if not self.opts.get("nvd", True) or os.getenv("DISABLE_NVD", "").lower() in ("1", "true", "yes"):
            self.log(" NVD CVE lookup disabled", "muted")
            return []
        if not CVE_LOOKUP_AVAILABLE:
            return []
        self.log(" STAGE 5C: CVE LOOKUP (NVD, by detected product version) ", "stage")
        self.stage_signal.emit("CVE Lookup")

        cache_dir = os.path.join(RESULTS_DIR, "nvd_cache")
        seen_cpe, lookups, total = set(), 0, 0
        for svc in services:
            if self._stop or lookups >= 12:
                break
            cpes = [c for c in svc.get("cpe", []) if c.startswith("cpe:/a:") and cve_lookup.cpe22_to_23(c)]
            if not cpes:
                continue
            cpe = cpes[0]
            if cpe in seen_cpe:
                continue
            seen_cpe.add(cpe)
            lookups += 1
            res = cve_lookup.lookup(cpe, cache_dir, limit=5)
            epss = cve_lookup.epss_scores([c["cve"] for c in res["cves"]], cache_dir) if res["cves"] else {}
            if res["error"]:
                self.log(f"  NVD lookup failed for {cpe}: {res['error']}", "warn")
                continue
            product = svc.get("version") or svc.get("service")
            self.log(f"  NVD: {res['total']} CVE(s) list {product} ({res['cpe']}) as affected", "info")
            for c in res["cves"]:
                if c["cvss"] < 4.0 and not c["kev"]:
                    continue
                finding = Finding(
                    title=f"{product}: {c['cve']}", severity=severity_from_cvss(c["cvss"]),
                    source="nvd", confidence="version-match", category="cve",
                    host=svc.get("host", ""), port=svc.get("port", ""), cve=c["cve"], cvss=c["cvss"],
                    description=c["description"][:600], kev=c["kev"], references=[c["url"]],
                    epss=epss.get(c["cve"], 0.0),
                    evidence=f"detected version CPE {res['cpe']}",
                    remediation="Upgrade to a vendor-fixed version, or confirm the fix was back-ported.")
                if self._add_finding(finding):
                    total += 1
        if lookups == 0:
            self.log("  No service reported a versioned CPE - nothing to look up", "muted")
        else:
            self.log(f"  CVE lookup: {total} version-matched CVE finding(s) from {lookups} product(s)", "good")
        return total

    def stage_exploit_lookup(self, services):
        """List public Exploit-DB references for the exact product versions detected."""
        self.current_stage = "exploit"
        self.log("━━━ STAGE 7: EXPLOIT REFERENCE LOOKUP (Exploit-DB) ━━━", "stage")
        self.stage_signal.emit("Exploit Lookup")
        self.prog("vuln", 40)
        exploits = []
        if not EXPLOIT_SEARCH_AVAILABLE or not exploit_search.available():
            self.log("  Exploit-DB index not installed - lookup skipped (install it: danishrecon setup exploitdb)", "warn")
            self.prog("vuln", 60)
            return exploits

        searched = set()
        for svc in services:
            if self._stop:
                break
            m = re.search(r"^(.*?)[ /_-]*v?(\d+(?:\.\d+)+)", svc.get("version") or "")
            if not m:
                continue   # no version detected -> a product name alone proves nothing
            product, version = (m.group(1).strip() or svc["service"]), m.group(2)
            key = (product.lower(), version)
            if key in searched:
                continue
            searched.add(key)
            hits = exploit_search.search(product, version, limit=8)
            self.log(f"  exploit-db: '{product} {version}' -> {len(hits)} reference(s)", "muted")
            for h in hits:
                label = f"EDB-{h['id']}: {h['title'][:100]}" + (f" [{h['cves'].replace(';', ', ')}]" if h["cves"] else "")
                exploits.append({"service": svc["service"], **h})
                self.result_signal.emit("Exploit Suggestions", f"⚡ {label}", Theme.current["RED"])
                self.data["exploits"].append(f"{svc['service']}:{svc['port']} - {label}")
        if not searched:
            self.log("  No versioned services detected - no exploit references to list", "muted")
        self.prog("vuln", 60)
        return exploits

    def stage_ai_ranking(self, services, nikto_findings):
        self.current_stage = "ai"
        self.log(" STAGE 8: AI VULNERABILITY RANKING + CVSS ", "stage")
        self.stage_signal.emit("AI Ranking")
        self.prog("ai", 10)

        RISK_MATRIX = {
            # (service, base_risk, base_cvss)
            "ftp":      ("CRITICAL", 9.0), "telnet":  ("CRITICAL", 9.5),
            "rdp":      ("CRITICAL", 9.8), "smb":     ("CRITICAL", 9.3),
            "vnc":      ("CRITICAL", 8.8), "mysql":   ("HIGH",     7.5),
            "mssql":    ("HIGH",     7.5), "oracle":  ("HIGH",     7.5),
            "ssh":      ("HIGH",     6.5), "mongodb": ("HIGH",     7.8),
            "redis":    ("HIGH",     7.5), "elastic":  ("HIGH",    7.5),
            "http":     ("MEDIUM",   5.3), "https":    ("MEDIUM",  5.0),
            "http-alt": ("MEDIUM",   5.5), "smtp":     ("MEDIUM",  4.3),
            "dns":      ("MEDIUM",   5.0), "snmp":     ("HIGH",    7.5),
        }

        vulns = []
        for svc in services:
            if self._stop: break
            sname = svc["service"].lower()
            base_risk, base_cvss = RISK_MATRIX.get(sname, ("LOW", 3.0))

            # Context scoring
            score_adj = 0.0
            if svc["port"] in ("21","23","3389","5900"): score_adj += 0.5
            if not svc["version"]: score_adj += 0.3   # unknown version = risk
            if "anonymous" in svc.get("banner","").lower(): score_adj += 1.0
            final_cvss = min(10.0, base_cvss + score_adj)
            if   final_cvss >= 9.0: final_risk = "CRITICAL"
            elif final_cvss >= 7.0: final_risk = "HIGH"
            elif final_cvss >= 4.0: final_risk = "MEDIUM"
            else:                   final_risk = "LOW"

            # CVE lookup - only CVEs whose version/banner rule actually matches this service
            cves = matched_cves(sname, svc.get("version", ""), svc.get("banner", ""))
            if cves:
                # A confirmed CVE outranks the generic exposure score for the service.
                final_cvss = max(final_cvss, max(c["cvss"] for c in cves))
                if   final_cvss >= 9.0: final_risk = "CRITICAL"
                elif final_cvss >= 7.0: final_risk = "HIGH"
                elif final_cvss >= 4.0: final_risk = "MEDIUM"
            cve_str = ", ".join(c["cve"] for c in cves[:2]) if cves else ""
            mitre  = cves[0].get("mitre","") if cves else ""
            tech   = cves[0].get("tech","") if cves else ""
            compliance = cves[0].get("compliance","") if cves else ""
            tactic = MITRE_TACTICS.get(mitre,"") if mitre else ""

            # Add to MITRE tracking
            if mitre and mitre not in [m["id"] for m in self.data["mitre_techniques"]]:
                self.data["mitre_techniques"].append({"id":mitre,"tactic":tactic,"tech":tech,"service":sname})
                self.result_signal.emit("MITRE ATT&CK",
                    f"[{mitre}] {tactic}  {tech} ({sname})", Theme.current["PURPLE"])

            risk_icon = {"CRITICAL":"","HIGH":"","MEDIUM":"","LOW":""}.get(final_risk,"")
            label = (f"[{final_risk:8s}] CVSS:{final_cvss:.1f}  "
                     f"{svc['service']:12s} :{svc['port']:5s}  {cve_str}")
            compliance_short = compliance.split(",")[0] if compliance else ""
            if compliance_short:
                label += f"  [{compliance_short}]"

            vulns.append({"service":sname,"port":svc["port"],"risk":final_risk,
                          "cvss":final_cvss,"cve":cve_str,"mitre":mitre})
            self.result_signal.emit("Ranked Vulnerabilities", label,
                Theme.current["RED"] if final_risk=="CRITICAL" else
                Theme.current["ORANGE"] if final_risk=="HIGH" else
                Theme.current["TEXT"])
            self.data["vulnerabilities"].append(label)
            self.data["risk_counts"][final_risk] = self.data["risk_counts"].get(final_risk,0)+1

            DB.add_vuln(self.scan_id, svc["host"], sname, svc["port"],
                        final_risk, cve_str, final_cvss,
                        (f"{cves[0]['title']} ({sname} on :{svc['port']})" if cves
                         else f"Exposed service: {sname} on :{svc['port']}"),
                        mitre, tech, compliance)

        # Nikto findings - parse severity from stored format and respect it
        for f in nikto_findings:  # Process ALL findings without limit
            # Check if finding has a severity level already (format: "[SEVERITY] ...")
            severity_match = re.match(r'\[(\w+)\]', f)
            if severity_match:
                severity = severity_match.group(1)
                # Validate it's a known severity
                if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    severity = "MEDIUM"  # Default fallback
            else:
                severity = "MEDIUM"  # Default for findings without explicit severity
            
            # Determine CVSS based on severity
            cvss_map = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0}
            cvss = cvss_map.get(severity, 5.0)
            
            label = f" [{severity:8s}] CVSS:{cvss:.1f}  web vulnerability  {f}"
            vulns.append({"service":"web","risk":severity,"cvss":cvss})
            self.result_signal.emit("Ranked Vulnerabilities", label, 
                Theme.current["RED"] if severity=="CRITICAL" else
                Theme.current["ORANGE"] if severity=="HIGH" else
                Theme.current["TEXT"])
            self.data["vulnerabilities"].append(label)
            self.data["risk_counts"][severity] = self.data["risk_counts"].get(severity,0)+1

        vulns.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["risk"],4))
        self.chart_signal.emit({"risk_counts": self.data["risk_counts"],
                                "port_states": self.data["port_states"]})
        self.prog("ai", 100)
        return vulns

    #  Gemini AI Analysis of Vulnerabilities 
    def stage_gemini_analysis(self, services):
        """
        Uses Google Gemini API to generate natural-language explanations
        of discovered vulnerabilities and their implications
        Only analyzes CRITICAL services to stay within API rate limits
        """
        if not self.gemini_analyzer or not self.gemini_analyzer.enabled:
            self.log("  Gemini analysis disabled (API unavailable)", "warn")
            return
        
        self.current_stage = "gemini"
        self.log(" STAGE 8.5: GEMINI AI VULNERABILITY ANALYSIS ", "stage")
        self.stage_signal.emit("AI Analysis")
        self.prog("gemini", 10)
        
        # Define which services are critical (worth API calls)
        critical_services = {
            "http", "https", "http-alt",  # Web services
            "ssh", "telnet",               # Remote access
            "ftp", "sftp",                 # File transfer
            "smb", "cifs", "netbios-ssn",  # File sharing
            "mysql", "postgresql", "mssql", "oracle", "mongodb",  # Databases
            "smtp", "pop3", "imap", "pop", # Mail services
            "snmp",                        # Management
            "rdp", "ms-wbt-server",        # Remote desktop
            "kerberos", "kdc",             # Authentication
            "dns", "domain",               # DNS services
            "ldap", "ldaps",               # Directory services
            "rsync", "nfs",                # Remote filesystems
            "vnc"                          # Remote display
        }
        
        # Filter to only critical services
        critical_svcs = [s for s in services if s["service"].lower() in critical_services]
        low_priority_svcs = [s for s in services if s["service"].lower() not in critical_services]
        
        # Log filtering results
        if low_priority_svcs:
            skipped_names = ", ".join([f"{s['service']} ({s['port']})" for s in low_priority_svcs[:5]])
            if len(low_priority_svcs) > 5:
                skipped_names += f" ... and {len(low_priority_svcs) - 5} more"
            self.log(f"  ⊘ Skipping {len(low_priority_svcs)} low-risk services: {skipped_names}", "info")
        
        # Build vulnerability data for Gemini analysis (critical services only)
        vulns_for_analysis = []
        for svc in critical_svcs:
            if self._stop: break
            sname = svc["service"].lower()
            
            # Find this vulnerability in our ranked list
            risk_level = "LOW"
            for vuln_entry in self.data["vulnerabilities"]:
                if sname in vuln_entry.lower() and f":{svc['port']}" in vuln_entry:
                    if "CRITICAL" in vuln_entry: risk_level = "CRITICAL"
                    elif "HIGH" in vuln_entry: risk_level = "HIGH"
                    elif "MEDIUM" in vuln_entry: risk_level = "MEDIUM"
                    break
            
            # Get CVE info
            cves = matched_cves(sname, svc.get("version", ""), svc.get("banner", ""))
            cve_id = cves[0]["cve"] if cves else "N/A"
            cvss_score = cves[0].get("cvss", 5.0) if cves else 0.0
            
            vuln_data = {
                "id": f"{sname}_{svc['port']}",
                "name": f"{sname.upper()} on port {svc['port']}",
                "service": sname,
                "port": svc["port"],
                "version": svc.get("version", "Unknown"),
                "cve": cve_id,
                "cvss_score": cvss_score,
                "severity": risk_level,
                "description": f"Service {sname} running on port {svc['port']}",
                "exploit_available": any("exploit" in str(e).lower() for e in self.data.get("exploits", []))
            }
            vulns_for_analysis.append(vuln_data)
        
        # Analyze each vulnerability with Gemini — fallback if nothing found from services
        if not vulns_for_analysis:
            # Fallback: build a minimal entry for the primary target web surface
            # so we always get at least a basic security overview from Gemini
            self.log("  No service-matched vulns — falling back to web surface analysis on primary target", "warn")
            vulns_for_analysis = [{
                "id": f"web_{self.original_target}",
                "name": f"Web Application on {self.original_target}",
                "service": "https",
                "port": "443",
                "version": "(CDN/proxy — Vercel/Cloudflare)",
                "cve": "N/A",
                "cvss_score": 5.0,
                "severity": "MEDIUM",
                "description": (
                    f"Web application hosted on {self.original_target} behind a CDN/proxy. "
                    f"Direct port access is restricted. Potential web-layer vulnerabilities: "
                    f"missing security headers, CORS misconfiguration, XSS, CSRF, broken auth."
                ),
                "exploit_available": False,
            }]
            # NOTE: do NOT return here — fall through so the fallback entry gets analyzed below
        
        analyzed_count = 0
        for i, vuln in enumerate(vulns_for_analysis, 1):
            if self._stop: break
            
            self.log(f"  [{i}/{len(vulns_for_analysis)}] Analyzing: {vuln['name']}", "info")
            
            analysis = self.gemini_analyzer.analyze_vulnerability(vuln)
            if analysis:
                self.data["gemini_analyses"][vuln["id"]] = analysis
                analyzed_count += 1
                self.log(f"    ✓ Analysis complete", "good")
            else:
                self.log(f"    ✗ Analysis failed - API limit or error", "warn")
            
            # Update progress
            progress = 10 + int((i / len(vulns_for_analysis)) * 80)
            self.prog("gemini", progress)
        
        # Generate executive summary (with error handling so scan doesn't crash)
        self.log("  Generating executive summary...", "info")
        try:
            summary = self.gemini_analyzer.generate_executive_summary(self.data)
            if summary:
                self.data["gemini_analyses"]["executive_summary"] = summary
                self.log("  ✓ Executive summary generated", "good")
            else:
                self.log("  ✗ Could not generate executive summary (API limit)", "warn")
        except Exception as e:
            self.log(f"  ✗ Executive summary failed (continuing scan): {str(e)[:100]}", "warn")
        
        self.log(f" Completed AI analysis for {analyzed_count}/{len(vulns_for_analysis)} critical services", "good")
        self.prog("gemini", 100)

    #  Compliance Mapping 
    def stage_compliance(self, vulns):
        self.current_stage = "compliance"
        self.log(" COMPLIANCE MAPPING ", "stage")
        self.stage_signal.emit("Compliance Check")

        # Map vulns to relevant frameworks based on actual findings
        frameworks = {
            "PCI-DSS": {"services": {"ftp","ssh","mysql","mssql","http","https","smb"}, "controls": []},
            "HIPAA":   {"services": {"mysql","mssql","oracle","https","encryption"}, "controls": []},
            "NIST":    {"services": {"ssh","http","https","rdp","smb","mysql"}, "controls": []},
            "CIS":     {"services": {"ssh","rdp","smb","http","https","mysql"}, "controls": []},
            "OWASP":   {"services": {"http","https","web"}, "controls": []},
        }

        # Collect actual services found in this scan
        found_services = {v.get("service", "").lower() for v in vulns}
        critical_high_vulns = [v for v in vulns if v.get("risk") in ("CRITICAL", "HIGH")]

        for fw, data in frameworks.items():
            relevant = found_services & data["services"]
            if relevant:
                # Populate control list from CVE_DB if available
                for svc in relevant:
                    cve_list = CVE_DB.get(svc, [])
                    for entry in cve_list:
                        comp = entry.get("compliance", "")
                        for item in comp.split(","):
                            item = item.strip()
                            if fw in item:
                                control = item.split(":")[1] if ":" in item else item
                                if control not in data["controls"]:
                                    data["controls"].append(control)

                # Build status line based on actual findings for this framework
                affected_by_vulns = [v for v in critical_high_vulns if v.get("service") in relevant]
                if affected_by_vulns:
                    status = f" FAIL ({len(affected_by_vulns)} critical findings)"
                    color = Theme.current["RED"]
                else:
                    # An automated scan cannot certify compliance - absence of high
                    # findings only means nothing was flagged for these controls.
                    status = " REVIEW (no high-severity findings)"
                    color = Theme.current["TEXT2"]
                
                controls_list = data["controls"][:6]
                label = f"{status}  {fw}: {len(relevant)} service(s), {len(controls_list)} controls to review"
                self.result_signal.emit("Compliance", label, color)
                self.data["compliance"].append(label)
                
                # Show which services trigger this framework
                for svc in sorted(relevant):
                    svc_vulns = [v for v in vulns if v.get("service") == svc]
                    highest_risk = max((v.get("risk") for v in svc_vulns), default="LOW")
                    self.result_signal.emit("Compliance", f"     {svc.upper()}: {highest_risk}", Theme.current["TEXT2"])
                
                # Show affected controls
                if controls_list:
                    self.result_signal.emit("Compliance", f"     Affected Controls:", Theme.current["TEXT2"])
                    for ctrl in controls_list:
                        self.result_signal.emit("Compliance", f"       — {ctrl}", Theme.current["TEXT2"])

    #  Attack Paths 
    def stage_attack_paths(self, services):
        self.current_stage = "paths"
        self.log(" STAGE 9: ATTACK PATH GENERATION ", "stage")
        self.stage_signal.emit("Attack Paths")

        # Build attack chains based on ACTUAL services and vulnerabilities found
        # Each chain is triggered by a specific service being present
        
        seen = set()
        added_count = 0
        
        # Iterate through services and generate contextual chains
        services_with_ports = [s for s in services if s.get("port") and s.get("state") == "open"]
        
        for svc in services_with_ports:
            svc_lower = svc["service"].lower()
            port = svc["port"]
            
            # Generate paths specific to this service + port combo
            if svc_lower == "ftp":
                paths = [
                    f"External Attacker → FTP:{port} → Anonymous Login → File Exfiltration → Data Breach",
                    f"External Attacker → FTP:{port} → Weak Creds (Default/Dict) → PHP Shell Upload → RCE",
                ]
            elif svc_lower == "ssh":
                paths = [
                    f"Insider/External → SSH:{port} → Weak Key or Brute Force → Shell Access → Privilege Escalation",
                    f"Attacker → SSH:{port} → Stolen Credentials → Persistence via authorized_keys → Lateral Movement",
                ]
            elif svc_lower == "http":
                paths = [
                    f"External → HTTP:{port} → SQLi in Login → DB Dump → Credential Harvest → Account Takeover",
                    f"External → HTTP:{port} → Reflected XSS → Session Hijack → Authenticated Abuse",
                    f"External → HTTP:{port} → Path Traversal → /etc/passwd Read → User Enum + RCE Setup",
                    f"External → HTTP:{port} → File Upload Bypass → Webshell Upload → OS Command Execution",
                ]
            elif svc_lower == "https":
                paths = [
                    f"External → HTTPS:{port} → Weak Ciphers/TLS Downgrade → MitM → Session Intercept",
                    f"External → HTTPS:{port} → App Vulnerability (SQLi/SSRF) → Backend Network Access",
                ]
            elif svc_lower == "http-alt":
                paths = [
                    f"External → Tomcat/Alt-HTTP:{port} → AJP Ghostcat Exploit → Sensitive File Read → Config Leak + RCE",
                    f"External → Alt-HTTP:{port} → Default Admin Credentials → WAR Deployment → Full App Compromise",
                ]
            elif svc_lower == "mysql":
                paths = [
                    f"Network → MySQL:{port} → No Root Password / Default Creds → Full Database Access → Data Exfil + Load_File RCE",
                    f"App Vulnerability (SQLi) → MySQL:{port} → SQL Query Abuse → DB Dump → Credential+PII Harvest",
                ]
            elif svc_lower == "mssql":
                paths = [
                    f"Network → MSSQL:{port} → Default 'sa' Password → Database Control → Extended Stored Procedures RCE",
                    f"Domain User → MSSQL:{port} → Impersonation + xp_cmdshell → OS Command Execution as MSSQL Service Account",
                ]
            elif svc_lower == "rdp":
                paths = [
                    f"Network → RDP:{port} → BlueKeep (CVE-2019-0708) → SYSTEM Privilege Shell → Domain Admin Compromise",
                    f"Network → RDP:{port} → Credential Spray (Weak Password) → Desktop Access + Persistence",
                ]
            elif svc_lower == "smb":
                paths = [
                    f"Network → SMB:{port} → EternalBlue (MS17-010) → SYSTEM Shell → Ransomware Deployment",
                    f"Internal Network → SMB:{port} → Null Session Enumeration → User/Share Mapping → Credential Relay → Domain Admin",
                ]
            elif svc_lower == "smtp":
                paths = [
                    f"External → SMTP:{port} → Open Relay Flag → Spoof Emails from Company Domain → Phishing Campaign + Brand Damage",
                    f"External → SMTP:{port} → VRFY/EXPN Commands Active → User Enumeration → Targeted Phishing",
                ]
            elif svc_lower == "snmp":
                paths = [
                    f"Network → SNMP:{port} → Default Community String (public) → Device/Network Enumeration → Config Read",
                    f"Network → SNMP:{port} → SNMPv1/v2 Weakness → Brute Force Community → Network Device Compromise",
                ]
            else:
                paths = [
                    f"External Attacker → {svc_lower.upper()}:{port} → Service Exploit → System Compromise",
                ]

            # Add each path if not already seen
            for path in paths:
                if path not in seen:
                    seen.add(path)
                    self.result_signal.emit("Attack Paths", f" {path}", Theme.current["ORANGE"])
                    self.log(f"  Path: {path[:80]}", "info")
                    self.data["attack_paths"].append(path)
                    added_count += 1
        
        # If no traditional services but web vulns found, add web-specific paths
        if added_count == 0 and self.data.get("vulnerabilities"):
            web_paths = [
                "Attacker → CDN/Web App → Missing CSP / X-Frame-Options → XSS Injection → Session Hijack → Account Takeover",
                "Attacker → Web App → CORS Misconfiguration (Allow-Origin: *) → Cross-Origin Data Leak → Sensitive Info Theft",
                "Attacker → DNS → Missing SPF/DMARC Records → Email Spoofing → Phishing Campaign → Credential+MFA Token Harvest",
                "Attacker → Web App → CORS + JSONP Bypass → Cross-Site Request Forgery → Unauthorized Actions on User Account",
                "Attacker → CDN / Edge → Cache Poisoning → Serve Malicious Content → Mass User Compromise + CnC Redirect",
                "Attacker → Subdomain Enumeration → Forgotten/Unpatched Subdomain → Takeover or Phishing Host Setup",
            ]
            for path in web_paths:
                if path not in seen:
                    seen.add(path)
                    self.result_signal.emit("Attack Paths", f" {path}", Theme.current["ORANGE"])
                    self.log(f"  Path: {path[:80]}", "info")
                    self.data["attack_paths"].append(path)

    #  Recommendations 
    def stage_recommendations(self, vulns):
        self.current_stage = "recs"
        self.log(" SECURITY RECOMMENDATIONS ", "stage")
        self.stage_signal.emit("Recommendations")

        specific_actions = {
            "ftp": "Disable FTP and migrate to SFTP/SCP. Block port 21 at the perimeter and remove anonymous access.",
            "telnet": "Disable Telnet and enforce SSH with key-based authentication only.",
            "ssh": "Disable password auth, restrict source IPs, and enforce MFA for privileged access.",
            "http": "Force HTTPS redirect, deploy HSTS, and add CSP/X-Frame-Options/X-Content-Type-Options headers.",
            "https": "Enforce TLS 1.2+ only, remove weak ciphers, and rotate certificates with monitoring.",
            "http-alt": "Disable or firewall AJP/admin interfaces and restrict management to trusted hosts.",
            "mysql": "Bind database to localhost/private network, rotate credentials, and enforce least privilege.",
            "rdp": "Restrict RDP behind VPN, enable NLA and MFA, and patch all known RDP CVEs.",
            "smb": "Disable SMBv1, patch SMB vulnerabilities, block internet exposure of port 445, and enable SMB signing.",
            "smtp": "Disable open relay, enforce STARTTLS/TLS, and configure SPF, DKIM, and DMARC.",
            "snmp": "Replace default community strings and migrate to SNMPv3 with auth and encryption.",
            "web": "Fix web misconfigurations and deploy WAF rules for high-risk inputs and attack patterns.",
        }

        risk_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        seen_recs = set()

        def add_rec(rec_text, color):
            if rec_text in seen_recs:
                return
            seen_recs.add(rec_text)
            self.result_signal.emit("Security Recommendations", rec_text, color)
            self.data["recommendations"].append(rec_text)

        prioritized = sorted(
            vulns,
            key=lambda v: (
                risk_rank.get(v.get("risk", "LOW"), 4),
                -float(v.get("cvss", 0.0) or 0.0),
            ),
        )

        # Create finding-specific remediation lines so recommendations differ per scan.
        for vuln in prioritized[:12]:
            svc = vuln.get("service", "").lower()
            if svc not in specific_actions:
                continue
            risk = vuln.get("risk", "MEDIUM")
            port = vuln.get("port", "?")
            cvss = float(vuln.get("cvss", 0.0) or 0.0)
            cve = (vuln.get("cve") or "").strip()
            cve_part = f"; CVE: {cve}" if cve else ""
            rec = f"{risk}: {svc.upper()} on port {port} (CVSS {cvss:.1f}{cve_part}) - {specific_actions[svc]}"
            add_rec(rec, Theme.current["GREEN"])

        # Add context-aware guidance based on observed exposure profile.
        crit_count = len([v for v in vulns if v.get("risk") == "CRITICAL"])
        high_count = len([v for v in vulns if v.get("risk") == "HIGH"])
        if crit_count or high_count:
            add_rec(
                f"PRIORITY: Remediate {crit_count} CRITICAL and {high_count} HIGH findings first (Critical <24h, High <7 days).",
                Theme.current["TEXT2"],
            )

        if any(v.get("service") in {"ssh", "rdp", "smb", "telnet", "ftp", "vnc"} for v in vulns):
            add_rec(
                "HARDEN ACCESS: Restrict remote administration ports to VPN/jump-host ranges and enforce MFA for admin workflows.",
                Theme.current["TEXT2"],
            )

        if any(v.get("service") in {"http", "https", "http-alt", "web"} for v in vulns):
            add_rec(
                "WEB DEFENSE: Add continuous web scanning in CI/CD and block high-risk payloads using WAF virtual patching.",
                Theme.current["TEXT2"],
            )

        if any(v.get("service") in {"mysql", "mssql", "oracle", "mongodb", "redis", "elastic"} for v in vulns):
            add_rec(
                "DATA LAYER: Move databases to private network zones and allow inbound access only from approved application hosts.",
                Theme.current["TEXT2"],
            )

        if any("SPF" in str(v).upper() or "DMARC" in str(v).upper() for v in self.data.get("vulnerabilities", [])):
            add_rec(
                "MEDIUM: Configure SPF, DMARC, and DKIM records to prevent email spoofing and phishing attacks.",
                Theme.current["TEXT2"],
            )

        if not self.data["recommendations"]:
            add_rec(
                "LOW: No major service-specific findings were identified. Maintain patch hygiene and continuous monitoring.",
                Theme.current["TEXT2"],
            )

    #  Network Attack Graph 
    def stage_attack_graph(self, services):
        self.current_stage = "graph"
        self.log(" STAGE 10: NETWORK ATTACK GRAPH ", "stage")
        self.stage_signal.emit("Attack Graph")

        fig = plt.figure(figsize=(20, 13), facecolor="#080C18")
        gs  = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

        #  Main attack graph 
        ax1 = fig.add_subplot(gs[:, :2])
        ax1.set_facecolor("#080C18")

        G = nx.DiGraph()
        node_meta = {}

        G.add_node("ATTACKER",        meta=("attacker",  "#EF4444", 3200))
        G.add_node("INTERNET",        meta=("net",       "#475569", 2000))
        G.add_node("FIREWALL",        meta=("fw",        "#F59E0B", 2000))
        target_node = f"TARGET\n{self.target[:15]}"
        G.add_node(target_node,       meta=("target",    "#00E5FF", 2800))

        G.add_edge("ATTACKER",   "INTERNET",    label="probe")
        G.add_edge("INTERNET",   "FIREWALL",    label="bypass")
        G.add_edge("FIREWALL",   target_node,   label="access")

        svc_colors = {
            "ftp":"#EF4444","telnet":"#EF4444","rdp":"#EF4444","smb":"#EF4444",
            "ssh":"#F59E0B","mysql":"#F59E0B","mssql":"#F59E0B","mongodb":"#F59E0B",
            "http":"#00E5FF","https":"#8B5CF6","http-alt":"#F59E0B",
            "smtp":"#10B981","dns":"#10B981",
        }

        for svc in services[:12]:
            sname  = svc["service"].upper()
            sport  = svc["port"]
            snode  = f"{sname}\n:{sport}"
            enode  = f"EXPLOIT\n{sname}"
            G.add_node(snode, meta=("service", svc_colors.get(svc["service"].lower(),"#10B981"), 1800))
            G.add_node(enode, meta=("exploit", "#EF4444", 1400))
            G.add_edge(target_node, snode, label="exposes")
            G.add_edge(snode, enode, label="vuln")
            G.add_edge("ATTACKER", enode, label="exploits", style="dashed")

        try:
            pos = nx.kamada_kawai_layout(G)
        except:
            pos = nx.spring_layout(G, seed=42, k=3.0)

        colors = []
        sizes  = []
        for n in G.nodes():
            meta = G.nodes[n].get("meta", ("x","#64748B",1600))
            colors.append(meta[1])
            sizes.append(meta[2])

        # Draw edges with different styles
        solid_edges  = [(u,v) for u,v,d in G.edges(data=True) if d.get("style") != "dashed"]
        dashed_edges = [(u,v) for u,v,d in G.edges(data=True) if d.get("style") == "dashed"]

        nx.draw_networkx_edges(G, pos, edgelist=solid_edges,
            edge_color="#1E3A5F", arrows=True, arrowsize=18,
            width=1.8, alpha=0.9, connectionstyle="arc3,rad=0.08", ax=ax1)
        nx.draw_networkx_edges(G, pos, edgelist=dashed_edges,
            edge_color="#EF444440", arrows=True, arrowsize=14,
            width=1.0, alpha=0.5, style="dashed",
            connectionstyle="arc3,rad=-0.12", ax=ax1)
        nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=sizes,
            alpha=0.93, ax=ax1)
        nx.draw_networkx_labels(G, pos, font_color="#F1F5F9",
            font_size=6.5, font_weight="bold", ax=ax1)
        edge_labels = {(u,v): d["label"] for u,v,d in G.edges(data=True) if "label" in d and d.get("style")!="dashed"}
        nx.draw_networkx_edge_labels(G, pos, edge_labels,
            font_color="#64748B", font_size=5.5, ax=ax1)

        patches = [
            mpatches.Patch(color="#EF4444", label="Critical / Attacker"),
            mpatches.Patch(color="#F59E0B", label="High Risk"),
            mpatches.Patch(color="#00E5FF", label="Target / HTTP"),
            mpatches.Patch(color="#8B5CF6", label="HTTPS"),
            mpatches.Patch(color="#10B981", label="Low Risk"),
            mpatches.Patch(color="#475569", label="Infrastructure"),
        ]
        ax1.legend(handles=patches, loc="lower left",
            facecolor="#0C1220", edgecolor="#1E293B", labelcolor="#E2E8F0",
            fontsize=7.5, framealpha=0.9)
        ax1.set_title(f"ATTACK GRAPH    {self.target}",
            color="#00E5FF", fontsize=13, fontweight="bold", fontfamily="monospace", pad=10)
        ax1.axis("off")

        #  Risk donut chart 
        ax2 = fig.add_subplot(gs[0, 2])
        ax2.set_facecolor("#080C18")
        risk_counts = self.data["risk_counts"]
        labels = [k for k,v in risk_counts.items() if v > 0]
        sizes2 = [v for v in risk_counts.values() if v > 0]
        pie_colors = {"CRITICAL":"#EF4444","HIGH":"#F59E0B","MEDIUM":"#EAB308","LOW":"#10B981"}
        colors2 = [pie_colors.get(l,"#64748B") for l in labels]
        if sizes2:
            wedges, texts, autotexts = ax2.pie(
                sizes2, labels=labels, colors=colors2, autopct="%1.0f%%",
                startangle=90, pctdistance=0.7, wedgeprops={"width":0.55,"edgecolor":"#080C18","linewidth":2})
            for t in texts: t.set_color("#94A3B8"); t.set_fontsize(8)
            for at in autotexts: at.set_color("#fff"); at.set_fontsize(8); at.set_fontweight("bold")
        else:
            ax2.text(0.5, 0.5, "No vulns", ha="center", va="center", color="#64748B")
        ax2.set_title("Risk Distribution", color="#00E5FF", fontsize=10, fontweight="bold", pad=5)

        #  Service heatbar 
        ax3 = fig.add_subplot(gs[1, 2])
        ax3.set_facecolor("#080C18")
        port_data = self.data["port_states"]
        if port_data:
            svc_names  = list(port_data.keys())[:10]
            svc_counts = [port_data[s] for s in svc_names]
            # Exposure weight of the service type itself (not a CVSS score of any CVE).
            _exposure = {"telnet": 9.5, "rdp": 9.0, "smb": 9.0, "microsoft-ds": 9.0, "ftp": 8.5,
                         "vnc": 8.5, "mongodb": 7.5, "redis": 7.5, "mysql": 7.5, "mssql": 7.5,
                         "postgresql": 7.0, "snmp": 7.0, "ssh": 6.0, "http": 5.0,
                         "http-alt": 5.0, "https": 4.5, "smtp": 4.5, "dns": 4.5}
            risk_vals  = [_exposure.get(s.lower(), 3.0) for s in svc_names]
            bar_colors = [plt.cm.RdYlGn_r(v/10.0) for v in risk_vals]
            bars = ax3.barh(svc_names, svc_counts, color=bar_colors, alpha=0.85, height=0.6)
            ax3.set_facecolor("#080C18")
            ax3.tick_params(colors="#94A3B8", labelsize=7)
            ax3.spines[:].set_color("#1E293B")
            ax3.set_xlabel("Count", color="#64748B", fontsize=7)
            for bar, rv in zip(bars, risk_vals):
                ax3.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height()/2,
                         f"exposure:{rv}", va="center", color="#94A3B8", fontsize=6)
        else:
            ax3.text(0.5, 0.5, "No services", ha="center", va="center", color="#64748B", transform=ax3.transAxes)
        ax3.set_title("Service Risk Heatmap", color="#00E5FF", fontsize=10, fontweight="bold", pad=5)

        fig.text(
            0.5,
            0.01,
            f"DanishRecon  |  Start {self.data.get('started_at', self.data['timestamp'])}  |  End {self.data.get('ended_at', 'In progress') or 'In progress'}",
            ha="center", color="#334155", fontsize=8, fontfamily="monospace")

        graph_path = os.path.join(RESULTS_DIR, "attack_graph_v3.png")
        plt.savefig(graph_path, dpi=150, bbox_inches="tight", facecolor="#080C18")
        plt.close()
        self.log(f"  Attack graph  {graph_path}", "good")
        return graph_path

    def _generate_gemini_html_section(self):
        """Generate HTML section for Gemini AI analyses"""
        if not self.data.get("gemini_analyses"):
            return '<p style="color:var(--text2)">No AI analysis available (Gemini not enabled)</p>'
        
        analyses = self.data["gemini_analyses"]
        html_parts = []
        
        # Ensure analyses is a dict
        if not isinstance(analyses, dict):
            return '<p style="color:var(--text2)">AI analysis data format error</p>'
        
        # Executive summary if available
        if "executive_summary" in analyses:
            summary = analyses["executive_summary"]
            html_parts.append(f'''
            <div style="background:rgba(0,229,255,.05);border-left:3px solid var(--cyan);padding:16px;margin-bottom:20px;border-radius:4px;">
              <h3 style="color:var(--cyan);font-size:12px;margin-bottom:10px;">EXECUTIVE SUMMARY (AI-POWERED)</h3>
              <p style="color:#CBD5E1;font-size:13px;line-height:1.8;white-space:pre-wrap;">{esc(summary)}</p>
            </div>
            ''')
        
        # Individual vulnerability analyses
        for vuln_id, analysis in analyses.items():
            if vuln_id == "executive_summary":
                continue
            html_parts.append(f'''
            <div style="background:rgba(139,92,246,.05);border-left:3px solid var(--purple);padding:14px;margin-bottom:12px;border-radius:4px;">
              <h4 style="color:var(--purple);font-size:11px;margin-bottom:8px;letter-spacing:1px;">VULNERABILITY: {esc(str(vuln_id).upper())}</h4>
              <p style="color:#CBD5E1;font-size:12px;line-height:1.7;white-space:pre-wrap;">{esc(analysis)}</p>
            </div>
            ''')
        
        return "\n".join(html_parts) if html_parts else '<p style="color:var(--text2)">Analysis in progress...</p>'

    #  HTML Report 
    def stage_report(self, graph_path: str):
        self.current_stage = "report"
        self.log(" STAGE 11: GENERATING PENTEST REPORT ", "stage")

        generated_at = datetime.now()
        self._sync_timing_data(ended_at=self.ended_at, generated_at=generated_at)

        ts  = self.data["timestamp"]
        tgt = esc(self.data["target"])
        started_at = self.data.get("started_at", ts)
        ended_at = self.data.get("ended_at", "") or "In progress"
        generated_at_str = self.data.get("generated_at", self._format_dt(generated_at))
        duration = self.data.get("duration", "00:00:00")
        rc  = self.data["risk_counts"]
        public_api_count = int(self.data.get("api_count", 0) or 0)
        auth_api_count = int(self.data.get("auth_api_count", 0) or 0)
        evidence_count = len(self.data.get("evidence", []))
        total_risk = rc.get("CRITICAL",0)+rc.get("HIGH",0)+rc.get("MEDIUM",0)+rc.get("LOW",0)
        risk_score = min(10.0, round(
            (rc.get("CRITICAL",0)*10 + rc.get("HIGH",0)*7 + rc.get("MEDIUM",0)*4 + rc.get("LOW",0)*2)
            / max(total_risk,1), 1))

        def ul(items, empty="<li>None found</li>"):
            return "".join(f"<li>{esc(i)}</li>" for i in items) if items else empty

        def risk_badge(text):
            text = esc(text)  # scan-derived text is never trusted as HTML
            if "CRITICAL" in text: cls="crit"
            elif "HIGH"    in text: cls="high"
            elif "MEDIUM"  in text: cls="med"
            else: cls="low"
            
            # Handle both "[RISK] text" and plain text formats
            if "]" in text:
                badge = text.split("]")[0].replace("[","")
                desc = text.split("]", 1)[-1].strip()
            else:
                # For plain text without [RISK], try to extract risk from content
                if "CRITICAL" in text:
                    badge = "CRITICAL"
                elif "HIGH" in text:
                    badge = "HIGH"
                elif "MEDIUM" in text:
                    badge = "MEDIUM"
                else:
                    badge = "LOW"
                desc = text.replace(badge, "").strip()
            
            return f'<span class="badge {cls}">{badge}</span> {desc if desc else "—"}'

        vuln_rows = "\n".join(
            f'<tr><td class="risk-cell">{risk_badge(v)}</td></tr>'
            for v in self.data["vulnerabilities"]
        )

        img_tag = ""
        if os.path.exists(graph_path):
            with open(graph_path,"rb") as f:
                b64 = base64.b64encode(f.read()).decode()
            img_tag = f'<img src="data:image/png;base64,{b64}" style="width:100%;border-radius:8px;">'

        mitre_rows = "\n".join(
            f'<tr><td style="color:#8B5CF6">{esc(m["id"])}</td><td>{esc(m["tactic"])}</td><td>{esc(m["tech"])}</td><td style="color:#94A3B8">{esc(m["service"])}</td></tr>'
            for m in self.data["mitre_techniques"]
        ) or '<tr><td colspan="4" style="color:#64748B">None detected</td></tr>'

        compliance_rows = "\n".join(f'<li>{esc(c)}</li>' for c in self.data["compliance"])
        
        secret_findings_rows = "\n".join(
            f"<li style=\"padding:6px 8px;\">{esc(s)}</li>"
            for s in self.data.get("secret_findings", [])[:25]
        ) or '<li style="color:var(--text2);">• No secret patterns detected</li>'
        
        evidence_rows = "\n".join(
            f"<tr><td>{esc(e.get('type',''))}</td><td>{esc(e.get('title',''))}</td><td>{esc(e.get('source_url',''))}</td><td>{esc(e.get('status_code',''))}</td><td>{esc(e.get('method',''))}</td><td>{esc(e.get('surface',''))}</td><td>{esc(e.get('timestamp',''))}</td></tr>"
            for e in self.data.get("evidence", [])[:150]
        ) or '<tr><td colspan="7" style="color:var(--text2)">No evidence records</td></tr>'
        
        # Format crypto analysis for HTML
        crypto_analysis_rows = ""
        crypto_data = self.data.get('crypto_analysis', {})
        if crypto_data:
            if isinstance(crypto_data, dict):
                for port, analysis in crypto_data.items():
                    if not isinstance(analysis, dict):
                        continue
                    grade = analysis.get('overall_rating', {}).get('grade', 'N/A')
                    score = analysis.get('overall_rating', {}).get('score', 0)
                    crypto_analysis_rows += f"<li><strong>Port {esc(port)}: TLS Grade {esc(grade)} ({esc(score)}/100, indicative)</strong></li>"
                    
                    # TLS versions
                    tls_versions = analysis.get('tls_versions', {})
                    if isinstance(tls_versions, dict):
                        for version, info in tls_versions.items():
                            if isinstance(info, dict) and info.get('supported'):
                                status = "✅" if not info.get('deprecated') else "⚠️"
                                crypto_analysis_rows += f"<li>{status} {esc(version)} supported</li>"
                    
                    # Vulnerabilities
                    vulns = analysis.get('vulnerabilities', [])
                    if vulns and isinstance(vulns, list):
                        for vuln in vulns:
                            if isinstance(vuln, dict):
                                risk = vuln.get('risk', 'MEDIUM')
                                color = "#FF6B6B" if risk == 'CRITICAL' else "#FF9B9B" if risk == 'HIGH' else "#FFD700"
                                crypto_analysis_rows += f"<li style=\"color:{color}\"><strong>[{esc(risk)}]</strong> {esc(vuln.get('type', 'Unknown'))}</li>"
            elif isinstance(crypto_data, list):
                for item in crypto_data:
                    if isinstance(item, dict):
                        crypto_analysis_rows += f"<li>{esc(item)}</li>"
                    else:
                        crypto_analysis_rows += f"<li>{esc(item)}</li>"
        
        crypto_section = f"<ul>{crypto_analysis_rows}</ul>" if crypto_analysis_rows else '<ul><li style="color:var(--text2)">No cryptography analysis data available</li></ul>'
        
        # Format recommendations for HTML
        recommendations_rows = ""
        recommendations = self.data.get('recommendations', {})
        
        if isinstance(recommendations, dict):
            # Recommendation engine format (has 'recommendations' key)
            recs_list = recommendations.get('recommendations', [])
            for rec in recs_list[:20]:
                vuln_title = rec.get('vulnerability', 'Unknown')
                severity = rec.get('severity', 'MEDIUM')
                color = "#FF6B6B" if severity == 'CRITICAL' else "#FF9B9B" if severity == 'HIGH' else "#FFD700"
                recommendations_rows += f"<li style=\"color:{color}\"><strong>[{esc(severity)}]</strong> {esc(vuln_title)}</li>"
        elif isinstance(recommendations, list):
            # Stage recommendations format (simple list of strings)
            for rec in recommendations[:20]:
                if isinstance(rec, str):
                    recommendations_rows += f"<li>{esc(rec)}</li>"
                elif isinstance(rec, dict):
                    vuln_title = rec.get('vulnerability', str(rec))
                    severity = rec.get('severity', 'MEDIUM')
                    color = "#FF6B6B" if severity == 'CRITICAL' else "#FF9B9B" if severity == 'HIGH' else "#FFD700"
                    recommendations_rows += f"<li style=\"color:{color}\"><strong>[{esc(severity)}]</strong> {esc(vuln_title)}</li>"
        
        recommendations_section = f"<ul>{recommendations_rows}</ul>" if recommendations_rows else '<ul><li style="color:var(--text2)">No specific recommendations generated</li></ul>'
        
        # Format compliance mapping for HTML
        compliance_recs = self.data.get('compliance_recommendations', {})
        compliance_findings = ""
        if compliance_recs:
            if isinstance(compliance_recs, dict):
                for framework, details in compliance_recs.items():
                    status = details.get('status', 'Not evaluated') if isinstance(details, dict) else str(details)
                    compliance_findings += f"<li><strong>{esc(framework)}:</strong> {esc(status)}</li>"
            elif isinstance(compliance_recs, list):
                for item in compliance_recs:
                    if isinstance(item, dict):
                        framework = item.get('framework', 'Unknown')
                        status = item.get('status', 'Not evaluated')
                        compliance_findings += f"<li><strong>{esc(framework)}:</strong> {esc(status)}</li>"
                    else:
                        compliance_findings += f"<li>{esc(item)}</li>"
        
        compliance_section = f"<ul>{compliance_findings}</ul>" if compliance_findings else '<ul><li style="color:var(--text2)">No compliance mapping available</li></ul>'
        
        # Generated configs list
        generated_configs = ""
        recommendations = self.data.get('recommendations', {})
        
        # Handle both list and dict formats for recommendations
        has_recommendations = False
        if isinstance(recommendations, dict):
            has_recommendations = bool(recommendations.get('recommendations'))
        elif isinstance(recommendations, list):
            has_recommendations = bool(recommendations)
        
        if has_recommendations:
            generated_configs = "<ul>"
            generated_configs += f"<li>✅ hardened_nginx_{self.scan_id}.conf - Ready for deployment</li>"
            generated_configs += f"<li>✅ hardened_apache_{self.scan_id}.conf - Ready for deployment</li>"
            generated_configs += f"<li>✅ waf_rules_{self.scan_id}.txt - ModSecurity compatible</li>"
            generated_configs += "</ul>"
        else:
            generated_configs = '<ul><li style="color:var(--text2)">No hardened configs generated</li></ul>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DanishRecon  Pentest Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
:root{{
  --bg:#080C18;--panel:#0C1220;--card:#111827;
  --cyan:#00E5FF;--green:#10B981;--red:#EF4444;
  --orange:#F59E0B;--purple:#8B5CF6;--blue:#3B82F6;
  --text:#F1F5F9;--text2:#94A3B8;--border:#1E293B;
}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:var(--bg);color:var(--text);font-family:'Space Grotesk',sans-serif;font-size:14px;line-height:1.7;}}
a{{color:var(--cyan);text-decoration:none;}}
.hero{{
  background:linear-gradient(135deg,#0C1220 0%,#080C18 50%,#0D0A1F 100%);
  padding:56px 64px 48px;border-bottom:1px solid var(--border);position:relative;overflow:hidden;
}}
.hero::before{{
  content:'';position:absolute;top:-20%;right:-10%;width:50%;height:150%;
  background:radial-gradient(ellipse,rgba(0,229,255,.05) 0%,transparent 65%);
}}
.hero::after{{
  content:'';position:absolute;bottom:-30%;left:5%;width:40%;height:120%;
  background:radial-gradient(ellipse,rgba(139,92,246,.04) 0%,transparent 65%);
}}
.badge-hero{{display:inline-flex;align-items:center;gap:8px;
  background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.25);
  color:var(--cyan);font-family:'JetBrains Mono',monospace;font-size:11px;
  letter-spacing:3px;padding:5px 14px;border-radius:4px;margin-bottom:20px;}}
h1{{font-size:44px;font-weight:700;letter-spacing:-0.5px;color:#fff;}}
h1 em{{color:var(--cyan);font-style:normal;}}
.hero-meta{{color:var(--text2);font-family:'JetBrains Mono',monospace;font-size:11px;
  margin-top:14px;letter-spacing:1px;display:flex;gap:24px;flex-wrap:wrap;}}
.hero-meta strong{{color:var(--cyan);}}
.stats{{display:flex;gap:20px;margin-top:36px;flex-wrap:wrap;}}
.stat{{
  background:rgba(255,255,255,.02);border:1px solid var(--border);
  border-radius:10px;padding:18px 26px;text-align:center;
  position:relative;overflow:hidden;min-width:110px;
}}
.stat::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;}}
.stat.s-crit::before{{background:var(--red);}}
.stat.s-high::before{{background:var(--orange);}}
.stat.s-med::before{{background:#EAB308;}}
.stat.s-low::before{{background:var(--green);}}
.stat.s-blue::before{{background:var(--blue);}}
.stat .num{{font-size:34px;font-weight:700;font-family:'JetBrains Mono',monospace;}}
.stat.s-crit .num{{color:var(--red);}}
.stat.s-high .num{{color:var(--orange);}}
.stat.s-med  .num{{color:#EAB308;}}
.stat.s-low  .num{{color:var(--green);}}
.stat.s-blue .num{{color:var(--cyan);}}
.stat .lbl{{font-size:10px;color:var(--text2);letter-spacing:2px;margin-top:3px;font-weight:600;}}
.risk-score{{
  display:inline-flex;align-items:center;gap:12px;
  background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.3);
  border-radius:8px;padding:12px 20px;margin-top:24px;
}}
.risk-score .score-num{{font-size:28px;font-weight:700;color:var(--red);font-family:'JetBrains Mono',monospace;}}
.risk-score .score-lbl{{color:var(--text2);font-size:12px;}}
main{{max-width:1100px;margin:0 auto;padding:48px 64px;}}
section{{margin-bottom:52px;}}
h2{{
  font-size:13px;font-weight:700;letter-spacing:3px;text-transform:uppercase;
  color:var(--cyan);border-bottom:1px solid var(--border);
  padding-bottom:10px;margin-bottom:22px;font-family:'JetBrains Mono',monospace;
  display:flex;align-items:center;gap:10px;
}}
h2 .sec-num{{
  background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.2);
  color:var(--cyan);font-size:10px;padding:2px 8px;border-radius:3px;
}}
.card{{
  background:var(--card);border:1px solid var(--border);
  border-radius:10px;padding:22px 26px;margin-bottom:14px;
}}
.exec-card{{
  background:linear-gradient(135deg,#0C1220,#0D0A1F);
  border:1px solid var(--border);border-radius:10px;padding:28px 32px;
}}
.exec-card p{{color:#CBD5E1;font-size:14px;line-height:1.9;margin-bottom:14px;}}
ul{{list-style:none;padding:0;}}
ul li{{
  padding:8px 12px;border-bottom:1px solid var(--border);
  font-size:13px;color:var(--text);font-family:'JetBrains Mono',monospace;
}}
ul li::before{{content:" ";color:var(--cyan);}}
ul li:last-child{{border-bottom:none;}}
.badge{{
  display:inline-block;padding:4px 10px;border-radius:4px;
  font-size:11px;font-weight:700;font-family:'JetBrains Mono',monospace;
  margin-right:8px;white-space:nowrap;
}}
.badge.crit{{background:rgba(239,68,68,.15);color:#EF4444;border:1px solid rgba(239,68,68,.3);}}
.badge.high{{background:rgba(245,158,11,.15);color:#F59E0B;border:1px solid rgba(245,158,11,.3);}}
.badge.med {{background:rgba(234,179,8,.15);color:#EAB308;border:1px solid rgba(234,179,8,.3);}}
.badge.low {{background:rgba(16,185,129,.15);color:#10B981;border:1px solid rgba(16,185,129,.3);}}
table{{width:100%;border-collapse:collapse;}}
td,th{{padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;text-align:left;}}
th{{color:var(--cyan);font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:1.5px;background:var(--panel);}}
.risk-cell{{font-family:'JetBrains Mono',monospace;font-size:12px;}}
.mitre-table td:first-child{{color:var(--purple);font-weight:600;}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:16px;}}
@media(max-width:768px){{.two-col{{grid-template-columns:1fr;}}.hero{{padding:32px 24px;}}.stats{{gap:12px;}}main{{padding:32px 24px;}}}}
footer{{
  text-align:center;padding:28px;color:var(--text2);
  font-family:'JetBrains Mono',monospace;font-size:10px;
  border-top:1px solid var(--border);letter-spacing:1px;
}}
</style>
</head>
<body>
<div class="hero">
  <div class="badge-hero"> CONFIDENTIAL // PENTEST REPORT</div>
  <h1>Danish<em>Recon</em></h1>
  <div class="hero-meta">
    <span>TARGET: <strong>{tgt}</strong></span>
        <span>STARTED: <strong>{started_at}</strong></span>
        <span>ENDED: <strong>{ended_at}</strong></span>
        <span>DURATION: <strong>{duration}</strong></span>
    <span>PROFILE: <strong>{esc(self.profile)}</strong></span>
    <span>SCAN-ID: <strong>#{self.scan_id}</strong></span>
  </div>
  <div class="stats">
    <div class="stat s-blue"><div class="num">{len(self.data['hosts'])}</div><div class="lbl">HOSTS</div></div>
    <div class="stat s-blue"><div class="num">{len(self.data['services'])}</div><div class="lbl">SERVICES</div></div>
        <div class="stat s-blue"><div class="num">{public_api_count}</div><div class="lbl">API (PUBLIC)</div></div>
        <div class="stat s-blue"><div class="num">{auth_api_count}</div><div class="lbl">API (AUTH)</div></div>
        <div class="stat s-blue"><div class="num">{evidence_count}</div><div class="lbl">EVIDENCE</div></div>
    <div class="stat s-crit"><div class="num">{rc.get('CRITICAL',0)}</div><div class="lbl">CRITICAL</div></div>
    <div class="stat s-high"><div class="num">{rc.get('HIGH',0)}</div><div class="lbl">HIGH</div></div>
    <div class="stat s-med"><div class="num">{rc.get('MEDIUM',0)}</div><div class="lbl">MEDIUM</div></div>
    <div class="stat s-low"><div class="num">{rc.get('LOW',0)}</div><div class="lbl">LOW</div></div>
    <div class="stat s-blue"><div class="num">{len(self.data['exploits'])}</div><div class="lbl">EXPLOITS</div></div>
    <div class="stat s-blue"><div class="num">{len(self.data['attack_paths'])}</div><div class="lbl">ATTACK PATHS</div></div>
  </div>
  <div class="risk-score">
    <div class="score-num">{risk_score}/10</div>
    <div class="score-lbl">OVERALL RISK SCORE<br><span style="font-size:10px;color:#EF4444;">{'CRITICAL' if risk_score>=8 else 'HIGH' if risk_score>=6 else 'MEDIUM' if risk_score>=4 else 'LOW'}</span></div>
  </div>
</div>

<main>
<section>
  <h2><span class="sec-num">01</span> EXECUTIVE SUMMARY</h2>
  <div class="exec-card">
    <p>This report presents findings of an automated reconnaissance and vulnerability assessment
        conducted against <strong style="color:var(--cyan)">{tgt}</strong> starting at {started_at} and ending at {ended_at} using DanishRecon
    with the <strong>{esc(self.profile)}</strong> scan profile.</p>
    <p>The assessment identified <strong style="color:var(--red)">{len(self.data['vulnerabilities'])} vulnerabilities</strong>
    across {len(self.data['services'])} exposed services on {len(self.data['hosts'])} live hosts.
    The overall risk score is <strong style="color:var(--red)">{risk_score}/10</strong>.
    {rc.get('CRITICAL',0)} CRITICAL and {rc.get('HIGH',0)} HIGH severity findings require immediate remediation.</p>
        <p>Scan timing: <strong style="color:var(--cyan)">Start</strong> {started_at}  |  <strong style="color:var(--cyan)">End</strong> {ended_at}  |  <strong style="color:var(--cyan)">Duration</strong> {duration}. Report generated at {generated_at_str}.</p>
    <p>Exploit references are mapped to CVE identifiers, CVSS scores, and MITRE ATT&CK techniques.
    Compliance gaps identified against PCI-DSS, HIPAA, NIST SP 800-53, and CIS Controls are documented below.</p>
  </div>
</section>

<section>
  <h2><span class="sec-num">02</span> INFRASTRUCTURE DISCOVERY</h2>
  <div class="two-col">
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">HOSTS DISCOVERED</h3>
    <ul>{ul(self.data['hosts'])}</ul></div>
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">OS FINGERPRINTS</h3>
    <ul>{ul(self.data['os_guesses'])}</ul></div>
  </div>
  <div class="two-col">
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">DNS RECORDS</h3>
    <ul>{ul(self.data['dns_records'])}</ul></div>
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">SSL/TLS ISSUES</h3>
    <ul>{ul(self.data['ssl_issues'])}</ul></div>
  </div>
</section>

<section>
  <h2><span class="sec-num">03</span> SERVICES & VERSIONS</h2>
  <div class="two-col">
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">OPEN SERVICES</h3>
    <ul>{ul(self.data['services'])}</ul></div>
    <div class="card"><h3 style="color:var(--cyan);font-size:11px;letter-spacing:1px;margin-bottom:12px;">VERSIONS</h3>
    <ul>{ul(self.data['versions'])}</ul></div>
  </div>
</section>

<section>
  <h2><span class="sec-num">03B</span> CRYPTOGRAPHY ANALYSIS (TLS/SSL)</h2>
  <div class="card">
    {crypto_section}
  </div>
</section>

<section>
    <h2><span class="sec-num">03C</span> STAGE 6.5 - API SURFACE DISCOVERY</h2>
    <div class="card">
        <ul>
            <li>Public API endpoints found: {public_api_count}</li>
            <li>Authenticated API endpoints found: {auth_api_count}</li>
            <li>Evidence records captured: {evidence_count}</li>
        </ul>
    </div>
</section>

<section>
  <h2><span class="sec-num">04</span> RANKED VULNERABILITIES</h2>
  <div class="card">
    <table><tbody>{vuln_rows or '<tr><td style="color:var(--text2)">No vulnerabilities found</td></tr>'}</tbody></table>
  </div>
</section>

<section>
  <h2><span class="sec-num">04A</span> AI-POWERED VULNERABILITY ANALYSIS</h2>
  <div class="card">
    {self._generate_gemini_html_section()}
  </div>
</section>

<section>
  <h2><span class="sec-num">05</span> MITRE ATT&CK MAPPING</h2>
  <div class="card">
    <table class="mitre-table">
      <thead><tr><th>TECHNIQUE ID</th><th>TACTIC</th><th>TECHNIQUE</th><th>SERVICE</th></tr></thead>
      <tbody>{mitre_rows}</tbody>
    </table>
  </div>
</section>

<section>
  <h2><span class="sec-num">06</span> EXPLOIT REFERENCES</h2>
  <div class="card"><ul>{ul(self.data['exploits'])}</ul></div>
</section>

<section>
  <h2><span class="sec-num">07</span> POTENTIAL ATTACK PATHS</h2>
  <div class="card"><p style="color:var(--text2);font-size:12px;margin-bottom:10px;">Hypothetical scenarios generated from the exposed service types. They illustrate what to review and were not tested or confirmed.</p><ul>{ul(self.data['attack_paths'])}</ul></div>
</section>

<section>
  <h2><span class="sec-num">08</span> COMPLIANCE STATUS</h2>
  <div class="card"><ul>{compliance_rows or '<li style="color:var(--text2)">No compliance data generated</li>'}</ul></div>
</section>

<section>
  <h2><span class="sec-num">09</span> SECURITY RECOMMENDATIONS</h2>
  <div class="card">{recommendations_section}</div>
</section>

<section>
  <h2><span class="sec-num">09A</span> GENERATED HARDENED CONFIGURATIONS</h2>
  <div class="card">
    <p style="color:var(--cyan);font-size:12px;margin-bottom:12px;"><strong>⚡ Auto-Generated Secure Configs (Ready to Deploy)</strong></p>
    {generated_configs}
  </div>
</section>

<section>
  <h2><span class="sec-num">09B</span> COMPLIANCE FRAMEWORK MAPPING</h2>
  <div class="card">
    <p style="color:var(--cyan);font-size:12px;margin-bottom:12px;"><strong>✅ Security Standards Alignment</strong></p>
    {compliance_section}
  </div>
</section>

<section>
  <h2><span class="sec-num">10</span> NETWORK ATTACK GRAPH</h2>
  <div class="card">{img_tag or '<p style="color:var(--text2)">Graph not generated</p>'}</div>
</section>

<section>
    <h2><span class="sec-num">12</span> STAGE 6.6 - SECRET SCANNING & EVIDENCE</h2>
    <div class="card">
        <h3 style="color:var(--cyan);font-size:12px;letter-spacing:1px;margin-bottom:12px;">SECRET FINDINGS DETECTED: {len(self.data.get('secret_findings', []))}</h3>
        <ul>
            {secret_findings_rows}
        </ul>
        <hr style="border:none;border-top:1px solid var(--border);margin:16px 0;">
        <h3 style="color:var(--cyan);font-size:12px;letter-spacing:1px;margin-bottom:12px;">EVIDENCE RECORDS: {len(self.data.get('evidence', []))}</h3>
        <table style="width:100%;font-size:12px;">
            <thead><tr><th style="text-align:left;padding:6px;">TYPE</th><th style="text-align:left;padding:6px;">TITLE</th><th style="text-align:left;padding:6px;">SOURCE URL</th><th style="text-align:left;padding:6px;">STATUS</th><th style="text-align:left;padding:6px;">METHOD</th><th style="text-align:left;padding:6px;">SURFACE</th><th style="text-align:left;padding:6px;">TIMESTAMP</th></tr></thead>
            <tbody>{evidence_rows}</tbody>
        </table>
    </div>
</section>
</main>

<footer>DanishRecon &nbsp;|&nbsp; SCAN #{self.scan_id} &nbsp;|&nbsp; START {started_at} &nbsp;|&nbsp; END {ended_at} &nbsp;|&nbsp; GENERATED {generated_at_str}
&nbsp;|&nbsp; FOR AUTHORIZED PENETRATION TESTING ONLY &nbsp;|&nbsp; DO NOT DISTRIBUTE</footer>
</body></html>"""

        report_path = os.path.join(RESULTS_DIR, f"report_{self.scan_id}.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        # Keep a latest-report alias for UI flows that still expect report_v3.html.
        latest_report_path = os.path.join(RESULTS_DIR, "report_v3.html")
        if os.path.abspath(latest_report_path) != os.path.abspath(report_path):
            with open(latest_report_path, "w", encoding="utf-8") as f:
                f.write(html)
        self.log(f"  HTML report  {report_path}", "good")
        return report_path

    #  Export helpers 
    def export_json(self):
        path = os.path.join(RESULTS_DIR, f"scan_{self.scan_id}.json")
        with open(path,"w",encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        return path

    def export_csv(self):
        path = os.path.join(RESULTS_DIR, f"vulns_{self.scan_id}.csv")
        rows = DB.get_scan_vulns(self.scan_id)
        with open(path,"w",newline="",encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id","scan_id","host","service","port","risk","cve","cvss","title","mitre","technique","compliance"])
            w.writerows(rows)
        return path

    def export_markdown(self):
        d = self.data
        self._sync_timing_data(ended_at=self.ended_at)
        lines = [
            f"# DanishRecon  Pentest Report",
            f"**Target:** {d['target']}  **Started:** {d['started_at']}  **Ended:** {d['ended_at'] or 'In progress'}  **Duration:** {d['duration']}  **Profile:** {d['profile']}",
            f"**Report Generated:** {d['generated_at']}",
            "", "---", "",
            "## Executive Summary",
            f"- Hosts: {len(d['hosts'])}  Services: {len(d['services'])}  Vulns: {len(d['vulnerabilities'])}",
            f"- API Endpoints (Public): {d.get('api_count', 0)}",
            f"- API Endpoints (Authenticated): {d.get('auth_api_count', 0)}",
            f"- Evidence Records: {len(d.get('evidence', []))}",
            f"- Secret Findings (Stage 6.6): {len(d.get('secret_findings', []))}",
            "", "## Vulnerabilities",
        ]
        lines += ["", "## Stage 6.5 - API Surface Discovery"]
        lines.append(f"- Public endpoints found: {d.get('api_count', 0)}")
        lines.append(f"- Authenticated endpoints found: {d.get('auth_api_count', 0)}")
        if d.get("api_endpoints"):
            lines.append("- Public endpoint samples:")
            for ep in d.get("api_endpoints", [])[:20]:
                lines.append(f"  - {ep.get('url','')}")
        else:
            lines.append("- Public endpoint samples: None")
        if d.get("auth_api_endpoints"):
            lines.append("- Auth endpoint samples:")
            for ep in d.get("auth_api_endpoints", [])[:20]:
                lines.append(f"  - {ep.get('url','')}")
        else:
            lines.append("- Auth endpoint samples: None")

        lines += ["", "## Stage 6.6 - Secret Scanning"]
        if d.get("secret_findings"):
            for s in d.get("secret_findings", [])[:50]:
                lines.append(f"- {s}")
        else:
            lines.append("- No secret patterns detected")
        for v in d["vulnerabilities"]:
            lines.append(f"- {v}")
        lines += ["", "## Attack Paths"]
        for p in d["attack_paths"]:
            lines.append(f"- {p}")
        lines += ["", "## Recommendations"]
        recommendations = d.get("recommendations", [])
        if isinstance(recommendations, dict):
            # Handle recommendation engine format (dict with 'recommendations' key)
            recs_list = recommendations.get('recommendations', [])
            for r in recs_list:
                vuln = r.get('vulnerability', str(r))
                severity = r.get('severity', '')
                fix = r.get('fix', '')
                lines.append(f"- [{severity}] {vuln}: {fix}")
        elif isinstance(recommendations, list):
            # Handle stage_recommendations format (simple list)
            for r in recommendations:
                if isinstance(r, dict):
                    lines.append(f"- {r.get('vulnerability', str(r))}")
                else:
                    lines.append(f"- {r}")
        lines += ["", "## Evidence Collector"]
        for e in d.get("evidence", [])[:100]:
            lines.append(
                f"- [{e.get('type','')}] {e.get('title','')} | url={e.get('source_url','')} | "
                f"status={e.get('status_code','')} | method={e.get('method','')} | surface={e.get('surface','')} | ts={e.get('timestamp','')}"
            )
        path = os.path.join(RESULTS_DIR, f"report_{self.scan_id}.md")
        with open(path,"w",encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path
    
    def export_pdf(self):
        """Generate professional PDF report with executive summary, findings, charts, and remediation"""
        if not REPORTLAB_AVAILABLE:
            msg = " ReportLab not installed. Install with: pip install reportlab"
            print(msg)
            self.log(msg, "error")
            return None
        
        print(" Starting PDF export...")
        
        d = self.data
        self._sync_timing_data(ended_at=self.ended_at)
        path = os.path.join(RESULTS_DIR, f"report_{self.scan_id}.pdf")
        
        # Create PDF document
        doc = SimpleDocTemplate(path, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Define styles
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='CustomTitle',
                                  parent=styles['Heading1'],
                                  fontSize=24,
                                  textColor=colors.HexColor('#00E5FF'),
                                  spaceAfter=30,
                                  alignment=TA_CENTER))
        styles.add(ParagraphStyle(name='CustomHeading',
                                  parent=styles['Heading2'],
                                  fontSize=16,
                                  textColor=colors.HexColor('#00E5FF'),
                                  spaceAfter=12,
                                  spaceBefore=12))
        styles.add(ParagraphStyle(name='CriticalText',
                                  parent=styles['Normal'],
                                  fontSize=10,
                                  textColor=colors.red,
                                  leftIndent=20))
        styles.add(ParagraphStyle(name='HighText',
                                  parent=styles['Normal'],
                                  fontSize=10,
                                  textColor=colors.orange,
                                  leftIndent=20))
        
        # Title Page
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph("CYBERSECURITY PENETRATION TEST REPORT", styles['CustomTitle']))
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph(f"<b>Target:</b> {d['target']}", styles['Normal']))
        elements.append(Paragraph(f"<b>Scan Started:</b> {d['started_at']}", styles['Normal']))
        elements.append(Paragraph(f"<b>Scan Ended:</b> {d['ended_at'] or 'In progress'}", styles['Normal']))
        elements.append(Paragraph(f"<b>Duration:</b> {d['duration']}", styles['Normal']))
        elements.append(Paragraph(f"<b>Report Generated:</b> {d['generated_at']}", styles['Normal']))
        elements.append(Paragraph(f"<b>Scan Profile:</b> {d['profile']}", styles['Normal']))
        elements.append(Paragraph(f"<b>Scan ID:</b> #{self.scan_id}", styles['Normal']))
        elements.append(Spacer(1, 0.5*inch))
        elements.append(Paragraph("<i>Generated by DanishRecon</i>", styles['Normal']))
        elements.append(PageBreak())
        
        # Executive Summary
        elements.append(Paragraph("EXECUTIVE SUMMARY", styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        rc = d.get("risk_counts", {})
        summary_data = [
            ['Metric', 'Count'],
            ['Scan Started', d['started_at']],
            ['Scan Ended', d['ended_at'] or 'In progress'],
            ['Duration', d['duration']],
            ['Live Hosts', str(len(d['hosts']))],
            ['Services Detected', str(len(d['services']))],
            ['Vulnerabilities Found', str(len(d['vulnerabilities']))],
            ['Critical Findings', f"<font color='red'><b>{rc.get('CRITICAL', 0)}</b></font>"],
            ['High Findings', f"<font color='orange'><b>{rc.get('HIGH', 0)}</b></font>"],
            ['Medium Findings', str(rc.get('MEDIUM', 0))],
            ['Low Findings', str(rc.get('LOW', 0))],
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0C1220')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00E5FF')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#111827')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#334155')),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#111827'), colors.HexColor('#0F172A')]),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Risk Assessment
        risk_text = "<b>Overall Risk Assessment:</b> "
        if rc.get('CRITICAL', 0) > 0:
            risk_text += "<font color='red'><b>CRITICAL</b></font> - Immediate action required."
        elif rc.get('HIGH', 0) > 0:
            risk_text += "<font color='orange'><b>HIGH</b></font> - Urgent remediation needed."
        elif rc.get('MEDIUM', 0) > 0:
            risk_text += "<font color='yellow'><b>MEDIUM</b></font> - Address in near term."
        else:
            risk_text += "<font color='green'><b>LOW</b></font> - Maintain current security posture."
        elements.append(Paragraph(risk_text, styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        # CVSS Score Breakdown
        elements.append(Paragraph("CVSS SCORE BREAKDOWN", styles['CustomHeading']))
        cvss_data = [['Severity', 'Count', 'CVSS Range', 'Priority']]
        cvss_data.append(['Critical', str(rc.get('CRITICAL', 0)), '9.0 - 10.0', 'P0 - Immediate'])
        cvss_data.append(['High', str(rc.get('HIGH', 0)), '7.0 - 8.9', 'P1 - Urgent'])
        cvss_data.append(['Medium', str(rc.get('MEDIUM', 0)), '4.0 - 6.9', 'P2 - Normal'])
        cvss_data.append(['Low', str(rc.get('LOW', 0)), '0.1 - 3.9', 'P3 - Low'])
        
        cvss_table = Table(cvss_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 2*inch])
        cvss_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0C1220')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00E5FF')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (0, 1), colors.red),
            ('BACKGROUND', (0, 2), (0, 2), colors.orange),
            ('BACKGROUND', (0, 3), (0, 3), colors.yellow),
            ('BACKGROUND', (0, 4), (0, 4), colors.green),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#334155')),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
        ]))
        elements.append(cvss_table)
        elements.append(PageBreak())
        
        # Technical Findings - Hosts & Services
        elements.append(Paragraph("TECHNICAL FINDINGS", styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        elements.append(Paragraph("<b>Discovered Hosts</b>", styles['Heading3']))
        for host in d['hosts'][:10]:  # Limit to 10 for brevity
            elements.append(Paragraph(f" {host}", styles['Normal']))
        if len(d['hosts']) > 10:
            elements.append(Paragraph(f"<i>... and {len(d['hosts']) - 10} more</i>", styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        elements.append(Paragraph("<b>Open Services</b>", styles['Heading3']))
        for svc in d['services'][:15]:  # Limit to 15
            elements.append(Paragraph(f" {svc}", styles['Normal']))
        if len(d['services']) > 15:
            elements.append(Paragraph(f"<i>... and {len(d['services']) - 15} more</i>", styles['Normal']))
        elements.append(PageBreak())

        # Stage 6.5 API Surface Discovery (always present)
        elements.append(Paragraph("STAGE 6.5 - API SURFACE DISCOVERY", styles['CustomHeading']))
        elements.append(Paragraph(f"Public endpoints found: {d.get('api_count', 0)}", styles['Normal']))
        elements.append(Paragraph(f"Authenticated endpoints found: {d.get('auth_api_count', 0)}", styles['Normal']))
        api_sample = d.get('api_endpoints', [])[:12]
        if api_sample:
            for ep in api_sample:
                elements.append(Paragraph(f"• {ep.get('url', '')}", styles['Normal']))
        else:
            elements.append(Paragraph("• No public API endpoints recorded", styles['Normal']))
        auth_sample = d.get('auth_api_endpoints', [])[:12]
        if auth_sample:
            for ep in auth_sample:
                elements.append(Paragraph(f"• [AUTH] {ep.get('url', '')}", styles['Normal']))
        else:
            elements.append(Paragraph("• No authenticated API endpoints recorded", styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))

        # Stage 6.6 Secret Scanning (always present)
        elements.append(Paragraph("STAGE 6.6 - SECRET SCANNING", styles['CustomHeading']))
        secret_findings = d.get('secret_findings', [])
        elements.append(Paragraph(f"Secret findings detected: {len(secret_findings)}", styles['Normal']))
        if secret_findings:
            for finding in secret_findings[:100]:  # Show up to 100 secret findings
                elements.append(Paragraph(f"• {finding}", styles['Normal']))
        else:
            elements.append(Paragraph("• No secret patterns detected", styles['Normal']))
        elements.append(PageBreak())
        
        # Critical Vulnerabilities
        elements.append(Paragraph("CRITICAL VULNERABILITIES", styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        critical_vulns = [v for v in d['vulnerabilities'] if 'CRITICAL' in v]
        if critical_vulns:
            for vuln in critical_vulns[:20]:  # Top 20 critical
                elements.append(Paragraph(f" {vuln}", styles['CriticalText']))
        else:
            elements.append(Paragraph("No critical vulnerabilities detected.", styles['Normal']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        # High Vulnerabilities
        elements.append(Paragraph("HIGH SEVERITY VULNERABILITIES", styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        high_vulns = [v for v in d['vulnerabilities'] if 'HIGH' in v and 'CRITICAL' not in v]
        if high_vulns:
            for vuln in high_vulns[:20]:  # Top 20 high
                elements.append(Paragraph(f" {vuln}", styles['HighText']))
        else:
            elements.append(Paragraph("No high severity vulnerabilities detected.", styles['Normal']))
        
        elements.append(PageBreak())
        
        # Medium Vulnerabilities
        elements.append(Paragraph("MEDIUM SEVERITY VULNERABILITIES", styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        medium_vulns = [v for v in d['vulnerabilities'] if 'MEDIUM' in v and 'HIGH' not in v and 'CRITICAL' not in v]
        if medium_vulns:
            for vuln in medium_vulns[:20]:  # Top 20 medium
                elements.append(Paragraph(f" {vuln}", styles['Normal']))
        else:
            elements.append(Paragraph("No medium severity vulnerabilities detected.", styles['Normal']))
        
        elements.append(PageBreak())
        
        # Remediation Priorities
        elements.append(Paragraph("REMEDIATION PRIORITIES", styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        remediation_text = """
        <b>Priority 0 (Immediate - Within 24 Hours):</b><br/>
         Patch all CRITICAL vulnerabilities (CVSS >= 9.0)<br/>
         Disable insecure services (FTP, Telnet, SMB if unpatched)<br/>
         Update systems with known active exploits<br/>
        <br/>
        <b>Priority 1 (Urgent - Within 7 Days):</b><br/>
         Address all HIGH severity findings (CVSS 7.0-8.9)<br/>
         Implement SSL/TLS certificate updates<br/>
         Configure firewalls and WAF rules<br/>
        <br/>
        <b>Priority 2 (Normal - Within 30 Days):</b><br/>
         Remediate MEDIUM severity vulnerabilities<br/>
         Harden service configurations<br/>
         Update outdated software versions<br/>
        <br/>
        <b>Priority 3 (Low - Within 90 Days):</b><br/>
         Address LOW severity findings<br/>
         Implement security best practices<br/>
         Regular security scanning schedule<br/>
        """
        elements.append(Paragraph(remediation_text, styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Embed Attack Graph if available
        graph_path = d.get('graph_path', '')
        if graph_path and os.path.exists(graph_path):
            elements.append(PageBreak())
            elements.append(Paragraph("ATTACK GRAPH VISUALIZATION", styles['CustomHeading']))
            elements.append(Spacer(1, 0.2*inch))
            try:
                img = Image(graph_path, width=6*inch, height=4*inch)
                elements.append(img)
            except:
                elements.append(Paragraph("Graph image not available.", styles['Normal']))
        
        # Recommendations
        elements.append(PageBreak())
        elements.append(Paragraph("SECURITY RECOMMENDATIONS", styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        recommendations = d.get('recommendations', [])
        recommendations_to_show = []
        if isinstance(recommendations, dict):
            # Handle recommendation engine format
            recs_list = recommendations.get('recommendations', [])
            for r in recs_list[:10]:
                if isinstance(r, dict):
                    recommendations_to_show.append(f"{r.get('severity', '')}: {r.get('vulnerability', str(r))}")
                else:
                    recommendations_to_show.append(str(r))
        elif isinstance(recommendations, list):
            # Handle stage_recommendations format
            recommendations_to_show = [str(r) for r in recommendations[:10]]
        
        for rec in recommendations_to_show:
            elements.append(Paragraph(f" {rec}", styles['Normal']))
        
        # Footer
        elements.append(Spacer(1, 0.5*inch))
        elements.append(Paragraph("<i>End of Report</i>", styles['Normal']))
        elements.append(Paragraph(f"<i>Scan started at {d['started_at']} and ended at {d['ended_at'] or 'In progress'} (duration {d['duration']})</i>", styles['Normal']))
        elements.append(Paragraph(f"<i>Generated by DanishRecon on {d['generated_at']}</i>", styles['Normal']))
        
        # Build PDF
        try:
            doc.build(elements)
            success_msg = f" PDF report generated: {path}"
            print(success_msg)
            self.log(f"  PDF report generated: {path}", "good")
            return path
        except Exception as e:
            error_msg = f" PDF generation error: {e}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            self.log(f"  PDF generation error: {e}", "error")
            return None

    #  CRYPTOGRAPHY ANALYSIS 
    def stage_cryptography_analysis(self, services):
        """Analyze cryptographic configurations (TLS/SSL, ciphers, keys)"""
        if not CRYPTO_ANALYZER_AVAILABLE:
            self.log("  Cryptography analyzer not available (skipping)", "muted")
            return {}
        
        self.current_stage = "crypto"
        self.log(" CRYPTOGRAPHY ANALYSIS ", "stage")
        self.stage_signal.emit("Cryptography Analysis")
        self.prog("misc", 65)
        
        crypto_results = {}
        
        try:
            # Analyze HTTPS port if discovered
            if self.target:
                self.log(f"  Analyzing cryptography for {self.target}...", "info")
                analyzed = False
                
                # Extract ports from discovered services to check for HTTPS
                ports_to_check = [443, 8443]  # Fallback defaults
                https_keywords = ['https', 'ssl', 'tls', 'secure', 'cert']
                
                if services:
                    discovered_https_ports = []
                    self.log(f"  Found {len(services)} services to check for HTTPS...", "muted")
                    
                    for service in services:
                        try:
                            # Services can be dict or string format
                            if isinstance(service, dict):
                                port = service.get('port')
                                service_name = str(service.get('service', '')).lower()
                            else:
                                # Try to parse "port/proto service" format
                                parts = str(service).split()
                                if parts:
                                    port_proto = parts[0].split('/')
                                    port = int(port_proto[0]) if port_proto[0].isdigit() else None
                                    service_name = ' '.join(parts[1:]).lower() if len(parts) > 1 else ''
                                else:
                                    continue
                            
                            # Check if this is an HTTPS service
                            if port and any(kw in service_name for kw in https_keywords):
                                if port not in discovered_https_ports:
                                    discovered_https_ports.append(port)
                                    self.log(f"    Found HTTPS service on port {port}: {service_name[:50]}", "muted")
                        except:
                            continue
                    
                    # Use discovered HTTPS ports first, then fall back to defaults
                    if discovered_https_ports:
                        ports_to_check = discovered_https_ports + [p for p in ports_to_check if p not in discovered_https_ports]
                        self.log(f"  Will check these discovered HTTPS ports: {ports_to_check}", "info")
                    else:
                        self.log(f"  No HTTPS services discovered in port scan. Checking standard ports: {ports_to_check}", "muted")
                else:
                    self.log(f"  No services discovered. Checking standard HTTPS ports: {ports_to_check}", "muted")
                
                # Try to analyze each potential HTTPS port
                for port in ports_to_check:
                    try:
                        self.log(f"    Testing port {port}...", "muted")
                        analyzer = CryptographyAnalyzer(self.target, port)
                        result = analyzer.analyze()
                        
                        # Any port that completed a real TLS handshake is analysed - an
                        # invalid certificate is a finding, not a reason to skip the port.
                        if result and result.get('reachable'):
                            crypto_results[port] = result
                            analyzed = True
                            for _v in result.get('vulnerabilities', []):
                                # Certificate problems are already recorded by the SSL stage.
                                if _v.get('category') == 'protocol':
                                    self._record_finding(
                                        _v.get('risk', 'MEDIUM'),
                                        f"TLS: {_v.get('type')} on {self.target}:{port}",
                                        host=self.target, service="tls", port=port)
                            
                            # Display in GUI results panel
                            grade = result.get('overall_rating', {}).get('grade', 'N/A')
                            score = result.get('overall_rating', {}).get('score', 0)
                            self.result_signal.emit("Cryptography Analysis", 
                                                  f"TLS Grade: {grade} ({score}/100) on port {port}",
                                                  "#00E5FF")  # Cyan for crypto
                            
                            self.log(f"    ✅ TLS Grade: {grade} (port {port})", "good")
                            
                            # Show TLS versions
                            tls_versions = result.get('tls_versions', {})
                            if tls_versions:
                                for version, info in tls_versions.items():
                                    if info.get('supported'):
                                        status = "✅" if not info.get('deprecated') else "⚠️"
                                        self.result_signal.emit("TLS Versions", 
                                                              f"{status} {version} (port {port})",
                                                              "#00E5FF")
                            
                            # Log vulnerabilities found
                            vulns = result.get('vulnerabilities', [])
                            if vulns:
                                for vuln in vulns:
                                    risk = vuln.get('risk', 'MEDIUM')
                                    color = "#FF6B6B" if risk == 'CRITICAL' else "#FF9B9B" if risk == 'HIGH' else "#FFD700"
                                    self.result_signal.emit("Crypto Issues", 
                                                          f"{vuln.get('type', 'Unknown')} ({risk}) on port {port}",
                                                          color)
                            else:
                                self.result_signal.emit("Cryptography Analysis", 
                                                      f"✅ No critical cryptographic vulnerabilities (port {port})",
                                                      "#00E5FF")
                            break  # Stop after first successful port
                    except Exception as e:
                        error_msg = str(e)[:100]
                        self.log(f"    Port {port}: {error_msg}", "muted")
                        continue
                
                if not analyzed:
                    self.log(f"  ⚠️  Could not analyze cryptography (no HTTPS port accessible on {self.target})", "warn")
                    self.log(f"      Scanned ports: {ports_to_check}", "muted")
                    self.log(f"      Target may not have HTTPS enabled or may be unreachable", "muted")
                    # Nothing was analysed, so nothing is reported (the report shows
                    # "No cryptography analysis data available").
                    self.result_signal.emit("Cryptography Analysis",
                                          "⚠️ No TLS service reachable - cryptography not analysed",
                                          "#FFD700")
                
                # Store in data
                self.data['crypto_analysis'] = crypto_results
        except Exception as e:
            error_str = str(e)[:150]
            self.log(f"  Cryptography analysis error: {error_str}", "warn")
            # Still store empty data so HTML section shows
            self.data['crypto_analysis'] = {}
        
        return crypto_results

    # ─────────────────────────────────────────────────────────────────────────
    #  NUCLEI VULNERABILITY SCAN
    # ─────────────────────────────────────────────────────────────────────────
    # Category inferred from a nuclei template's id/tags, so template findings land in the
    # same structured-finding buckets as everything else.
    _NUCLEI_CATEGORY = [
        ("sqli", ("sqli", "sql-injection")), ("xss", ("xss", "cross-site-scripting")),
        ("ssti", ("ssti",)), ("lfi", ("lfi", "file-inclusion")), ("rfi", ("rfi",)),
        ("ssrf", ("ssrf",)), ("xxe", ("xxe",)), ("rce", ("rce", "code-injection", "command-injection")),
        ("cors", ("cors",)), ("redirect", ("redirect",)), ("takeover", ("takeover",)),
        ("exposed-panel", ("panel", "login", "dashboard")),
        ("exposure", ("exposure", "exposed", "disclosure", "listing", "backup", "config",
                      "logs", "file-upload", "swagger", "api-docs", "debug", "info-leak",
                      "metric", "prometheus", "git", "dir-listing", "directory-listing")),
        ("misconfig", ("misconfig", "misconfiguration", "default-login", "header")),
        ("cve", ("cve",)),
    ]

    @staticmethod
    def _nuclei_category(f):
        tid = (f.get("template_id") or "").lower()
        tags = [str(t).lower() for t in (f.get("tags") or [])]
        hay = tid + " " + " ".join(tags)
        for cat, needles in ScanEngine._NUCLEI_CATEGORY:
            if any(n in hay for n in needles):
                return cat
        return "misconfig"

    def stage_nuclei_scan(self, services):
        """Run the full nuclei template set against discovered web services.

        Unlike the DAST stage (which fuzzes parameters), this runs nuclei's own templates
        for misconfigurations, exposed panels/files, default logins and known CVEs. Every
        match becomes a structured Finding, so it reaches the report, dashboard, SARIF and
        the scan diff just like any other finding.
        """
        self.current_stage = "nuclei"
        self.log(" STAGE 6B: NUCLEI TEMPLATE SCAN ", "stage")
        self.stage_signal.emit("Nuclei Scan")
        self.prog("vuln", 20)

        if not RECON_TOOLS_AVAILABLE or not recon_tools.find_tool("nuclei"):
            self.log("  nuclei not found - template scan skipped (no findings generated)", "warn")
            self.prog("vuln", 25)
            return []

        # Roots FIRST: nuclei's exposure / misconfig templates probe well-known paths
        # (/metrics, /api-docs, /.git, admin panels, ...) against each base URL themselves,
        # so the base must be scanned early - if the template run times out, the base has
        # already been covered. A capped slice of crawled URLs follows for app-specific
        # templates. (Scanning every crawled URL against the full template set times out.)
        scope = self._scope_hosts()
        roots = self._web_base_urls(services)
        crawled = [u for u in self.data.get("crawled_urls", []) if recon_tools.in_scope(u, scope)]
        # Exposure/misconfig templates self-probe known paths against each base URL, so the
        # roots alone cover /metrics, /api-docs, /.git, panels, etc. Adding many crawled URLs
        # multiplies hosts-per-template and makes the run time out before it finishes, so keep
        # the crawled slice small (none on Quick); the Full profile casts a wider net.
        cap = {"Quick": 0, "Custom": 10, "Stealth": 10, "Full": 60}.get(self.profile, 10)
        urls, seen = [], set()
        for u in roots + crawled:
            base = u.split("?")[0]
            if u not in seen and (u in roots or base not in seen):
                seen.add(u)
                seen.add(base)
                urls.append(u)
            if len(urls) >= len(roots) + cap:
                break
        if not urls:
            self.log("  No web targets to scan with nuclei", "muted")
            self.prog("vuln", 25)
            return []

        severities = ["critical", "high", "medium"] + (["low", "info"] if self.profile == "Full" else [])
        budget = {"Quick": 600, "Stealth": 900, "Custom": 900, "Full": 1800}.get(self.profile, 900)
        rate = 10 if self.profile == "Stealth" else 50
        # The FULL template set (~9000 templates) times out long before the high-value
        # exposure/misconfig templates run. Target the categories that actually matter for a
        # web app (exposed files/panels/config, default logins, takeover, git/swagger/backup
        # leaks); known-CVE coverage comes from the NVD stage. 'Full' profile widens this.
        tags = ("exposure,exposures,misconfig,misconfiguration,exposed-panel,panel,default-login,"
                "config,logs,backup,swagger,git,debug,takeover,disclosure,listing")
        extra = [] if self.profile == "Full" else ["-tags", tags]
        self.log(f"  nuclei templates on {len(urls)} URL(s) "
                 f"({'full set' if self.profile == 'Full' else 'exposure/misconfig tags'}, "
                 f"severities: {', '.join(severities)}, budget {budget}s)", "info")

        r = recon_tools.nuclei_run(urls, dast=False, severities=severities, budget=budget, rate=rate,
                                   extra=extra, headers=self._auth_headers(), stop_check=lambda: self._stop)
        if not r["available"]:
            self.log("  nuclei not available - template scan skipped", "warn")
            self.prog("vuln", 25)
            return []
        if r["status"] in ("timeout", "error"):
            self.log(f"  nuclei template scan ended with status '{r['status']}' - results may be partial "
                     f"{r.get('stderr_tail', '')[-160:]}", "warn")

        added = 0
        for f in r["findings"]:
            self.data["nuclei_findings"].append(f)
            sev = f["severity"] if f["severity"] != "INFO" else "LOW"
            finding = Finding(
                title=f["name"], severity=sev, source="nuclei", confidence="confirmed",
                category=self._nuclei_category(f), host=recon_tools.host_of(f["matched_at"]) or f["host"],
                url=f["matched_at"], cve=f["cve"], cvss=f["cvss"], description=f["description"],
                evidence=f["evidence"], remediation=f["remediation"], references=f["references"])
            if self._add_finding(finding, container="Nuclei Findings"):
                added += 1

        if added:
            crits = sum(1 for f in r["findings"] if f["severity"] == "CRITICAL")
            highs = sum(1 for f in r["findings"] if f["severity"] == "HIGH")
            self.log(f" ✓ Nuclei template scan: {added} finding(s) ({crits} critical, {highs} high) in {r.get('seconds', 0)}s", "good")
        else:
            self.log(f" ⊘ Nuclei template scan: no template matched in {r.get('seconds', 0)}s", "muted")
        self.prog("vuln", 25)
        return r["findings"]

    def stage_dirbuster_scan(self, services):
        """Run high-performance directory discovery against web services."""
        self.current_stage = "dirbuster"
        self.log(" STAGE 6.8: DIRECTORY DISCOVERY (DIRBUSTER MODE) ", "stage")
        self.stage_signal.emit("DirBuster Scan")
        self.prog("vuln", 30)

        findings = []
        
        if not DIRBUSTER_AVAILABLE:
            self.log("  ✗ DirBuster scanner module not loaded", "warn")
            return findings

        # --- Setup paths ---
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_dir = os.path.join(base_path, "dirbuster_pkg")
        # Use medium wordlist if it exists, fallback to small
        wordlist = os.path.join(db_dir, "directory-list-2.3-medium.txt")
        if not os.path.exists(wordlist):
            wordlist = os.path.join(db_dir, "directory-list-2.3-small.txt")

        if not os.path.exists(wordlist):
            self.log(f"  ✗ Wordlist not found in {db_dir}", "warn")
            return findings

        # --- Identify web targets ---
        web_svcs = [s for s in services if s.get("service") in ("http", "https", "http-alt")]
        if not web_svcs:
            web_svcs = [{"host": self.target, "port": "80", "service": "http"}]

        for svc in web_svcs:
            if self._stop: break
            self._wait_if_paused()

            host = svc.get("host", self.target)
            port = svc.get("port", "80")
            proto = "https" if svc.get("service") == "https" or port == "443" else "http"
            url = f"{proto}://{host}:{port}/"
            
            self.log(f"  Brute forcing: {url}", "info")
            
            self.dirbuster_engine = DirBusterScanner(
                target_url=url,
                wordlist_path=wordlist,
                threads=30, # Increased for better performance
                log_callback=self.log,
                result_callback=self.result_signal.emit
            )
            
            try:
                svc_findings = self.dirbuster_engine.run()
                for found in svc_findings:
                    findings.append({"url": url, "found": found})
                    # DB insertion is handled by the result_callback in dirbuster_scanner if desired,
                    # but let's add it here for consistency with other stages.
                    DB.add_evidence(self.scan_id, "Directory Discovery", found, source_url=url, notes="CyberRecon BruteForce")
            except Exception as e:
                self.log(f"  Error during discovery on {url}: {e}", "warn")

        self.log(f" ✓ Discovery complete: {len(findings)} items found", "good")
        self.prog("vuln", 35)
        return findings

    #  RECOMMENDATION GENERATION 
    def stage_recommendation_generation(self, vulns, crypto_analysis=None):
        """Generate actionable security recommendations and hardened configurations"""
        if not RECOMMENDATION_ENGINE_AVAILABLE:
            self.log("  Recommendation engine not available (skipping)", "muted")
            return {}
        
        self.current_stage = "recommendations"
        self.log(" RECOMMENDATION GENERATION ", "stage")
        self.stage_signal.emit("Generating Recommendations")
        self.prog("misc", 80)
        
        try:
            # Prepare vulnerability data for recommendation engine
            vuln_data = []
            
            # Handle various data formats
            if isinstance(vulns, dict):
                vulns = list(vulns.values()) if vulns else []
            elif not isinstance(vulns, list):
                vulns = [vulns] if vulns else []
            
            for vuln in vulns:
                # Extract vulnerability text regardless of format
                if isinstance(vuln, dict):
                    vuln_text = str(vuln.get('title', str(vuln))).lower()
                else:
                    vuln_text = str(vuln).lower()
                
                vuln_text = vuln_text.replace('(', '').replace(')', '')
                
                # Map to recommendation engine types
                if 'xss' in vuln_text:
                    vuln_data.append({'type': 'xss', 'title': vuln_text})
                elif any(x in vuln_text for x in ['sql', 'injection']):
                    vuln_data.append({'type': 'sql_injection', 'title': vuln_text})
                elif 'idor' in vuln_text:
                    vuln_data.append({'type': 'idor', 'title': vuln_text})
                elif any(x in vuln_text for x in ['auth', 'password', 'weak']):
                    vuln_data.append({'type': 'weak_authentication', 'title': vuln_text})
                elif any(x in vuln_text for x in ['header', 'csp', 'security']):
                    vuln_data.append({'type': 'missing_security_headers', 'title': vuln_text})
                elif any(x in vuln_text for x in ['tls', 'ssl', 'crypto', 'cipher']):
                    vuln_data.append({'type': 'weak_cryptography', 'title': vuln_text})
            
            if not vuln_data:
                self.log("  No vulnerabilities to generate recommendations for", "muted")
                return {}
            
            # Generate recommendations
            engine = RecommendationEngine()
            recommendations = engine.generate_recommendations(vuln_data)
            
            self.log(f"  Generated {len(recommendations['recommendations'])} recommendation sets", "good")
            
            # Display recommendations in GUI
            self.result_signal.emit("Security Recommendations", 
                                  f"Generated {len(recommendations['recommendations'])} fix recommendations",
                                  "#FFD700")  # Gold for recommendations
            
            # Show each recommendation type
            for rec in recommendations['recommendations']:
                vuln_title = rec.get('vulnerability', 'Unknown')
                severity = rec.get('severity', 'MEDIUM')
                color = "#FF6B6B" if severity == 'CRITICAL' else "#FF9B9B" if severity == 'HIGH' else "#FFD700"
                self.result_signal.emit("Security Recommendations", 
                                      f"✅ {vuln_title} - {severity}",
                                      color)
            
            # Generate hardened configs
            nginx_config = engine.generate_nginx_hardened_config()
            apache_config = engine.generate_apache_hardened_config()
            waf_rules = engine.generate_waf_rules()
            
            # Save to results directory
            with open(os.path.join(RESULTS_DIR, f"hardened_nginx_{self.scan_id}.conf"), 'w') as f:
                f.write(nginx_config)
            with open(os.path.join(RESULTS_DIR, f"hardened_apache_{self.scan_id}.conf"), 'w') as f:
                f.write(apache_config)
            with open(os.path.join(RESULTS_DIR, f"waf_rules_{self.scan_id}.txt"), 'w') as f:
                f.write(waf_rules)
            
            # Display generated configs in GUI
            self.result_signal.emit("Generated Configs", 
                                  "✅ hardened_nginx.conf (ready to deploy)",
                                  "#00E5FF")
            self.result_signal.emit("Generated Configs", 
                                  "✅ hardened_apache.conf (ready to deploy)",
                                  "#00E5FF")
            self.result_signal.emit("Generated Configs", 
                                  "✅ WAF rules (ModSecurity)",
                                  "#00E5FF")
            
            self.log(f"  Hardened configs: nginx, apache, WAF rules saved", "good")
            
            # Generate compliance report
            compliance_report = engine.generate_compliance_report(recommendations['recommendations'])
            self.data['compliance_recommendations'] = compliance_report
            self.data['recommendations'] = recommendations
            
            # Display compliance mapping
            self.result_signal.emit("Compliance Mapping", 
                                  "✅ PCI-DSS compliance mapped",
                                  "#00E5FF")
            self.result_signal.emit("Compliance Mapping", 
                                  "✅ HIPAA compliance mapped",
                                  "#00E5FF")
            self.result_signal.emit("Compliance Mapping", 
                                  "✅ NIST CSF mapped",
                                  "#00E5FF")
            self.result_signal.emit("Compliance Mapping", 
                                  "✅ ISO 27001 mapped",
                                  "#00E5FF")
            
            self.log(f"  Compliance mapping complete (PCI/HIPAA/NIST/ISO)", "good")
            
        except Exception as e:
            self.log(f"  Recommendation generation error: {str(e)[:100]}", "warn")
        
        return self.data.get('recommendations', {})

    #  MAIN RUN 
    def _run_stage(self, name, fn, *args, default=None):
        """Run one pipeline stage in isolation.

        A stage that raises is logged and recorded in data["stage_errors"]; the scan then
        continues with the remaining stages instead of dying. A user stop raises
        _ScanStopped so run() can finalise the scan properly.
        """
        self._wait_if_paused()
        if self._stop:
            raise _ScanStopped()
        try:
            result = fn(*args)
        except _ScanStopped:
            raise
        except Exception as e:
            self.log(f"  Stage '{name}' failed: {str(e)[:200]} - continuing with remaining stages", "error")
            self.log(traceback.format_exc(), "muted")
            self.data.setdefault("stage_errors", []).append(
                {"stage": name, "error": str(e)[:300]})
            return default
        return default if result is None else result

    def _run_pipeline(self):
        st = self._run_stage

        self.log(f" DanishRecon  Scan started on {self.target}", "stage")
        self.log(f"   Profile: {self.profile} | Scan ID: #{self.scan_id}", "info")
        self.log(f"   Results: {os.path.abspath(RESULTS_DIR)}", "muted")

        st("dns", self.stage_dns_recon)
        subdomains = st("subdomain", self.stage_subdomain_discovery) or [self.target]
        live_hosts = st("host", self.stage_host_discovery, subdomains) or [self.target]
        st("ssl", self.stage_ssl_analysis, live_hosts)
        services = st("portscan", self.stage_port_scan, live_hosts) or []
        services = self._ensure_seed_service(services)

        # nmap reports 'tcpwrapped'/'unknown' when it connects but cannot identify the
        # service (common behind CDNs/proxies). Fall back to the well-known service for
        # that port so downstream stages still know which ports speak HTTP(S).
        _PORT_SVC_MAP = {
            "80": "http",   "8080": "http",  "8000": "http",  "8008": "http",
            "443": "https", "8443": "https", "4443": "https",
            "21": "ftp",    "22": "ssh",     "23": "telnet",  "25": "smtp",
            "110": "pop3",  "143": "imap",   "587": "smtp",   "465": "smtp",
            "3306": "mysql", "5432": "postgresql", "1433": "mssql",
            "3389": "rdp",  "445": "smb",    "139": "smb",
            "161": "snmp",  "53": "dns",     "5900": "vnc",   "6379": "redis",
            "27017": "mongodb", "9200": "elasticsearch",
        }
        _normalized_count = 0
        for _svc in services:
            if _svc.get("service", "").lower() in ("tcpwrapped", "unknown", ""):
                _port_str = str(_svc.get("port", ""))
                _guessed = _PORT_SVC_MAP.get(_port_str, "")
                if _guessed:
                    self.log(f"  [Normalize] port {_port_str}: '{_svc['service']}' -> '{_guessed}' (guessed from port)", "info")
                    _svc["service"] = _guessed
                    _normalized_count += 1
        if _normalized_count:
            self.log(f"  Normalized {_normalized_count} unidentified services by port number", "good")

        crypto_analysis = {}
        if CRYPTO_ANALYZER_AVAILABLE:
            crypto_analysis = st("crypto", self.stage_cryptography_analysis, services) or {}

        st("tls_ciphers", self.stage_tls_cipher_audit, services)
        st("amplification", self.stage_amplification_check, services)
        st("cve", self.stage_cve_lookup, services)
        st("takeover", self.stage_takeover_check, services)
        st("waf", self.stage_waf_detection, services)
        st("crawl", self.stage_web_discovery, services)
        nikto_findings = st("nikto", self.stage_web_scan, services) or []
        st("openvas", self.stage_openvas_scan, services)
        st("api", self.stage_api_discovery, services)
        st("dast", self.stage_dast_scan, services)
        if self.opts.get("legacy_heuristics"):
            # Old length/keyword heuristics - unverified signals, never written to the report.
            st("web_vuln", self.stage_web_vulnerability_testing, services)
        st("secrets", self.stage_secret_scanning, services)

        if self.opts.get("nuclei"):
            st("nuclei", self.stage_nuclei_scan, services)
        else:
            self.log("  Nuclei scanning disabled", "muted")

        if self.opts.get("dirbuster"):
            st("dirbuster", self.stage_dirbuster_scan, services)
        else:
            self.log("  DirBuster discovery disabled", "muted")

        st("exploit", self.stage_exploit_lookup, services)
        vulns = st("ai", self.stage_ai_ranking, services, nikto_findings) or []
        st("gemini", self.stage_gemini_analysis, services)
        st("compliance", self.stage_compliance, vulns)
        st("paths", self.stage_attack_paths, services)
        st("recs", self.stage_recommendations, vulns)
        if RECOMMENDATION_ENGINE_AVAILABLE:
            st("recgen", self.stage_recommendation_generation, vulns, crypto_analysis)

        graph_path = st("graph", self.stage_attack_graph, services) or ""
        self.prog("vuln", 100)

        st("diff", self._diff_against_previous)
        self._mark_scan_completed()
        if self._stop:
            raise _ScanStopped()

        # Reporting is not isolated: a scan without a report is a failed scan.
        report_path = self.stage_report(graph_path)
        json_path   = self.export_json()
        csv_path    = self.export_csv()
        md_path     = self.export_markdown()

        self.data["report_path"] = report_path
        self.data["graph_path"]  = graph_path
        self.data["json_path"]   = json_path

        DB.finish_scan(self.scan_id, {
            "hosts": len(self.data["hosts"]),
            "services": len(self.data["services"]),
            "vulns": len(self.data["vulnerabilities"]),
            "started_at": self.data["started_at"],
            "ended_at": self.data["ended_at"],
            "duration": self.data["duration"],
            "stage_errors": len(self.data.get("stage_errors", [])),
        })

        self.log(" SCAN COMPLETE ", "stage")
        if self.data.get("stage_errors"):
            failed = ", ".join(e["stage"] for e in self.data["stage_errors"])
            self.log(f" Completed with failed stage(s): {failed} - results from those stages are missing", "warn")
        self.log(f" Started: {self.data['started_at']} | Ended: {self.data['ended_at']} | Duration: {self.data['duration']}", "good")
        self.log(f" HTML Report: {os.path.abspath(report_path)}", "good")
        self.log(f" JSON Export: {os.path.abspath(json_path)}", "good")
        self.log(f" CSV Export:  {os.path.abspath(csv_path)}", "good")
        self.log(f" Markdown:    {os.path.abspath(md_path)}", "good")

    def run(self):
        self.current_stage = "init"
        status = "failed"
        try:
            self._run_pipeline()
            status = "stopped" if self._stop else "complete"
        except _ScanStopped:
            status = "stopped"
        except Exception as e:
            self.log(f"Scan error: {e}", "error")
            self.log(traceback.format_exc(), "muted")
        finally:
            # Never leave a scan row stuck in 'running'.
            if status != "complete":
                try:
                    DB.set_scan_status(self.scan_id, status)
                except Exception:
                    pass

        if status == "complete":
            self.scan_complete.emit(self.data)
        else:
            # Both a user stop and a fatal error must release the GUI.
            self.stopped.emit()

# 
#  MINI WIDGETS
# 
