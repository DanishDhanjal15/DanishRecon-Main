#!/usr/bin/env python3
"""
DanishRecon - analysis engines beyond target recon.

Two engines that reuse the recon side's Finding model, SQLite database (findings / triage /
diff) and reporting, but take different inputs:

  MalwareEngine(paths)   - STATIC analysis of files (hash, type, entropy, strings/IOCs, PE
                           imports, Office macros, YARA, optional reputation lookup).
                           Files are never executed - this is defensive analysis only.
  SnifferEngine(source)  - traffic analysis of a .pcap file (default) or a live interface
                           capture (opt-in), via tshark: protocols, DNS/HTTP/TLS, cleartext
                           credentials, insecure protocols, and IOC matching.

Both are pure-Python/CLI-wrapper and degrade gracefully when an optional tool/library is
missing. They emit the same Signal objects as scan_core.ScanEngine, so the CLI, GUI and
dashboard can drive them the same way.
"""
from __future__ import annotations

import math
import os
import re
import shutil
import subprocess
import tempfile
import time
import traceback
from datetime import datetime

from danishrecon import scan_core
from danishrecon.scan_core import DB, RESULTS_DIR, Signal, esc, normalize_target
from danishrecon.findings import Finding, sort_key, write_sarif

# Optional libraries - absence is reported, never fatal.
try:
    import pefile
    _PEFILE = True
except Exception:
    _PEFILE = False
try:
    import yara
    _YARA = True
except Exception:
    _YARA = False
try:
    from oletools.olevba import VBA_Parser
    _OLEVBA = True
except Exception:
    _OLEVBA = False

import requests


# ───────────────────────────────── shared base ─────────────────────────────────
class _AnalysisEngine:
    """Common plumbing: signals, findings store, DB row, finalize + reports."""

    SIGNALS = ("log_signal", "progress_signal", "result_signal", "stage_signal",
               "chart_signal", "scan_complete", "stopped")

    def __init__(self, target_label, scan_type):
        for s in self.SIGNALS:
            setattr(self, s, Signal())
        self.scan_type = scan_type
        self.target = target_label
        self._stop = False
        self.started_at = datetime.now()
        self.scan_id = DB.new_scan(target_label, scan_type, scan_type=scan_type)
        self.data = {
            "scan_id": self.scan_id, "target": target_label, "scan_type": scan_type,
            "profile": scan_type, "timestamp": self.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "started_at": self.started_at.strftime("%Y-%m-%d %H:%M:%S"), "ended_at": "",
            "generated_at": "", "duration": "00:00:00",
            "findings": [], "vulnerabilities": [], "stage_errors": [],
            "risk_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "hosts": [], "services": [], "versions": [],
        }
        os.makedirs(RESULTS_DIR, exist_ok=True)

    def stop(self):
        self._stop = True

    def log(self, msg, level="info"):
        try:
            DB.add_timeline(self.scan_id, self.scan_type, msg, level)
        except Exception:
            pass
        self.log_signal.emit(msg, level)

    def prog(self, bar, val):
        self.progress_signal.emit(bar, val)

    def run_cmd(self, cmd, timeout=120):
        """Run an external command; returns scan_core.CmdResult (status-carrying str)."""
        if self._stop:
            return scan_core.CmdResult("", status="ok", cmd=cmd)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
            return scan_core.CmdResult(r.stdout + r.stderr, status="ok", cmd=cmd)
        except FileNotFoundError:
            return scan_core.CmdResult(f"__NOTFOUND__{cmd[0]}", status="not_found", cmd=cmd)
        except subprocess.TimeoutExpired:
            return scan_core.CmdResult("__TIMEOUT__", status="timeout", cmd=cmd)
        except Exception as e:
            return scan_core.CmdResult(f"__ERROR__{e}", status="error", cmd=cmd)

    def _add_finding(self, finding, container="Findings"):
        fp = finding.fingerprint
        if any(f.get("fingerprint") == fp for f in self.data["findings"]):
            return False
        self.data["findings"].append(finding.to_dict())
        self.data["vulnerabilities"].append(finding.label())
        if finding.severity in self.data["risk_counts"]:
            self.data["risk_counts"][finding.severity] += 1
        DB.add_finding(self.scan_id, self.target, self.data["findings"][-1])
        color = ("#EF4444" if finding.severity in ("CRITICAL", "HIGH")
                 else "#F59E0B" if finding.severity == "MEDIUM" else "#94A3B8")
        self.result_signal.emit(container, finding.label(), color)
        return True

    def _finalize(self, status="complete"):
        ended = datetime.now()
        secs = max(int((ended - self.started_at).total_seconds()), 0)
        self.data["ended_at"] = ended.strftime("%Y-%m-%d %H:%M:%S")
        self.data["generated_at"] = self.data["ended_at"]
        self.data["duration"] = f"{secs // 3600:02d}:{secs % 3600 // 60:02d}:{secs % 60:02d}"
        if status == "complete":
            paths = write_analysis_reports(self.data, self.scan_id)
            self.data.update(paths)
            DB.finish_scan(self.scan_id, {"findings": len(self.data["findings"]),
                                          "duration": self.data["duration"],
                                          "started_at": self.data["started_at"],
                                          "ended_at": self.data["ended_at"]})
        else:
            try:
                DB.set_scan_status(self.scan_id, status)
            except Exception:
                pass


# ───────────────────────────────── reporting ───────────────────────────────────
def write_analysis_reports(data, scan_id):
    """Write JSON, findings JSON, SARIF and a simple HTML report for an analysis run."""
    import json
    out = {}
    base = RESULTS_DIR
    findings = sorted(data["findings"], key=sort_key)
    with open(os.path.join(base, f"scan_{scan_id}.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    with open(os.path.join(base, f"findings_{scan_id}.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, default=str)
    out["sarif_path"] = write_sarif(findings, os.path.join(base, f"scan_{scan_id}.sarif"))

    rc = data["risk_counts"]
    rows = ""
    for f in findings:
        where = esc(f.get("file") or f.get("url") or f"{f.get('host', '')}:{f.get('port', '')}".strip(":"))
        sev = f.get("severity", "INFO")
        color = {"CRITICAL": "#b3261e", "HIGH": "#c2570c", "MEDIUM": "#8a6d00",
                 "LOW": "#2f6f4f", "INFO": "#5b6676"}.get(sev, "#5b6676")
        rows += (f"<tr><td style='color:{color};font-weight:700'>{sev}</td>"
                 f"<td>{esc(f.get('title', ''))}</td><td style='font-family:monospace;font-size:12px'>{where}</td>"
                 f"<td>{esc(f.get('evidence', ''))[:400]}</td>"
                 f"<td style='color:#64748b'>{esc(f.get('source', ''))}/{esc(f.get('confidence', ''))}</td></tr>")
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>DanishRecon {esc(data.get('scan_type', ''))} report #{scan_id}</title>
<style>body{{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0f141a;color:#e6ebf1;margin:0;padding:24px}}
h1{{font-size:20px}} .sub{{color:#93a1b3;font-size:13px;margin-bottom:16px}}
.counts span{{display:inline-block;margin-right:14px;font-weight:700}}
table{{width:100%;border-collapse:collapse;margin-top:16px;font-size:13px}}
th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #273140;vertical-align:top}}
th{{color:#93a1b3;text-transform:uppercase;font-size:11px;letter-spacing:.6px}}</style></head>
<body><h1>DanishRecon — {esc(data.get('scan_type', '').title())} Analysis</h1>
<div class="sub">Target: <b>{esc(data.get('target', ''))}</b> &nbsp;|&nbsp; Scan #{scan_id} &nbsp;|&nbsp;
Started {esc(data.get('started_at', ''))} &nbsp;|&nbsp; Duration {esc(data.get('duration', ''))} &nbsp;|&nbsp;
FOR AUTHORIZED / DEFENSIVE USE ONLY</div>
<div class="counts"><span style="color:#b3261e">CRITICAL {rc.get('CRITICAL', 0)}</span>
<span style="color:#c2570c">HIGH {rc.get('HIGH', 0)}</span>
<span style="color:#8a6d00">MEDIUM {rc.get('MEDIUM', 0)}</span>
<span style="color:#2f6f4f">LOW {rc.get('LOW', 0)}</span>
<span style="color:#5b6676">INFO {rc.get('INFO', 0)}</span></div>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Where</th><th>Evidence</th><th>Source</th></tr></thead>
<tbody>{rows or '<tr><td colspan=5 style="color:#64748b">No findings.</td></tr>'}</tbody></table>
</body></html>"""
    rp = os.path.join(base, f"report_{scan_id}.html")
    with open(rp, "w", encoding="utf-8") as fh:
        fh.write(html)
    out["report_path"] = rp
    return out


# ═══════════════════════════════ MALWARE (static) ═══════════════════════════════
_MAGIC = [
    (b"MZ", "PE executable (Windows)"), (b"\x7fELF", "ELF executable (Linux)"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class"), (b"PK\x03\x04", "ZIP / Office OOXML / JAR"),
    (b"%PDF", "PDF document"), (b"\xd0\xcf\x11\xe0", "OLE / legacy Office (doc/xls)"),
    (b"\x1f\x8b", "gzip"), (b"Rar!", "RAR archive"), (b"7z\xbc\xaf", "7-Zip archive"),
    (b"#!", "script (shebang)"), (b"<?php", "PHP script"),
]
# Win32 APIs that commonly appear in malware (not proof, but worth flagging together).
_SUS_IMPORTS = {
    "virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
    "setwindowshookex", "getprocaddress", "loadlibrarya", "loadlibraryw", "winexec",
    "shellexecutea", "shellexecutew", "urldownloadtofilea", "urldownloadtofilew",
    "internetopena", "internetopenurla", "wininet", "createprocessa", "createprocessw",
    "regsetvalueexa", "regcreatekeyexa", "cryptencrypt", "cryptdecrypt", "ntunmapviewofsection",
    "isdebuggerpresent", "checkremotedebuggerpresent", "virtualprotect", "wsastartup",
}
_IOC_RE = {
    "url": re.compile(r"\bhttps?://[^\s\"'<>\\)]{6,200}", re.I),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|ru|cn|top|xyz|io|co|us|uk|de|site|online|club|pw|tk)\b", re.I),
    "email": re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I),
    "btc": re.compile(r"\b(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b"),
    "registry": re.compile(r"\bHK(?:LM|CU|CR|U|CC)\\[\\A-Za-z0-9 _.-]{4,120}", re.I),
}
_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 3)


def file_type(head: bytes) -> str:
    for sig, name in _MAGIC:
        if head.startswith(sig):
            return name
    return "unknown / data"


class MalwareEngine(_AnalysisEngine):
    """Static analysis of one or more files. Files are read, never executed."""

    def __init__(self, paths, options=None):
        self.paths = [paths] if isinstance(paths, str) else list(paths)
        self.opts = options or {}
        label = os.path.basename(self.paths[0]) if len(self.paths) == 1 else f"{len(self.paths)} files"
        super().__init__(label, "malware")
        self.data["files_analyzed"] = 0
        self.data["iocs"] = {}

    def _iter_files(self):
        for p in self.paths:
            if self._stop:
                return
            if os.path.isdir(p):
                for root, _, names in os.walk(p):
                    for n in names:
                        yield os.path.join(root, n)
            elif os.path.isfile(p):
                yield p
            else:
                self.log(f"  Not found: {p}", "warn")

    def run(self):
        self.log(f" MALWARE STATIC ANALYSIS — {self.target}", "stage")
        self.stage_signal.emit("Malware Analysis")
        self.log(f"  Libraries: pefile={_PEFILE}, yara={_YARA}, oletools={_OLEVBA}", "muted")
        rules = self._load_yara()
        status = "complete"
        try:
            files = list(self._iter_files())
            self.log(f"  {len(files)} file(s) to analyze", "info")
            for i, path in enumerate(files):
                if self._stop:
                    status = "stopped"
                    break
                self.prog("vuln", int(10 + 80 * (i + 1) / max(len(files), 1)))
                try:
                    self._analyze_file(path, rules)
                    self.data["files_analyzed"] += 1
                except Exception as e:
                    self.log(f"  Error analyzing {path}: {str(e)[:150]}", "error")
                    self.data["stage_errors"].append({"stage": "file", "error": str(e)[:200]})
        except Exception as e:
            self.log(f"Malware analysis error: {e}", "error")
            self.log(traceback.format_exc(), "muted")
            status = "failed"
        self._finalize(status)
        if status == "complete":
            self.log(f" DONE — {self.data['files_analyzed']} file(s), {len(self.data['findings'])} finding(s)", "good")
            self.scan_complete.emit(self.data)
        else:
            self.stopped.emit()

    def _load_yara(self):
        if not _YARA:
            return None
        rules_path = self.opts.get("yara_rules") or os.getenv("YARA_RULES") or \
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules")
        if not os.path.exists(rules_path):
            self.log(f"  YARA available but no rules at {rules_path} (set YARA_RULES or --yara-rules)", "muted")
            return None
        try:
            if os.path.isdir(rules_path):
                files = {}
                for root, _, names in os.walk(rules_path):
                    for n in names:
                        if n.endswith((".yar", ".yara")):
                            files[os.path.join(root, n)] = os.path.join(root, n)
                rules = yara.compile(filepaths=files)
            else:
                rules = yara.compile(filepath=rules_path)
            self.log(f"  YARA rules loaded from {rules_path}", "good")
            return rules
        except Exception as e:
            self.log(f"  YARA rules failed to compile: {str(e)[:150]}", "warn")
            return None

    def _analyze_file(self, path, rules):
        import hashlib
        with open(path, "rb") as fh:
            blob = fh.read()
        sha256 = hashlib.sha256(blob).hexdigest()
        md5 = hashlib.md5(blob).hexdigest()
        ftype = file_type(blob[:16])
        ent = _entropy(blob[:1_000_000])
        name = os.path.basename(path)
        self.result_signal.emit("Files", f" {name}  [{ftype}]  {len(blob)} B  sha256={sha256[:16]}…  entropy={ent}", "#22D3EE")
        self.log(f"  {name}: {ftype}, {len(blob)} B, entropy {ent}, sha256 {sha256}", "info")

        def add(title, sev, cat, evidence, conf="confirmed", remediation="", refs=None):
            self._add_finding(Finding(
                title=title, severity=sev, source="malware", confidence=conf, category=cat,
                artifact_type="file", file=name, sha256=sha256, evidence=evidence,
                remediation=remediation or "Treat as untrusted; verify in an isolated environment before use.",
                references=refs or []), container="Malware Findings")

        # High entropy on an executable suggests packing/encryption.
        if ent >= 7.2 and ("executable" in ftype or "PE" in ftype):
            add(f"High-entropy {ftype.split('(')[0].strip()} (likely packed/encrypted)", "MEDIUM",
                "packing", f"Shannon entropy {ent} / 8.0", conf="heuristic")

        # Strings + IOCs
        strings = [m.group().decode("latin-1") for m in _PRINTABLE.finditer(blob[:3_000_000])]
        self._extract_iocs("\n".join(strings), name, sha256, add)

        # PE import analysis
        if _PEFILE and blob[:2] == b"MZ":
            self._analyze_pe(path, name, sha256, add)
        # Office macro analysis
        if _OLEVBA and (blob[:4] == b"PK\x03\x04" or blob[:4] == b"\xd0\xcf\x11\xe0"):
            self._analyze_macros(path, name, sha256, add)
        # YARA
        if rules is not None:
            try:
                matches = rules.match(data=blob, timeout=60)
                for m in matches:
                    meta = getattr(m, "meta", {}) or {}
                    sev = str(meta.get("severity", "")).upper()
                    sev = sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH"
                    add(f"YARA match: {m.rule}", sev, "yara",
                        f"rule {m.rule}" + (f" — {meta.get('description')}" if meta.get("description") else ""),
                        refs=[str(meta["reference"])] if meta.get("reference") else [])
            except Exception as e:
                self.log(f"  YARA match error on {name}: {str(e)[:120]}", "warn")
        # Reputation (opt-in): MalwareBazaar by hash (keyless)
        if self.opts.get("reputation"):
            self._reputation(sha256, name, add)

    def _extract_iocs(self, text, name, sha256, add):
        found = {}
        for kind, rx in _IOC_RE.items():
            vals = set(rx.findall(text))
            if kind == "ipv4":
                vals = {v for v in vals if all(0 <= int(o) <= 255 for o in v.split(".")) and not v.startswith(("0.", "127.", "255."))}
            if vals:
                found[kind] = sorted(vals)[:50]
        if found:
            store = self.data["iocs"].setdefault(name, {})
            store.update(found)
            summary = ", ".join(f"{k}:{len(v)}" for k, v in found.items())
            net = found.get("url", []) + found.get("domain", []) + found.get("ipv4", [])
            if net:
                add(f"Embedded network IOCs ({summary})", "LOW", "ioc",
                    "e.g. " + ", ".join(net[:6]), conf="heuristic",
                    remediation="Block/monitor these indicators; confirm whether the file should contact them.")

    def _analyze_pe(self, path, name, sha256, add):
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories()
            imports = set()
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                for imp in entry.imports:
                    if imp.name:
                        imports.add(imp.name.decode("latin-1").lower())
            sus = sorted(imports & _SUS_IMPORTS)
            if sus:
                sev = "HIGH" if len(sus) >= 5 else "MEDIUM"
                add(f"PE imports {len(sus)} suspicious API(s)", sev, "pe-imports",
                    ", ".join(sus[:15]), conf="heuristic",
                    remediation="Suspicious API combos (injection/download/persistence) warrant deeper review.")
            # No/odd sections or tiny import table can indicate packing
            if len(getattr(pe, "sections", [])) and all(s.get_entropy() >= 7.3 for s in pe.sections):
                add("All PE sections are high-entropy (packed)", "MEDIUM", "packing",
                    f"{len(pe.sections)} sections, all entropy ≥ 7.3", conf="heuristic")
        except Exception as e:
            self.log(f"  PE parse error on {name}: {str(e)[:120]}", "muted")

    def _analyze_macros(self, path, name, sha256, add):
        try:
            vp = VBA_Parser(path)
            if not vp.detect_vba_macros():
                vp.close()
                return
            autoexec, suspicious = [], []
            for kind, keyword, desc in (vp.analyze_macros() or []):
                if kind == "AutoExec":
                    autoexec.append(keyword)
                elif kind == "Suspicious":
                    suspicious.append(keyword)
            vp.close()
            if autoexec or suspicious:
                sev = "HIGH" if autoexec and suspicious else "MEDIUM"
                add("Office document contains VBA macros", sev, "macro",
                    f"auto-exec: {', '.join(autoexec[:6]) or 'none'}; suspicious: {', '.join(suspicious[:8]) or 'none'}",
                    remediation="Do not enable macros; open in Protected View / a sandbox.")
        except Exception as e:
            self.log(f"  Macro parse error on {name}: {str(e)[:120]}", "muted")

    def _reputation(self, sha256, name, add):
        try:
            resp = requests.post("https://mb-api.abuse.ch/api/v1/",
                                 data={"query": "get_info", "hash": sha256}, timeout=20)
            j = resp.json()
            if j.get("query_status") == "ok" and j.get("data"):
                d = j["data"][0]
                sig = d.get("signature") or "known malware"
                add(f"Known malware on MalwareBazaar: {sig}", "CRITICAL", "reputation",
                    f"file_type={d.get('file_type')}, first_seen={d.get('first_seen')}, tags={','.join(d.get('tags') or [])}",
                    refs=[f"https://bazaar.abuse.ch/sample/{sha256}/"],
                    remediation="Confirmed-malicious hash. Isolate and remediate affected systems.")
            else:
                self.log(f"  MalwareBazaar: {name} not in database (not proof it is clean)", "muted")
        except Exception as e:
            self.log(f"  Reputation lookup failed: {str(e)[:120]}", "warn")


# ═══════════════════════════════ SNIFFER (traffic) ═══════════════════════════════
def find_tshark():
    """Locate tshark (Wireshark CLI). Returns a path or None."""
    p = shutil.which("tshark")
    if p:
        return p
    for c in (r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe",
              "/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"):
        if os.path.isfile(c):
            return c
    return None


class SnifferEngine(_AnalysisEngine):
    """Traffic analysis of a .pcap file (default) or a live interface capture (opt-in)."""

    def __init__(self, source, options=None):
        self.opts = options or {}
        self.live = bool(self.opts.get("live"))
        self.source = source
        super().__init__(os.path.basename(source) if not self.live else f"iface:{source}", "sniff")
        self.tshark = find_tshark()
        self.data["bad_iocs"] = self._load_iocs()

    def _load_iocs(self):
        """Optional threat-intel: domains/IPs to flag if seen in traffic (file or malware IOCs)."""
        iocs = set()
        src = self.opts.get("ioc_file") or os.getenv("CYBERRECON_IOCS")
        if src and os.path.isfile(src):
            try:
                with open(src, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            iocs.add(line.lower())
            except Exception:
                pass
        return iocs

    def _tshark(self, args, timeout=300):
        return self.run_cmd([self.tshark] + args, timeout=timeout)

    def run(self):
        self.log(f" NETWORK TRAFFIC ANALYSIS — {self.target}", "stage")
        self.stage_signal.emit("Traffic Analysis")
        status = "complete"
        try:
            if not self.tshark:
                self.log("  tshark (Wireshark) not found — install Wireshark to analyze traffic", "error")
                self._finalize("failed")
                self.stopped.emit()
                return
            pcap = self.source
            if self.live:
                pcap = self._capture()
                if not pcap:
                    status = "failed"
                    self._finalize(status)
                    self.stopped.emit()
                    return
            elif not os.path.isfile(pcap):
                self.log(f"  pcap not found: {pcap}", "error")
                self._finalize("failed")
                self.stopped.emit()
                return

            self._protocol_summary(pcap)
            self._dns_http_tls(pcap)
            self._cleartext_credentials(pcap)
            self._insecure_protocols(pcap)
        except Exception as e:
            self.log(f"Traffic analysis error: {e}", "error")
            self.log(traceback.format_exc(), "muted")
            status = "failed"
        self._finalize(status)
        if status == "complete":
            self.log(f" DONE — {len(self.data['findings'])} finding(s)", "good")
            self.scan_complete.emit(self.data)
        else:
            self.stopped.emit()

    def _capture(self):
        """Live capture to a temp pcap. Authorized networks only; bounded by packet/time cap."""
        iface = self.source
        count = int(self.opts.get("count", 2000))
        duration = int(self.opts.get("duration", 60))
        out = os.path.join(RESULTS_DIR, f"capture_{self.scan_id}.pcap")
        self.log(f"  Capturing on {iface} (max {count} packets / {duration}s) — authorized networks only", "warn")
        args = ["-i", iface, "-a", f"duration:{duration}", "-c", str(count), "-w", out]
        r = self._tshark(args, timeout=duration + 30)
        if r.not_found or not os.path.isfile(out):
            self.log(f"  Capture failed ({r.status}). On Windows live capture needs Npcap + admin rights.", "error")
            return None
        self.log(f"  Captured to {out}", "good")
        return out

    def _count_lines(self, out):
        return [l for l in str(out).splitlines() if l.strip() and "__" not in l]

    def _protocol_summary(self, pcap):
        r = self._tshark(["-r", pcap, "-q", "-z", "io,phs"], timeout=180)
        if r.ok:
            protos = [l.strip() for l in str(r).splitlines() if l.strip() and "frames:" in l]
            for line in protos[:20]:
                self.result_signal.emit("Protocols", line[:120], "#94A3B8")
            self.log(f"  Protocol hierarchy: {len(protos)} protocol(s) seen", "info")
        r2 = self._tshark(["-r", pcap, "-q", "-z", "conv,tcp"], timeout=180)
        talkers = [l for l in str(r2).splitlines() if "<->" in l][:10]
        for t in talkers:
            self.result_signal.emit("Top Talkers", t.strip()[:120], "#94A3B8")

    def _dns_http_tls(self, pcap):
        # DNS queries
        r = self._tshark(["-r", pcap, "-Y", "dns.flags.response==0", "-T", "fields", "-e", "dns.qry.name"], timeout=180)
        domains = sorted({d.strip().lower() for d in self._count_lines(r) if d.strip()})
        for d in domains[:40]:
            self.result_signal.emit("DNS Queries", d, "#22D3EE")
            if self.data["bad_iocs"] and d in self.data["bad_iocs"]:
                self._add_finding(Finding(title=f"Traffic contacts known-bad domain: {d}", severity="HIGH",
                    source="sniffer", confidence="confirmed", category="ioc", artifact_type="flow",
                    host=d, evidence="DNS query matches the supplied threat-intel IOC list",
                    remediation="Investigate the host making this query; it may be compromised."),
                    container="Traffic Findings")
        if domains:
            self.log(f"  {len(domains)} unique DNS query name(s)", "info")
        # HTTP hosts (cleartext)
        r = self._tshark(["-r", pcap, "-Y", "http.request", "-T", "fields", "-e", "http.host", "-e", "http.request.uri"], timeout=180)
        http_hosts = sorted({l.split("\t")[0].strip().lower() for l in self._count_lines(r) if l.split("\t")[0].strip()})
        for h in http_hosts[:30]:
            self.result_signal.emit("HTTP Hosts", f"http://{h}", "#F59E0B")
        if http_hosts:
            self._add_finding(Finding(title="Cleartext HTTP traffic observed", severity="MEDIUM",
                source="sniffer", confidence="confirmed", category="cleartext", artifact_type="flow",
                evidence=f"{len(http_hosts)} host(s) served over plain HTTP, e.g. {', '.join(http_hosts[:5])}",
                remediation="Move these services to HTTPS; HTTP exposes data and credentials to the network."),
                container="Traffic Findings")
        # TLS SNI
        r = self._tshark(["-r", pcap, "-Y", "tls.handshake.extensions_server_name", "-T", "fields",
                          "-e", "tls.handshake.extensions_server_name"], timeout=180)
        sni = sorted({s.strip().lower() for s in self._count_lines(r) if s.strip()})
        for s in sni[:30]:
            self.result_signal.emit("TLS SNI", s, "#10B981")

    def _cleartext_credentials(self, pcap):
        checks = [
            ("HTTP Basic auth", "http.authbasic", ["http.authbasic"]),
            ("FTP credentials", 'ftp.request.command=="USER" || ftp.request.command=="PASS"',
             ["ftp.request.command", "ftp.request.arg"]),
            ("Telnet session (cleartext)", "telnet", ["frame.number"]),
            ("POP3 login", 'pop.request.command=="USER" || pop.request.command=="PASS"',
             ["pop.request.parameter"]),
            ("IMAP login", "imap.request contains \"LOGIN\"", ["imap.request"]),
        ]
        for title, disp, fields in checks:
            args = ["-r", pcap, "-Y", disp, "-T", "fields"] + sum([["-e", f] for f in fields], [])
            r = self._tshark(args, timeout=120)
            hits = self._count_lines(r)
            if hits:
                sample = "; ".join(h.strip() for h in hits[:3])[:200]
                self._add_finding(Finding(title=f"Cleartext credentials: {title}", severity="HIGH",
                    source="sniffer", confidence="confirmed", category="cleartext-creds", artifact_type="flow",
                    evidence=f"{len(hits)} occurrence(s). e.g. {sample}",
                    remediation="These credentials cross the network unencrypted. Switch to an encrypted protocol (HTTPS/FTPS/SSH)."),
                    container="Traffic Findings")

    def _insecure_protocols(self, pcap):
        insecure = {"telnet": "Telnet", "ftp": "FTP", "http": "HTTP", "snmp": "SNMP (v1/v2c)",
                    "tftp": "TFTP", "ldap": "LDAP (unencrypted)"}
        seen = []
        for proto, label in insecure.items():
            r = self._tshark(["-r", pcap, "-Y", proto, "-T", "fields", "-e", "frame.number"], timeout=90)
            if self._count_lines(r):
                seen.append(label)
        if seen:
            self._add_finding(Finding(title="Insecure/cleartext protocols in use", severity="MEDIUM",
                source="sniffer", confidence="confirmed", category="insecure-protocol", artifact_type="flow",
                evidence="Observed: " + ", ".join(seen),
                remediation="Replace with encrypted equivalents (SSH, FTPS/SFTP, HTTPS, SNMPv3, LDAPS)."),
                container="Traffic Findings")
