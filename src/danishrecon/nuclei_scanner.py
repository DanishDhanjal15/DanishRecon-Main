#!/usr/bin/env python3
"""
Nuclei Scanner Integration Module
==================================
Wraps the ProjectDiscovery Nuclei vulnerability scanner.
Nuclei is a fast, customizable vulnerability scanner based on templates.

SETUP (one-time):
  1. Download Nuclei: https://github.com/projectdiscovery/nuclei/releases
  2. Extract to PATH or specify templates_path in NucleiScanner()
  3. Optional: Download template pack:
     nuclei -update-templates

CyberRecon will auto-detect Nuclei; falls back to demo mode if not installed.
"""

import json
import re
import os
import subprocess
import shutil
import time
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Utility: Find Nuclei binary
# ─────────────────────────────────────────────────────────────────────────────

def find_nuclei() -> Optional[str]:
    """
    Search for Nuclei binary in PATH or common installation paths.
    
    Returns:
        str: Path to nuclei binary if found, None otherwise
    """
    # Try standard PATH first
    nuclei_bin = shutil.which("nuclei")
    if nuclei_bin:
        return nuclei_bin
    
    # Common Windows paths
    windows_paths = [
        r"C:\Program Files\nuclei\nuclei.exe",
        r"C:\Program Files (x86)\nuclei\nuclei.exe",
        os.path.expanduser(r"~\nuclei\nuclei.exe"),
        os.path.expanduser(r"~\Downloads\nuclei\nuclei.exe"),
        # Go install path (most common on Windows: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)
        os.path.expanduser(r"~\go\bin\nuclei.exe"),
        os.path.join(os.environ.get("GOPATH", os.path.expanduser("~/go")), "bin", "nuclei.exe"),
        os.path.join(os.environ.get("GOPATH", os.path.expanduser("~/go")), "bin", "nuclei"),
    ]
    
    # Common Unix paths
    unix_paths = [
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        os.path.expanduser("~/nuclei"),
        os.path.expanduser("~/go/bin/nuclei"),
    ]
    
    all_paths = windows_paths + unix_paths
    for path in all_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Data Model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class NucleiVulnerability:
    """A vulnerability found by Nuclei."""
    template_id: str
    template_name: str
    target: str
    severity: str
    cvss: float
    cve: str
    description: str
    matched_at: str
    extracted_values: Optional[Dict[str, Any]] = None


# ─────────────────────────────────────────────────────────────────────────────
# Main Scanner Class
# ─────────────────────────────────────────────────────────────────────────────

class NucleiScanner:
    """
    Runs Nuclei template-based vulnerability scanner.
    Auto-detects if Nuclei is installed; falls back to demo mode if not.
    """
    
    # Demo vulnerabilities (for Windows testing or when Nuclei is not installed)
    DEMO_VULNS = [
        {
            "template_id": "http-missing-headers",
            "template_name": "Missing Security Headers",
            "severity": "MEDIUM",
            "cvss": 5.3,
            "cve": "",
            "description": "Missing HTTP security headers (X-Frame-Options, Content-Security-Policy, X-Content-Type-Options)",
            "matched_at": "{target}/index.html"
        },
        {
            "template_id": "ssl-weak-cipher",
            "template_name": "Weak SSL/TLS Cipher Detected",
            "severity": "HIGH",
            "cvss": 7.5,
            "cve": "CVE-2021-3449",
            "description": "Server supports weak SSL/TLS ciphers that could be exploited",
            "matched_at": "https://{host}:443"
        },
        {
            "template_id": "http-open-redirect",
            "template_name": "Open Redirect Found",
            "severity": "MEDIUM",
            "cvss": 4.7,
            "cve": "",
            "description": "Open redirect vulnerability detected in redirect parameter",
            "matched_at": "{target}/api/redirect"
        },
    ]
    
    def __init__(
        self,
        target: str,
        severities: Optional[List[str]] = None,
        timeout: int = 300,
        log_callback: Optional[Callable] = None,
        result_callback: Optional[Callable] = None,
        templates_path: Optional[str] = None,
        extra_flags: Optional[List[str]] = None,
        demo: bool = False,
    ):
        """
        Initialize Nuclei scanner.
        
        Args:
            target: Target URL to scan (e.g., "https://example.com")
            severities: List of severity levels to scan for (critical, high, medium, low)
            timeout: Timeout in seconds for the scan
            log_callback: Function to call for logging (signature: log_callback(msg, level))
            result_callback: Function to call with results (signature: result_callback(title, msg, color))
            templates_path: Path to Nuclei templates directory
            extra_flags: Extra command-line flags for Nuclei
        """
        self.target = target
        self.severities = severities or ["critical", "high", "medium"]
        self.timeout = timeout
        self.log_callback = log_callback or self._default_log
        self.result_callback = result_callback or self._default_result
        self.templates_path = templates_path
        self.extra_flags = extra_flags or []
        
        self.request_timeout = 10   # seconds per HTTP request (nuclei -timeout)
        self.demo = demo            # simulated findings only when explicitly requested
        self.findings: List[Dict[str, Any]] = []
        self.timed_out = False
        self.nuclei_bin = find_nuclei()
        self.in_demo_mode = self.nuclei_bin is None
    
    def _default_log(self, msg: str, level: str = "info"):
        """Default logging function (prints to console)."""
        print(f"[{level.upper()}] {msg}")
    
    def _default_result(self, title: str, msg: str, color: str):
        """Default result callback."""
        print(f"{title}: {msg}")
    
    def _run_real_nuclei(self) -> List[Dict[str, Any]]:
        """Run real Nuclei scan against target."""
        findings = []
        
        try:
            # Build Nuclei command
            # Use -jsonl for line-by-line JSON output (compatible with Nuclei v3.7.1+)
            # NOTE: -templates flag is broken in v3.7.1 with large directories - omit it
            # Nuclei will use its default template location which works reliably
            cmd = [self.nuclei_bin, "-u", self.target, "-jsonl"]
            
            # Add severity filters
            if self.severities:
                severity_str = ",".join(self.severities)
                cmd.extend(["-severity", severity_str])
            
            # REMOVED: -templates flag causes crashes with large template sets in v3.7.1
            # Nuclei auto-detects templates from: ~/.pdcp/templates or -t T1,T2 format
            
            # Add extra flags
            cmd.extend(self.extra_flags)
            
            # Add other helpful flags
            # NOTE: nuclei's -timeout is the PER-REQUEST timeout in seconds, not the scan
            # budget. The overall budget (self.timeout) is enforced by the subprocess
            # timeout below.
            cmd.extend([
                "-timeout", str(self.request_timeout),
                "-rate-limit", "100",
                "-disable-update-check",
                "-ot",  # omit encoded template in JSON output
            ])
            
            self.log_callback(f"Running Nuclei: {' '.join(cmd)}", "debug")
            
            # Run the command
            start_time = time.time()
            # Use a larger buffer for subprocess timeout - Nuclei needs time for template loading/clustering
            # before it can even start making HTTP requests. Use max(timeout + 5min, timeout * 1.3)
            subprocess_timeout = max(self.timeout + 300, int(self.timeout * 1.3))
            self.log_callback(f"Subprocess will timeout at {subprocess_timeout}s (Nuclei timeout: {self.timeout}s)", "debug")
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=subprocess_timeout,
                )
            except subprocess.TimeoutExpired:
                self.timed_out = True
                self.log_callback(f"Nuclei scan timed out after {self.timeout}s (allowed up to {subprocess_timeout}s)", "warn")
                self.result_callback("Nuclei Scan", "⚠ Timeout - partial results may be available", "#F59E0B")
                return findings
            
            elapsed = time.time() - start_time
            
            # Check for Nuclei errors
            if result.returncode != 0 and result.returncode != 1:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                self.log_callback(f"Nuclei error (exit code {result.returncode}): {error_msg[:300]}", "warn")
                # Don't fail completely - Nuclei may still have produced partial results
            
            # Log stderr if present (contains progress info)
            if result.stderr:
                stderr_lines = result.stderr.strip().split('\n')
                for line in stderr_lines[-10:]:  # Last 10 lines of stderr
                    if line.strip() and ("[INF]" in line or "[WRN]" in line):
                        self.log_callback(f"  {line.strip()}", "info")
            
            # Parse JSON output
            json_lines_parsed = 0
            if result.stdout:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        json_lines_parsed += 1
                        
                        # Extract template information
                        template_id = entry.get("template-id", "unknown")
                        template_name = entry.get("info", {}).get("name", "Unknown Finding")
                        severity = entry.get("info", {}).get("severity", "medium").lower()
                        description = entry.get("info", {}).get("description", "")
                        matched_at = entry.get("matched-at", self.target)
                        # CVE ids live under info.classification.cve-id (list or string)
                        classification = entry.get("info", {}).get("classification") or {}
                        cve_raw = classification.get("cve-id") or ""
                        if isinstance(cve_raw, (list, tuple)):
                            cve = ", ".join(str(c).upper() for c in cve_raw if c)
                        else:
                            cve = str(cve_raw).upper()
                        cvss_real = classification.get("cvss-score")
                        
                        # Convert severity to CVSS-like score
                        cvss_map = {
                            "critical": 9.0,
                            "high": 7.5,
                            "medium": 5.3,
                            "low": 3.9,
                        }
                        # Prefer the template's real CVSS score; fall back to a severity bucket.
                        try:
                            cvss = float(cvss_real) if cvss_real else cvss_map.get(severity, 5.0)
                        except (TypeError, ValueError):
                            cvss = cvss_map.get(severity, 5.0)
                        
                        # Map to our risk levels
                        risk_map = {
                            "critical": "CRITICAL",
                            "high": "HIGH",
                            "medium": "MEDIUM",
                            "low": "LOW",
                        }
                        risk = risk_map.get(severity, "MEDIUM")
                        
                        finding = {
                            "template_id": template_id,
                            "template_name": template_name,
                            "target": self.target,
                            "severity": severity,
                            "risk": risk,
                            "cvss": cvss,
                            "cve": cve,
                            "description": description,
                            "matched_at": matched_at,
                        }
                        
                        findings.append(finding)
                        
                        # Emit result callback
                        self.result_callback(
                            "Nuclei Finding",
                            f"{risk}: {template_name}",
                            "#EF4444" if risk == "CRITICAL" else "#F97316" if risk == "HIGH" else "#EAB308"
                        )
                        
                        self.log_callback(
                            f"  Found [{risk}] {template_name}: {matched_at}",
                            "info"
                        )
                        
                    except json.JSONDecodeError:
                        # Skip non-JSON lines (stats, etc.)
                        pass
            
            self.log_callback(f"Nuclei scan completed in {elapsed:.1f}s: {len(findings)} findings ({json_lines_parsed} JSON lines parsed)", "info")
            
        except Exception as e:
            self.log_callback(f"Nuclei scan error: {str(e)[:200]}", "error")
            self.result_callback("Nuclei Scan", f"✗ Error: {str(e)[:100]}", "#EF4444")
        
        return findings
    
    def _run_demo_nuclei(self) -> List[Dict[str, Any]]:
        """Run Nuclei in demo mode (simulated findings)."""
        findings = []
        
        self.log_callback("Nuclei DEMO MODE - the findings below are simulated, not real", "warn")
        self.result_callback(
            "Nuclei Mode",
            "🎭 Demo Mode (Nuclei not installed - install for real scanning)",
            "#A78BFA"
        )
        
        # Generate realistic demo findings
        for demo_vuln in self.DEMO_VULNS:
            # Check if severity matches filter
            if demo_vuln["severity"].lower() not in self.severities:
                continue
            
            finding = {
                "template_id": demo_vuln["template_id"],
                "template_name": demo_vuln["template_name"],
                "target": self.target,
                "severity": demo_vuln["severity"].lower(),
                "risk": demo_vuln["severity"].upper() if demo_vuln["severity"].upper() != "CRITICAL" else "HIGH",
                "cvss": demo_vuln["cvss"],
                "cve": demo_vuln["cve"],
                "description": demo_vuln["description"],
                "matched_at": demo_vuln["matched_at"].format(target=self.target, host=self.target.split("://")[-1].split(":")[0]),
            }
            
            # Map risk
            severity = demo_vuln["severity"].lower()
            risk_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
            finding["risk"] = risk_map.get(severity, "MEDIUM")
            
            findings.append(finding)
            
            self.log_callback(
                f"  [DEMO] {finding['risk']}: {finding['template_name']}",
                "info"
            )
            
            self.result_callback(
                "Nuclei Finding (Demo)",
                f"{finding['risk']}: {finding['template_name']}",
                "#EF4444" if finding["risk"] == "CRITICAL" else "#F97316" if finding["risk"] == "HIGH" else "#EAB308"
            )
        
        # Simulate scanning time
        time.sleep(2)
        
        return findings
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the Nuclei scan.
        
        Returns:
            List of findings (dictionaries with template_id, template_name, target, risk, cvss, etc.)
        """
        self.log_callback(f"Starting Nuclei scan on {self.target}", "info")
        
        if self.demo:
            # Simulated output, only when the caller explicitly asked for a demo.
            self.findings = self._run_demo_nuclei()
        elif self.in_demo_mode:
            # Nuclei is not installed: report that, never invent findings.
            self.log_callback("Nuclei binary not found - scan skipped (no findings generated)", "warn")
            self.result_callback("Nuclei Scan", "⚠ Nuclei not installed - not scanned", "#F59E0B")
            self.findings = []
        else:
            self.findings = self._run_real_nuclei()
        
        return self.findings


# ─────────────────────────────────────────────────────────────────────────────
# Module-level exports
# ─────────────────────────────────────────────────────────────────────────────

__all__ = ["NucleiScanner", "NucleiVulnerability", "find_nuclei"]
