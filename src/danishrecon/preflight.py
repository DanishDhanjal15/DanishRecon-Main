#!/usr/bin/env python3
"""
preflight.py — DanishRecon system readiness check
====================================================

Detects the external CLI tools, Python packages, and configuration that
DanishRecon needs, and reports exactly what is ready and what is missing
(with copy-paste install hints per OS).

DESIGN RULE: this module imports ONLY the Python standard library, so it runs
even on a machine where none of the project's dependencies are installed yet.
That is the whole point — it is the first thing a new user should be able to run.

Usage:
    danishrecon-preflight          # human-readable report in the terminal
    danishrecon-preflight --json   # machine-readable JSON (for the GUI/CI)

Programmatic:
    from danishrecon.preflight import run_preflight
    report = run_preflight()       # -> dict, see build_report()
"""

import os
import re
import sys
import json
import shutil
import platform
import subprocess
import importlib.util

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# ─────────────────────────────────────────────────────────────────────────────
# Severity levels
# ─────────────────────────────────────────────────────────────────────────────
CRITICAL = "critical"     # app is basically useless without this
RECOMMENDED = "recommended"  # core feature won't work, but app still runs
OPTIONAL = "optional"     # nice-to-have / advanced feature

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)   # project root (holds nikto_official/, exploit-database/, .env)

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"


# ─────────────────────────────────────────────────────────────────────────────
# Low-level detection helpers
# ─────────────────────────────────────────────────────────────────────────────
def _which(*names):
    """Return the first executable found on PATH from the given names."""
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _first_existing(paths):
    """Return the first path that exists on disk, else None."""
    for p in paths:
        if p and os.path.exists(p):
            return p
    return None


def _try_version(cmd):
    """Run `cmd` and return a short one-line version string, or None on failure."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=8, check=False
        )
        text = _ANSI_RE.sub("", (out.stdout or out.stderr or "")).strip()
        return text.splitlines()[0].strip() if text else None
    except Exception:
        return None


def _has_module(mod_name):
    """True if a Python package is importable, without importing it."""
    try:
        return importlib.util.find_spec(mod_name) is not None
    except (ImportError, ValueError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Tool-specific locators (mirror the discovery logic in gui.py)
# ─────────────────────────────────────────────────────────────────────────────
def _find_nmap():
    return _which("nmap")


def _perl_has_xml_writer(perl_exe):
    """True if this Perl has XML::Writer — the module Nikto needs but Git Bash perl lacks."""
    if not perl_exe:
        return False
    try:
        r = subprocess.run([perl_exe, "-MXML::Writer", "-e", "1"],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _perl_candidates():
    import glob
    cands = []
    p = _which("perl")
    if p:
        cands.append(p)
    cands += [
        r"C:\Strawberry\perl\bin\perl.exe",
        r"C:\Program Files\Strawberry Perl\perl\bin\perl.exe",
    ]
    cands += glob.glob(os.path.expanduser(r"~\Downloads\strawberry-perl*\perl\bin\perl.exe"))
    return [c for c in cands if c and os.path.exists(c)]


def _find_perl():
    # Prefer a Perl that can actually run Nikto (has XML::Writer), else the first that exists
    cands = _perl_candidates()
    for c in cands:
        if _perl_has_xml_writer(c):
            return c
    return cands[0] if cands else None


def _find_nikto():
    from danishrecon.tools import find_nikto
    return find_nikto()


def _find_nuclei():
    p = _which("nuclei")
    if p:
        return p
    gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
    return _first_existing([
        os.path.join(gopath, "bin", "nuclei.exe"),
        os.path.join(gopath, "bin", "nuclei"),
        os.path.expanduser(r"~\go\bin\nuclei.exe"),
    ])


def _find_searchsploit():
    edb = os.path.join(_PARENT, "exploit-database")
    return _which("searchsploit") or _first_existing([
        os.path.join(edb, "searchsploit.ps1"),
        os.path.join(edb, "searchsploit.bat"),
        os.path.join(edb, "searchsploit"),
    ])


def _find_docker():
    return _which("docker")


# ─────────────────────────────────────────────────────────────────────────────
# Install hints per OS
# ─────────────────────────────────────────────────────────────────────────────
def _hint(win, linux, mac=None):
    if IS_WINDOWS:
        return win
    if IS_MAC:
        return mac or linux
    return linux


# ─────────────────────────────────────────────────────────────────────────────
# The checks
# ─────────────────────────────────────────────────────────────────────────────
def _check_external_tools():
    checks = []

    nmap = _find_nmap()
    checks.append(dict(
        name="nmap", category="External tool", severity=CRITICAL,
        ok=bool(nmap), path=nmap,
        version=_try_version([nmap, "--version"]) if nmap else None,
        purpose="Port scanning & service/version detection (core stage)",
        hint=_hint("Download: https://nmap.org/download.html (add to PATH)",
                   "sudo apt install nmap   # or: sudo dnf install nmap",
                   "brew install nmap"),
    ))

    perl = _find_perl()
    perl_ok = _perl_has_xml_writer(perl)   # perl that can actually run Nikto
    checks.append(dict(
        name="perl (Nikto)", category="External tool", severity=RECOMMENDED,
        ok=perl_ok, path=perl,
        version=("XML::Writer OK" if perl_ok else
                 ("found but missing XML::Writer" if perl else None)),
        purpose="Perl WITH the XML::Writer module — required to run Nikto",
        hint=_hint(
            "Install Strawberry Perl (has XML::Writer): https://strawberryperl.com/  "
            "— a bare Git Bash perl will NOT run Nikto",
            "sudo apt install libxml-writer-perl   # plus perl",
            "cpan install XML::Writer"),
    ))

    nikto = _find_nikto()
    checks.append(dict(
        name="nikto", category="External tool", severity=RECOMMENDED,
        ok=bool(nikto), path=nikto, version=None,
        purpose="Web server vulnerability scanning (Stage 6)",
        hint=_hint("danishrecon setup nikto   (needs Strawberry Perl: https://strawberryperl.com)",
                   "sudo apt install nikto   # or clone github.com/sullo/nikto",
                   "brew install nikto"),
    ))

    nuclei = _find_nuclei()
    checks.append(dict(
        name="nuclei", category="External tool", severity=OPTIONAL,
        ok=bool(nuclei), path=nuclei,
        version=_try_version([nuclei, "-version"]) if nuclei else None,
        purpose="Template-based vulnerability scanning (optional stage)",
        hint="danishrecon setup nuclei",
    ))

    # katana (crawler) + httpx (fingerprinting): without them the DAST stage has no
    # URLs/parameters to test, so injection flaws would go unchecked.
    try:
        from danishrecon import recon_tools as _rt          # stdlib-only module
        _katana, _httpx = _rt.find_tool("katana"), _rt.find_tool("httpx")
    except Exception:
        _katana = _httpx = None
    checks.append(dict(
        name="katana", category="External tool", severity=RECOMMENDED,
        ok=bool(_katana), path=_katana, version=None,
        purpose="Crawls the web app to find URLs/parameters for injection testing (DAST)",
        hint="danishrecon setup katana",
    ))
    checks.append(dict(
        name="httpx", category="External tool", severity=OPTIONAL,
        ok=bool(_httpx), path=_httpx, version=None,
        purpose="Web service probing and technology fingerprinting",
        hint="danishrecon setup httpx"
             "   (the ProjectDiscovery tool, not the Python 'httpx' package)",
    ))

    # Analysis modules (malware / traffic) - all optional
    _tshark = _which("tshark") or next((p for p in (
        r"C:\Program Files\Wireshark\tshark.exe", "/usr/bin/tshark", "/usr/local/bin/tshark")
        if os.path.isfile(p)), None)
    checks.append(dict(
        name="tshark", category="External tool", severity=OPTIONAL,
        ok=bool(_tshark), path=_tshark,
        version=_try_version([_tshark, "-v"]) if _tshark else None,
        purpose="Network traffic analysis (sniffer module): pcap analysis and live capture",
        hint=_hint("Install Wireshark: https://www.wireshark.org/download.html",
                   "sudo apt install tshark", "brew install wireshark"),
    ))
    for _mod, _why in (("pefile", "PE import/section analysis (malware module)"),
                       ("yara", "YARA rule matching (malware module)"),
                       ("oletools", "Office macro analysis (malware module)")):
        checks.append(dict(
            name=_mod, category="Python package", severity=OPTIONAL,
            ok=_has_module(_mod), path=None, version=None, purpose=_why,
            hint=f"pip install {'yara-python' if _mod == 'yara' else _mod}",
        ))

    from danishrecon.scan_core import find_rustscan as _frs
    _rustscan = _frs()
    checks.append(dict(
        name="rustscan", category="External tool", severity=OPTIONAL,
        ok=bool(_rustscan), path=_rustscan,
        version=_try_version([_rustscan, "--version"]) if _rustscan else None,
        purpose="Fast all-ports discovery for the Full profile (feeds nmap -sV; nmap used if absent)",
        hint="danishrecon setup rustscan",
    ))

    try:
        from danishrecon import exploit_search as _es       # stdlib-only module
        ss = _es.find_index()
    except Exception:
        ss = None
    checks.append(dict(
        name="exploit-db index", category="External tool", severity=OPTIONAL,
        ok=bool(ss), path=ss, version=None,
        purpose="Exploit-DB reference lookup for detected versions (files_exploits.csv)",
        hint="danishrecon setup exploitdb"
             "   (or set EXPLOITDB_PATH to an existing checkout)",
    ))

    docker = _find_docker()
    checks.append(dict(
        name="docker", category="External tool", severity=OPTIONAL,
        ok=bool(docker), path=docker,
        version=_try_version([docker, "--version"]) if docker else None,
        purpose="Runs the OpenVAS/Greenbone (GVM) container for deep vuln scans",
        hint=_hint("Install Docker Desktop: https://docs.docker.com/desktop/",
                   "sudo apt install docker.io", "brew install --cask docker"),
    ))

    return checks


def _check_python_packages():
    pkgs = [
        # (import name, pip name, severity, purpose)
        ("PyQt5", "PyQt5", CRITICAL, "GUI framework — app cannot launch without it"),
        ("networkx", "networkx", CRITICAL, "Attack-graph / topology modelling"),
        ("matplotlib", "matplotlib", CRITICAL, "Charts & attack-graph rendering"),
        ("requests", "requests", CRITICAL, "HTTP client for API/secret/web scanners"),
        ("dotenv", "python-dotenv", RECOMMENDED, "Loads .env (API keys, config)"),
        ("google.genai", "google-genai", OPTIONAL, "Gemini AI vulnerability analysis"),
        ("gvm", "python-gvm", OPTIONAL, "OpenVAS / Greenbone integration"),
        ("reportlab", "reportlab", OPTIONAL, "PDF report export"),
    ]
    checks = []
    for import_name, pip_name, sev, purpose in pkgs:
        ok = _has_module(import_name)
        checks.append(dict(
            name=pip_name, category="Python package", severity=sev,
            ok=ok, path=None, version=None, purpose=purpose,
            hint=f"pip install {pip_name}",
        ))
    return checks


def _check_config():
    checks = []
    # Same lookup the scanner uses: a .env in the working directory or any parent folder.
    candidates = []
    d = os.getcwd()
    while True:
        candidates.append(os.path.join(d, ".env"))
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    env_path = _first_existing(candidates)
    has_key = bool(os.environ.get("GEMINI_API_KEY", "").strip()) and \
        "your_api_key_here" not in os.environ.get("GEMINI_API_KEY", "")
    if env_path:
        try:
            with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("GEMINI_API_KEY=") and len(line.split("=", 1)[1].strip()) > 8 \
                            and "your_api_key_here" not in line:
                        has_key = True
                        break
        except Exception:
            pass

    checks.append(dict(
        name=".env file", category="Configuration", severity=OPTIONAL,
        ok=bool(env_path), path=env_path, version=None,
        purpose="Holds Gemini API key & optional Twilio alert config",
        hint="Copy .env.example to .env and fill in your values",
    ))
    checks.append(dict(
        name="GEMINI_API_KEY", category="Configuration", severity=OPTIONAL,
        ok=has_key, path=None, version=None,
        purpose="Enables AI-powered vulnerability analysis (Gemini)",
        hint="Get a free key at https://ai.google.dev/ and set it in .env",
    ))
    return checks


# ─────────────────────────────────────────────────────────────────────────────
# Report assembly
# ─────────────────────────────────────────────────────────────────────────────
def build_report():
    """Run every check and return a structured report dict."""
    checks = (
        _check_external_tools()
        + _check_python_packages()
        + _check_config()
    )

    missing_critical = [c for c in checks if not c["ok"] and c["severity"] == CRITICAL]
    missing_recommended = [c for c in checks if not c["ok"] and c["severity"] == RECOMMENDED]

    if missing_critical:
        status = "not_ready"      # app won't run / core scanning broken
    elif missing_recommended:
        status = "degraded"       # runs, but a core feature is disabled
    else:
        status = "ready"

    return {
        "status": status,
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "checks": checks,
        "summary": {
            "total": len(checks),
            "ok": sum(1 for c in checks if c["ok"]),
            "missing_critical": len(missing_critical),
            "missing_recommended": len(missing_recommended),
        },
    }


def run_preflight():
    """Public entry point — alias for build_report()."""
    return build_report()


# ─────────────────────────────────────────────────────────────────────────────
# Terminal rendering
# ─────────────────────────────────────────────────────────────────────────────
def _supports_color():
    isatty = getattr(sys.stdout, "isatty", None)
    return bool(isatty and isatty()) and os.environ.get("NO_COLOR") is None


def _c(code, text):
    if not _supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def _sev_label(sev):
    return {
        CRITICAL: _c("1;31", "CRITICAL"),
        RECOMMENDED: _c("1;33", "RECOMMENDED"),
        OPTIONAL: _c("1;36", "optional"),
    }.get(sev, sev)


def print_report(report):
    if IS_WINDOWS and _supports_color():
        os.system("")  # enable ANSI escape processing on legacy Windows consoles
    try:
        # Prefer UTF-8 so any tool version strings print cleanly; harmless if unsupported
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    print()
    print(_c("1;37", "  DanishRecon - System Readiness Check"))
    print("  " + "-" * 58)
    print(f"  Platform : {report['platform']}")
    print(f"  Python   : {report['python']}")
    print()

    # group by category
    by_cat = {}
    for c in report["checks"]:
        by_cat.setdefault(c["category"], []).append(c)

    for cat, items in by_cat.items():
        print(_c("1;37", f"  {cat}"))
        for c in items:
            mark = _c("1;32", "OK  ") if c["ok"] else _c("1;31", "MISS")
            line = f"    [{mark}] {c['name']:<16} {_sev_label(c['severity'])}"
            print(line)
            if c["ok"]:
                detail = c.get("version") or c.get("path")
                if detail:
                    print(f"            - {str(detail)[:70]}")
            else:
                print(f"            - {c['purpose']}")
                print(f"            - " + _c("2", f"fix: {c['hint']}"))
        print()

    s = report["summary"]
    print("  " + "-" * 58)
    banner = {
        "ready": _c("1;32", "  [READY] all core components present. You can scan."),
        "degraded": _c("1;33", "  [DEGRADED] app runs, but some core features are disabled."),
        "not_ready": _c("1;31", "  [NOT READY] install the CRITICAL items below to scan."),
    }[report["status"]]
    print(banner)
    print(f"  {s['ok']}/{s['total']} checks passed"
          f"  |  critical missing: {s['missing_critical']}"
          f"  |  recommended missing: {s['missing_recommended']}")
    if s["missing_critical"] or s["missing_recommended"]:
        print("  Scanning tools in one step:  danishrecon setup")
        print("  Full setup guide:            https://github.com/DanishDhanjal15/DanishRecon-Main/blob/main/docs/SETUP.md")
    print()


def main():
    report = build_report()
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    # Exit code: 0 ready, 1 degraded, 2 not_ready — useful for CI / installers
    sys.exit({"ready": 0, "degraded": 1, "not_ready": 2}[report["status"]])


if __name__ == "__main__":
    main()
