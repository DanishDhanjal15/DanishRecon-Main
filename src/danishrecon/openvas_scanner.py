#!/usr/bin/env python3
"""
OpenVAS Scanner Integration Module - Docker/GVM Edition
========================================================
Connects to Greenbone Community Edition running in Docker via GMP API.
Falls back to demo mode automatically if Docker is not running.

SETUP (one-time):
  1. Install Docker Desktop: https://www.docker.com/products/docker-desktop/
  2. Run in PowerShell:
       docker run -d --name greenbone -p 9390:9390 -p 9392:9392 securecompliance/gvm
  3. Wait ~5 minutes for NVT feed sync, then open http://localhost:9392
     Default login: admin / admin
  4. pip install python-gvm

CyberRecon will automatically detect Docker and use real OpenVAS scans.
"""

import json
import re
import os
import time
import socket
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

# ── GVM connection settings (override via environment variables) ─────────────
GVM_HOST     = os.getenv("GVM_HOST",     "127.0.0.1")
GVM_PORT     = int(os.getenv("GVM_PORT", "9390"))
GVM_USER     = os.getenv("GVM_USER",     "admin")
GVM_PASSWORD = os.getenv("GVM_PASSWORD", "admin")
GVM_TIMEOUT  = 120  # seconds for TLS socket — must be > longest GMP read op

# ── Well-known Greenbone UUIDs (used as fallbacks only) ─────────────────────
# These are populated by discovery at runtime; hardcoded UUIDs are last resort.
_KNOWN_SCAN_CONFIGS = {
    # GVM 21.4 / Greenbone Community Feed UUIDs
    "Full and Fast":        "daba56c8-73ec-11df-a475-002264764cea",
    "Full and Fast Ultimate": "698f691e-7489-11df-9d8c-002264764cea",
    "Full and very deep":   "708f25c4-7489-11df-8094-002264764cea",
    "Empty":                "085569ce-73ed-11df-83c3-002264764cea",
    # Older GVM / OpenVAS 8-9 UUIDs
    "Full and Fast (old)":  "74db13d6-7489-11df-91b9-002264764cea",
}
_PREFERRED_CONFIG_NAMES = [
    "Full and Fast",
    "Full and Fast Ultimate",
    "Full and very deep",
    "Base",
    "Discovery",
]

SCANNER_OPENVAS_DEFAULT  = "08b69003-5fc2-4037-a479-93b440211c73"
PORT_LIST_ALL_TCP        = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
PORT_LIST_ALL_TCP_UDP    = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"

# ── Try to import python-gvm ─────────────────────────────────────────────────
GVM_AVAILABLE = False
try:
    from gvm.connections import TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    GVM_AVAILABLE = True
except ImportError:
    pass


# ── Data model ───────────────────────────────────────────────────────────────
@dataclass
class OpenVASVulnerability:
    """A vulnerability found by OpenVAS / Greenbone."""
    oid:               str
    name:              str
    severity:          str
    cvss_score:        float
    host:              str
    port:              str
    service:           str
    description:       str
    created:           str
    modified:          str
    solution:          Optional[str] = None
    affected_resource: Optional[str] = None


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "CRITICAL"
    if cvss >= 7.0: return "HIGH"
    if cvss >= 4.0: return "MEDIUM"
    if cvss >  0.0: return "LOW"
    return "NONE"


def _gvm_reachable() -> bool:
    """Check if the Greenbone Docker container is running AND accepting TLS connections."""
    if not GVM_AVAILABLE:
        return False
    try:
        # Use a short timeout just for the reachability probe
        conn = TLSConnection(hostname=GVM_HOST, port=GVM_PORT, timeout=10)
        conn.connect()
        conn.disconnect()
        return True
    except Exception:
        return False


def _discover_scan_config(gmp) -> Optional[str]:
    """
    Dynamically discover the best available scan config UUID from the live GVM instance.
    Returns the UUID of the best available config, or None if none exist yet.
    Prefers 'Full and Fast' but accepts any config that is available.
    """
    try:
        configs_xml = gmp.get_scan_configs()
        all_configs = configs_xml.findall('.//config')

        if not all_configs:
            return None  # Feed not synced yet

        # Build a name→id map
        config_map = {}
        for c in all_configs:
            cid   = c.get('id', '')
            cname = c.findtext('name') or ''
            if cid and cname:
                config_map[cname] = cid

        # Try preferred names first
        for preferred in _PREFERRED_CONFIG_NAMES:
            if preferred in config_map:
                return config_map[preferred]

        # Fall back to any available config
        return list(config_map.values())[0]

    except Exception:
        return None


def _discover_port_list(gmp) -> str:
    """Dynamically discover a valid port list UUID. Falls back to hardcoded value."""
    try:
        pl_xml = gmp.get_port_lists()
        port_lists = pl_xml.findall('.//port_list')
        for pl in port_lists:
            pid   = pl.get('id', '')
            pname = pl.findtext('name') or ''
            # Prefer "All IANA assigned TCP"
            if 'All IANA assigned TCP' in pname and 'UDP' not in pname:
                return pid
        # Any TCP port list
        for pl in port_lists:
            pid   = pl.get('id', '')
            pname = pl.findtext('name') or ''
            if 'TCP' in pname:
                return pid
        # Return first available
        if port_lists:
            return port_lists[0].get('id', PORT_LIST_ALL_TCP)
    except Exception:
        pass
    return PORT_LIST_ALL_TCP


def _discover_scanner(gmp) -> str:
    """Dynamically discover the OpenVAS scanner UUID. Falls back to hardcoded value."""
    try:
        scanners_xml = gmp.get_scanners()
        for s in scanners_xml.findall('.//scanner'):
            sid   = s.get('id', '')
            sname = s.findtext('name') or ''
            stype = s.findtext('type') or ''
            # type=2 is OpenVAS scanner
            if stype == '2' or 'OpenVAS' in sname:
                return sid
    except Exception:
        pass
    return SCANNER_OPENVAS_DEFAULT


def _get_feed_sync_status(gmp) -> dict:
    """Return current feed sync status from GVM."""
    status = {"syncing": False, "feeds": []}
    try:
        feeds_xml = gmp.get_feeds()
        for feed in feeds_xml.findall('.//feed'):
            feed_type    = feed.findtext('type') or 'Unknown'
            feed_version = feed.findtext('version') or 'N/A'
            is_syncing   = feed.find('currently_syncing') is not None
            status["feeds"].append({
                "type": feed_type,
                "version": feed_version,
                "syncing": is_syncing
            })
            if is_syncing:
                status["syncing"] = True
    except Exception:
        pass
    return status


def _wait_for_configs(gmp, max_wait_seconds=900, poll_interval=30, log_fn=None) -> Optional[str]:
    """
    Poll GVM until scan configs appear (after feed sync completes).
    Important: GVM takes extra time to COMMIT NVTs to the DB after the sync
    process ends, so we extend the wait by 5 minutes after sync stops.
    Returns the best available config UUID, or None if timed out.
    """
    start = time.time()
    sync_finished_at: Optional[float] = None
    # Extra grace window after sync reports complete (DB commit takes time)
    POST_SYNC_GRACE = 300  # 5 minutes

    while True:
        cfg_id = _discover_scan_config(gmp)
        if cfg_id:
            return cfg_id

        elapsed   = int(time.time() - start)
        remaining = max_wait_seconds - elapsed

        feed_status   = _get_feed_sync_status(gmp)
        syncing_feeds = [f["type"] for f in feed_status["feeds"] if f["syncing"]]
        still_syncing = bool(syncing_feeds)

        # Track the moment sync reports as done
        if not still_syncing and sync_finished_at is None:
            sync_finished_at = time.time()
            if log_fn:
                log_fn("  Feed sync reported complete — waiting up to 5 more min for DB commit...", "info")

        # Decide whether to keep waiting
        if still_syncing:
            # While syncing: respect the original max_wait_seconds
            if elapsed >= max_wait_seconds:
                return None  # Timed out while still syncing
        else:
            # After sync stops: give POST_SYNC_GRACE seconds for DB commit
            time_since_sync_done = time.time() - (sync_finished_at or time.time())
            if time_since_sync_done >= POST_SYNC_GRACE:
                return None  # Timed out after sync

        status_str = ', '.join(syncing_feeds) if still_syncing else 'complete (DB commit pending)'
        msg = (f"  Waiting for GVM config availability... "
               f"({elapsed}s total) Feed: {status_str}")
        if log_fn:
            log_fn(msg, "info")

        time.sleep(poll_interval)

    return None  # Unreachable


# ── Main scanner class ────────────────────────────────────────────────────────
class OpenVASScanner:
    """
    Talks to Greenbone Community Edition (Docker) via GMP.
    Auto-detects whether Docker is up; falls back to demo mode if not.
    Dynamically discovers scan config UUIDs instead of relying on hardcoded values.
    """

    def __init__(self, openvas_path=None, timeout: int = 3600):
        self.timeout      = timeout
        self.scan_results = {}
        self._docker_up   = False
        self.available    = False

        # Cached UUIDs — discovered once on first scan, reused for all subsequent
        # hosts so we don't repeat the 15-min wait for every target
        self._config_id     : Optional[str] = None
        self._scanner_id    : Optional[str] = None
        self._port_list_id  : Optional[str] = None

        if GVM_AVAILABLE and _gvm_reachable():
            self._docker_up = True
            self.available  = True

    def is_available(self) -> bool:
        return self.available

    # ── Public entry point ───────────────────────────────────────────────────
    def scan_target(self, target: str, ports=None, demo_mode: bool = False,
                    log_fn=None) -> Dict[str, Any]:
        if demo_mode or not self.available:
            return self._demo_scan(target, ports)
        try:
            return self._scan_via_gmp(target, log_fn=log_fn)
        except Exception as e:
            return {
                "error":           f"GVM scan error: {str(e)}",
                "vulnerabilities": [],
                "demo_mode":       False,
                "source":          "GVM/OpenVAS (Docker)",
            }

    # ── Real GMP scan ────────────────────────────────────────────────────────
    def _scan_via_gmp(self, target: str, log_fn=None) -> Dict[str, Any]:
        """
        Run a real OpenVAS scan via GMP protocol.

        KEY FIX: Each network operation opens a FRESH TLSConnection so no
        single socket ever needs to live longer than one round-trip.
        The original code reused one connection for the entire scan lifetime,
        causing 'The read operation timed out' after GVM_TIMEOUT=120 s — right
        in the middle of a multi-minute scan polling loop.
        """

        def _fresh_gmp():
            """Return a new authenticated Gmp context manager."""
            conn = TLSConnection(hostname=GVM_HOST, port=GVM_PORT, timeout=GVM_TIMEOUT)
            gmp  = Gmp(conn, transform=EtreeTransform())
            gmp.connect()
            gmp.authenticate(GVM_USER, GVM_PASSWORD)
            return gmp

        # ── Phase 1: Discover UUIDs + create target + start task ─────────────
        # All happens in one short-lived connection (< 5 s total).
        with _fresh_gmp() as gmp:
            # Discover / cache scan config UUID
            config_id = self._config_id or _discover_scan_config(gmp)

            if not config_id:
                feed_status = _get_feed_sync_status(gmp)
                syncing = [f["type"] for f in feed_status["feeds"] if f["syncing"]]
                if syncing and log_fn:
                    log_fn(f"  NVT feed syncing ({', '.join(syncing)}) — waiting up to 15 min...", "warn")
                    log_fn("  Monitor at http://localhost:9392", "muted")
                elif log_fn:
                    log_fn("  Feed sync done but configs not in DB yet — waiting up to 5 min...", "warn")
                config_id = _wait_for_configs(gmp, max_wait_seconds=900, poll_interval=30, log_fn=log_fn)

            if not config_id:
                raise RuntimeError(
                    "GVM timed out waiting for scan configs. "
                    "Try: docker restart greenbone  and wait 10 min."
                )

            if not self._config_id:
                self._config_id = config_id

            if not self._scanner_id:
                self._scanner_id = _discover_scanner(gmp)
            if not self._port_list_id:
                self._port_list_id = _discover_port_list(gmp)

            scanner_id   = self._scanner_id
            port_list_id = self._port_list_id

            ts        = int(time.time())
            tgt_name  = f"CyberRecon-{target}-{ts}"
            task_name = f"CyberRecon-Task-{target}-{ts}"

            # Create target
            tgt_resp  = gmp.create_target(name=tgt_name, hosts=[target], port_list_id=port_list_id)
            target_id = tgt_resp.get("id")
            if not target_id:
                raise RuntimeError("GVM: failed to create scan target")

            # Create task
            task_resp = gmp.create_task(
                name=task_name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
            )
            task_id = task_resp.get("id")
            if not task_id:
                import xml.etree.ElementTree as _ET
                raise RuntimeError(
                    f"GVM: failed to create scan task. "
                    f"Response: {_ET.tostring(task_resp, encoding='unicode')[:300]}"
                )

            # Start task
            start_resp = gmp.start_task(task_id)
            rid_el     = start_resp.find("report_id")
            report_id  = rid_el.text if rid_el is not None else None

        if log_fn:
            log_fn(f"  OpenVAS task started (ID: {task_id[:8]}...) — polling every 30s", "info")

        # ── Phase 2: Poll for completion — FRESH connection every tick ────────
        # This is the critical fix: each get_task() call opens and closes its
        # own TLS connection so the 120-second socket timeout never triggers.
        deadline          = time.time() + self.timeout
        poll_count        = 0
        consecutive_errs  = 0
        MAX_CONSEC_ERRS   = 10   # give up polling after 10 back-to-back failures
        last_pct          = -1
        final_status      = "Unknown"

        while time.time() < deadline:
            time.sleep(30)
            poll_count += 1
            try:
                with _fresh_gmp() as gmp:
                    info        = gmp.get_task(task_id)
                    status_el   = info.find(".//status")
                    status_text = status_el.text if status_el is not None else "Unknown"
                    pct_el      = info.find(".//progress")
                    try:
                        pct = int(pct_el.text) if pct_el is not None else -1
                    except (ValueError, TypeError):
                        pct = -1

                    consecutive_errs = 0  # reset on success

                    if pct != last_pct and pct >= 0 and log_fn:
                        log_fn(f"  OpenVAS scan progress: {pct}% ({status_text})", "info")
                        last_pct = pct
                    elif log_fn and poll_count % 4 == 0:
                        log_fn(f"  OpenVAS still running... poll #{poll_count} ({status_text})", "muted")

                    final_status = status_text
                    if status_text in ("Done", "Stopped"):
                        if log_fn:
                            log_fn(f"  OpenVAS scan finished: {status_text}", "good")
                        break

            except Exception as poll_err:
                consecutive_errs += 1
                if log_fn:
                    log_fn(
                        f"  OpenVAS poll #{poll_count} error "
                        f"({consecutive_errs}/{MAX_CONSEC_ERRS}): {poll_err}",
                        "warn"
                    )
                if consecutive_errs >= MAX_CONSEC_ERRS:
                    if log_fn:
                        log_fn(
                            f"  {MAX_CONSEC_ERRS} consecutive poll failures — "
                            "fetching partial results and continuing scan",
                            "warn"
                        )
                    break
                time.sleep(15)  # brief back-off before retrying

        # ── Phase 3: Resolve report ID + fetch results ────────────────────────
        with _fresh_gmp() as gmp:
            if not report_id:
                info      = gmp.get_task(task_id)
                lr        = info.find(".//last_report/report")
                report_id = lr.get("id") if lr is not None else None

            if not report_id:
                raise RuntimeError("GVM: could not retrieve report ID after scan completed")

            report = gmp.get_report(
                report_id,
                filter_string="min_qod=70 apply_overrides=0 rows=-1",
                ignore_pagination=True,
                details=True,
            )
            vulns = self._parse_gmp_report(report, target)

        # ── Phase 4: Cleanup ──────────────────────────────────────────────────
        try:
            with _fresh_gmp() as gmp:
                gmp.delete_task(task_id, ultimate=False)
                gmp.delete_target(target_id, ultimate=False)
        except Exception:
            pass  # cleanup failure is non-fatal

        return {
            "target":          target,
            "vulnerabilities": vulns,
            "count":           len(vulns),
            "timestamp":       time.time(),
            "demo_mode":       False,
            "source":          "GVM/OpenVAS (Docker)",
        }

    # ── XML report parser ────────────────────────────────────────────────────
    def _parse_gmp_report(self, report_xml, target: str) -> List[OpenVASVulnerability]:
        vulns   = []
        results = report_xml.findall(".//results/result")

        for result in results:
            try:
                name = (result.findtext("name") or "").strip()
                if not name:
                    continue

                # Skip log / false-positive entries
                threat = (result.findtext(".//threat") or "").lower()
                if threat in ("log", "false positive", ""):
                    continue

                host_el  = result.find("host")
                host     = (host_el.text or target).strip() if host_el is not None else target

                port_raw = result.findtext("port") or "general/tcp"
                port_num = port_raw.split("/")[0] if "/" in port_raw else port_raw
                proto    = port_raw.split("/")[1] if "/" in port_raw else "tcp"

                try:
                    cvss = float(result.findtext(".//severity") or "0.0")
                except ValueError:
                    cvss = 0.0

                oid_el = result.find(".//nvt")
                oid    = oid_el.get("oid", "") if oid_el is not None else ""

                desc = (result.findtext(".//description") or "")[:500]
                sol  = (result.findtext(".//solution")    or "")[:300]

                vulns.append(OpenVASVulnerability(
                    oid=oid, name=name,
                    severity=_cvss_to_severity(cvss), cvss_score=cvss,
                    host=host, port=port_num, service=proto,
                    description=desc,
                    created=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    modified=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    solution=sol or None,
                ))
            except Exception:
                continue

        return vulns

    # ── Demo / fallback mode ─────────────────────────────────────────────────
    def _demo_scan(self, target: str, ports=None) -> Dict[str, Any]:
        p = "443" if "443" in str(ports) else "80"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        demo_vulns = [
            OpenVASVulnerability(
                oid="1.3.6.1.4.1.25623.1.0.1234",
                name="[DEMO] Missing HTTP Security Headers (X-Frame-Options)",
                severity="MEDIUM", cvss_score=5.3,
                host=target, port=p, service="http",
                description="[DEMO MODE] X-Frame-Options header is absent. "
                            "Start Docker + Greenbone for real results.",
                created=now, modified=now,
                solution="Add 'X-Frame-Options: DENY' to HTTP responses.",
            ),
            OpenVASVulnerability(
                oid="1.3.6.1.4.1.25623.1.0.5678",
                name="[DEMO] SSL/TLS: Deprecated TLSv1.0 Protocol Detected",
                severity="HIGH", cvss_score=7.5,
                host=target, port="443", service="https",
                description="[DEMO MODE] TLSv1.0 accepted. "
                            "Start Docker + Greenbone for real results.",
                created=now, modified=now,
                solution="Disable TLS 1.0. Use TLS 1.2 or higher.",
            ),
            OpenVASVulnerability(
                oid="1.3.6.1.4.1.25623.1.0.9012",
                name="[DEMO] Missing Content-Security-Policy Header",
                severity="MEDIUM", cvss_score=4.7,
                host=target, port=p, service="http",
                description="[DEMO MODE] CSP header missing. "
                            "Start Docker + Greenbone for real results.",
                created=now, modified=now,
                solution="Add a Content-Security-Policy response header.",
            ),
        ]
        return {
            "target":          target,
            "vulnerabilities": demo_vulns,
            "count":           len(demo_vulns),
            "timestamp":       time.time(),
            "demo_mode":       True,
            "source":          "Demo (Docker not running — pip install python-gvm + start Greenbone)",
        }


# ── Report generators (kept for compatibility) ────────────────────────────────
class OpenVASReportGenerator:
    @staticmethod
    def generate_json_report(results: Dict[str, Any]) -> str:
        data = {
            "scan_summary":    {"target": results.get("target"), "total_vulns": results.get("count", 0)},
            "vulnerabilities": [],
        }
        for v in results.get("vulnerabilities", []):
            is_obj = isinstance(v, OpenVASVulnerability)
            data["vulnerabilities"].append({
                "name":        v.name        if is_obj else v.get("name"),
                "severity":    v.severity    if is_obj else v.get("severity"),
                "cvss_score":  v.cvss_score  if is_obj else v.get("cvss_score"),
                "port":        v.port        if is_obj else v.get("port"),
                "service":     v.service     if is_obj else v.get("service"),
                "description": v.description if is_obj else v.get("description"),
            })
        return json.dumps(data, indent=2)

    @staticmethod
    def generate_html_summary(results: Dict[str, Any]) -> str:
        vulns  = results.get("vulnerabilities", [])
        groups = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in vulns:
            sev = (v.severity if isinstance(v, OpenVASVulnerability) else v.get("severity", "LOW"))
            if sev in groups:
                groups[sev] += 1
        ranges = {"CRITICAL": "9.0-10.0", "HIGH": "7.0-8.9", "MEDIUM": "4.0-6.9", "LOW": "0.1-3.9"}
        rows = "".join(
            f"<tr><td>{s}</td><td>{groups[s]}</td><td>{ranges[s]}</td></tr>"
            for s in groups
        )
        return (f"<div class='openvas-report'><h3>OpenVAS Report</h3>"
                f"<p><b>Target:</b> {results.get('target')} &nbsp; "
                f"<b>Total:</b> {results.get('count', 0)}</p>"
                f"<table>{rows}</table></div>")


if __name__ == "__main__":
    scanner = OpenVASScanner()
    if scanner.is_available():
        print(f"[+] Greenbone Docker detected on {GVM_HOST}:{GVM_PORT} — real scans enabled")
        # Check if feed is ready
        conn = TLSConnection(hostname=GVM_HOST, port=GVM_PORT, timeout=15)
        with Gmp(conn, transform=EtreeTransform()) as gmp:
            gmp.authenticate(GVM_USER, GVM_PASSWORD)
            cfg = _discover_scan_config(gmp)
            if cfg:
                print(f"[+] Scan config ready: {cfg}")
            else:
                print("[!] No scan configs available yet — NVT feed still syncing.")
                print("[i] Wait 5-10 more minutes, then retry. Check: http://localhost:9392")
    else:
        reasons = []
        if not GVM_AVAILABLE:
            reasons.append("python-gvm not installed  ->  pip install python-gvm")
        if not _gvm_reachable():
            reasons.append("Docker container not running  ->  docker run -d --name greenbone "
                           "-p 9390:9390 -p 9392:9392 securecompliance/gvm")
        for r in reasons:
            print(f"[!] {r}")
        print("[i] Running in DEMO mode until Docker is started.")
