"""Regression tests for the Phase 0 "trustworthy results" fixes.

Run from the CyberRecon-Pro folder:

    python -m unittest discover -s tests -v   (after: pip install -e .)

Everything here is offline: the only network traffic goes to throw-away servers that the
tests start on 127.0.0.1.
"""
import datetime
import os
import socket
import ssl
import sys
import tempfile
import threading
import unittest

import danishrecon

APP_DIR = os.path.dirname(os.path.abspath(danishrecon.__file__))   # the installed package

# The app writes its database/reports to ./results - keep that out of the real project.
_TMP = tempfile.mkdtemp(prefix="cyberrecon_tests_")
os.chdir(_TMP)
os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["DISABLE_GEMINI"] = "true"

from danishrecon import scan_core as crp  # noqa: E402
from danishrecon import cryptography_analyzer as ca  # noqa: E402
from danishrecon import nuclei_scanner  # noqa: E402


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TargetValidation(unittest.TestCase):
    def test_accepts_and_normalises(self):
        cases = {
            "example.com": "example.com",
            "https://Example.com/": "example.com",
            "http://example.com:8080/path?x=1": "example.com",
            "192.168.1.10": "192.168.1.10",
            "10.0.0.0/24": "10.0.0.0/24",
            "http://127.0.0.1:8080/": "127.0.0.1",
            "sub.domain.co.in": "sub.domain.co.in",
        }
        for raw, expected in cases.items():
            self.assertEqual(crp.normalize_target(raw), expected, raw)

    def test_rejects_option_injection_and_garbage(self):
        for bad in ["", "   ", "-oN /tmp/x", "--script=evil", "example.com; rm -rf /",
                    "a b.com", "999.1.1.1", "10.0.0.0/99", "user@host.com", "$(whoami).com",
                    "exa mple.com", "host`id`.com"]:
            with self.assertRaises(ValueError, msg=bad):
                crp.normalize_target(bad)


class CveMatching(unittest.TestCase):
    def test_open_port_alone_never_yields_a_cve(self):
        for svc in crp.CVE_DB:
            self.assertEqual(crp.matched_cves(svc, "", ""), [], svc)

    def test_unrelated_product_does_not_match(self):
        self.assertEqual(crp.matched_cves("http", "BaseHTTPServer 0.6 Python 3.11.9"), [])
        self.assertEqual(crp.matched_cves("http", "nginx 1.21.3"), [])
        self.assertEqual(crp.matched_cves("http", "Apache httpd 2.4.58"), [])
        self.assertEqual(crp.matched_cves("https", "nginx"), [])
        self.assertEqual(crp.matched_cves("ssh", "OpenSSH 9.6p1 Ubuntu"), [])
        self.assertEqual(crp.matched_cves("ftp", "vsftpd 3.0.3"), [])
        self.assertEqual(crp.matched_cves("https", "OpenSSL 1.0.1g"), [])

    def test_vulnerable_versions_match(self):
        ids = lambda *a: [c["cve"] for c in crp.matched_cves(*a)]
        self.assertEqual(ids("http", "Apache httpd 2.4.49 (Unix)"), ["CVE-2021-41773", "CVE-2021-42013"])
        self.assertEqual(ids("http", "Apache httpd 2.4.50"), ["CVE-2021-42013"])
        self.assertEqual(ids("https", "Apache httpd 2.4.49"), ["CVE-2021-41773", "CVE-2021-42013"])
        self.assertEqual(ids("ftp", "vsftpd 2.3.4"), ["CVE-2011-2523"])
        self.assertEqual(ids("ssh", "OpenSSH 7.4 (protocol 2.0)"), ["CVE-2018-15473"])
        self.assertEqual(ids("https", "Apache httpd 2.2.22 OpenSSL/1.0.1e"), ["CVE-2014-0160"])

    def test_cve_named_by_a_tool_matches(self):
        banner = "smb-vuln-ms17-010: VULNERABLE: IDs: CVE:CVE-2017-0144"
        self.assertEqual([c["cve"] for c in crp.matched_cves("smb", "", banner)], ["CVE-2017-0144"])


def _make_cert(days_valid):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit-test.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(days=400)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(now + datetime.timedelta(days=days_valid))
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp(dir=_TMP)
    cert_p, key_p = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    with open(cert_p, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_p, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    return cert_p, key_p


class _TlsServer:
    """Minimal TLS listener on 127.0.0.1 that completes handshakes and closes."""

    def __init__(self, days_valid):
        cert_p, key_p = _make_cert(days_valid)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_p, key_p)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.alive = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while self.alive:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(conn, server_side=True):
                    pass
            except Exception:
                pass

    def close(self):
        self.alive = False
        self.sock.close()


class TlsAnalysis(unittest.TestCase):
    def test_unreachable_port_reports_nothing_simulated(self):
        r = ca.CryptographyAnalyzer("127.0.0.1", _free_port()).analyze()
        self.assertFalse(r["reachable"])
        self.assertFalse(r["certificate_analysis"]["valid"])
        self.assertEqual(r["certificate_analysis"]["issuer"], "Unknown")
        self.assertEqual(r["overall_rating"]["grade"], "N/A")
        self.assertEqual(r["vulnerabilities"], [])
        self.assertNotIn("Let's Encrypt", str(r))

    def test_self_signed_certificate_is_read_and_flagged_untrusted(self):
        srv = _TlsServer(days_valid=200)
        try:
            info = ca.fetch_certificate("127.0.0.1", srv.port)
            self.assertTrue(info["reachable"])
            self.assertFalse(info["trusted"])
            self.assertFalse(info["expired"])
            self.assertIn("unit-test.local", info["subject"])
            self.assertTrue(190 <= info["days_remaining"] <= 200)
            r = ca.CryptographyAnalyzer("127.0.0.1", srv.port).analyze()
            self.assertTrue(r["reachable"])
            self.assertEqual(r["overall_rating"]["grade"], "F")
            self.assertIn("Certificate not trusted", [v["type"] for v in r["vulnerabilities"]])
        finally:
            srv.close()

    def test_expired_certificate_is_detected(self):
        srv = _TlsServer(days_valid=-10)
        try:
            info = ca.fetch_certificate("127.0.0.1", srv.port)
            self.assertTrue(info["expired"])
            r = ca.CryptographyAnalyzer("127.0.0.1", srv.port).analyze()
            self.assertIn("Expired certificate", [v["type"] for v in r["vulnerabilities"]])
        finally:
            srv.close()


class NucleiWrapper(unittest.TestCase):
    def test_missing_binary_produces_no_findings(self):
        original = nuclei_scanner.find_nuclei
        nuclei_scanner.find_nuclei = lambda: None
        try:
            s = nuclei_scanner.NucleiScanner("http://127.0.0.1:1", log_callback=lambda *a: None,
                                             result_callback=lambda *a: None)
            self.assertEqual(s.run(), [])
        finally:
            nuclei_scanner.find_nuclei = original


def _stub_engine(target="127.0.0.1"):
    """A ScanEngine whose stages are replaced by instant no-ops."""
    eng = crp.ScanEngine(target, "Quick", {})
    for name in dir(eng):
        if name.startswith("stage_"):
            setattr(eng, name, lambda *a, **k: None)
    eng.stage_report = lambda graph: "report.html"
    eng.export_json = lambda: "scan.json"
    eng.export_csv = lambda: "vulns.csv"
    eng.export_markdown = lambda: "report.md"
    return eng


def _status(scan_id):
    return crp.DB.conn.execute("select status from scans where id=?", (scan_id,)).fetchone()[0]


class EngineLifecycle(unittest.TestCase):
    def test_invalid_target_is_rejected_before_a_scan_row_exists(self):
        before = crp.DB.conn.execute("select count(*) from scans").fetchone()[0]
        with self.assertRaises(ValueError):
            crp.ScanEngine("--script=evil", "Quick", {})
        after = crp.DB.conn.execute("select count(*) from scans").fetchone()[0]
        self.assertEqual(before, after)

    def test_clean_run_completes(self):
        eng = _stub_engine()
        done = []
        eng.scan_complete.connect(lambda d: done.append(d))
        eng.run()
        self.assertEqual(_status(eng.scan_id), "complete")
        self.assertEqual(len(done), 1)

    def test_failing_stage_does_not_kill_the_scan(self):
        eng = _stub_engine()

        def boom(*a, **k):
            raise RuntimeError("stage exploded")
        eng.stage_waf_detection = boom
        done = []
        eng.scan_complete.connect(lambda d: done.append(d))
        eng.run()
        self.assertEqual(_status(eng.scan_id), "complete")
        self.assertEqual(len(done), 1)
        self.assertEqual([e["stage"] for e in eng.data["stage_errors"]], ["waf"])

    def test_stop_finalises_scan_and_notifies_gui(self):
        eng = _stub_engine()
        eng.stage_port_scan = lambda hosts: eng.stop() or []
        stopped, done = [], []
        eng.stopped.connect(lambda: stopped.append(1))
        eng.scan_complete.connect(lambda d: done.append(d))
        eng.run()
        self.assertEqual(_status(eng.scan_id), "stopped")
        self.assertEqual(stopped, [1])
        self.assertEqual(done, [])

    def test_fatal_error_marks_scan_failed_and_releases_gui(self):
        eng = _stub_engine()

        def boom(graph):
            raise RuntimeError("disk full")
        eng.stage_report = boom
        stopped = []
        eng.stopped.connect(lambda: stopped.append(1))
        eng.run()
        self.assertEqual(_status(eng.scan_id), "failed")
        self.assertEqual(stopped, [1])

    def test_stale_running_scans_are_marked_interrupted(self):
        sid = crp.DB.new_scan("stale.example", "Quick")
        self.assertEqual(_status(sid), "running")
        crp.DB.mark_stale_scans()
        self.assertEqual(_status(sid), "interrupted")


class ReportEscaping(unittest.TestCase):
    PAYLOAD = '<script>alert("x")</script>'

    def test_scan_derived_text_is_escaped_in_html_report(self):
        eng = crp.ScanEngine("127.0.0.1", "Quick", {})
        eng._mark_scan_completed()
        p = self.PAYLOAD
        eng.data["vulnerabilities"] = [f"[HIGH] header value {p}"]
        eng.data["hosts"] = [p]
        eng.data["services"] = [f"80/tcp {p}"]
        eng.data["versions"] = [p]
        eng.data["dns_records"] = [f"TXT: {p}"]
        eng.data["exploits"] = [p]
        eng.data["attack_paths"] = [p]
        eng.data["compliance"] = [p]
        eng.data["secret_findings"] = [p]
        eng.data["recommendations"] = [p]
        eng.data["evidence"] = [{"type": p, "title": p, "source_url": p, "status_code": 200,
                                 "method": "GET", "surface": "public", "timestamp": "t"}]
        eng.data["mitre_techniques"] = [{"id": p, "tactic": p, "tech": p, "service": p}]
        eng.data["gemini_analyses"] = {"executive_summary": p, p: p}
        path = eng.stage_report("")
        with open(path, encoding="utf-8") as f:
            html = f.read()
        self.assertNotIn(p, html)
        self.assertNotIn("<SCRIPT>", html)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
