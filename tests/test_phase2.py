"""Tests for findings persistence / triage / diff, authenticated-scan plumbing, the TLS
cipher parser, EPSS caching, explicit target ports and the web dashboard API guards.

All offline.   python -m unittest discover -s tests -v   (after: pip install -e .)
"""
import json
import os
import sys
import tempfile
import time
import unittest

import danishrecon

APP_DIR = os.path.dirname(os.path.abspath(danishrecon.__file__))   # the installed package

if "danishrecon.scan_core" not in sys.modules:
    os.chdir(tempfile.mkdtemp(prefix="cyberrecon_tests_"))
os.environ["DISABLE_GEMINI"] = "true"

from danishrecon import scan_core as crp  # noqa: E402
from danishrecon import cve_lookup  # noqa: E402
from danishrecon import recon_tools  # noqa: E402
from danishrecon.findings import Finding  # noqa: E402


def _finding(title="SQL injection", url="http://t/p?id=1", param="id", **kw):
    return Finding(title=title, severity=kw.pop("severity", "HIGH"), source="nuclei-dast",
                   category=kw.pop("category", "sqli"), url=url, parameter=param, **kw)


class EngineHasNoGuiDependency(unittest.TestCase):
    def test_core_does_not_import_qt(self):
        import subprocess
        code = ("import sys, os, tempfile; os.chdir(tempfile.mkdtemp()); "
                "from danishrecon import scan_core, cli; print(any(m.startswith('PyQt5') for m in sys.modules))")
        out = subprocess.run([sys.executable, "-W", "ignore", "-c", code], capture_output=True, text=True, timeout=120)
        self.assertEqual(out.stdout.strip().splitlines()[-1], "False", out.stderr[-400:])


class FindingsStore(unittest.TestCase):
    def _scan(self, target, findings, status="complete"):
        eng = crp.ScanEngine(target, "Quick", {})
        for f in findings:
            eng._add_finding(f)
        if status == "complete":
            crp.DB.finish_scan(eng.scan_id, {})
        return eng

    def test_findings_are_persisted_with_default_triage(self):
        eng = self._scan("store1.example", [_finding(), _finding(title="XSS", category="xss", param="q")])
        rows = crp.DB.get_findings(eng.scan_id)
        self.assertEqual([r["title"] for r in rows], ["SQL injection", "XSS"])
        self.assertTrue(all(r["triage"] == "open" and r["target"] == "store1.example" for r in rows))
        listed = next(s for s in crp.DB.list_scans() if s["id"] == eng.scan_id)
        self.assertEqual((listed["findings"], listed["confirmed_high"]), (2, 2))

    def test_triage_is_per_target_and_survives_rescans(self):
        a = self._scan("triage.example", [_finding()])
        fp = crp.DB.get_findings(a.scan_id)[0]["fingerprint"]
        crp.DB.set_triage("triage.example", fp, "false_positive", "checked manually")
        b = self._scan("triage.example", [_finding()])
        other = self._scan("other.example", [_finding()])
        self.assertEqual(crp.DB.get_findings(b.scan_id)[0]["triage"], "false_positive")
        self.assertEqual(crp.DB.get_findings(b.scan_id)[0]["triage_note"], "checked manually")
        self.assertEqual(crp.DB.get_findings(other.scan_id)[0]["triage"], "open")
        with self.assertRaises(ValueError):
            crp.DB.set_triage("triage.example", fp, "whatever")

    def test_diff_reports_new_fixed_and_persisting(self):
        old = self._scan("diff.example", [_finding(), _finding(title="XSS", category="xss", param="q")])
        new = self._scan("diff.example", [_finding(), _finding(title="Open redirect", category="redirect", param="next")])
        self.assertEqual(crp.DB.previous_scan_id("diff.example", new.scan_id), old.scan_id)
        d = crp.DB.diff_scans(old.scan_id, new.scan_id)
        self.assertEqual([f["title"] for f in d["new"]], ["Open redirect"])
        self.assertEqual([f["title"] for f in d["fixed"]], ["XSS"])
        self.assertEqual([f["title"] for f in d["persisting"]], ["SQL injection"])
        new._diff_against_previous()
        self.assertEqual((len(new.data["diff"]["new"]), len(new.data["diff"]["fixed"]), new.data["diff"]["persisting"]), (1, 1, 1))

    def test_unfinished_scans_are_not_used_as_baseline(self):
        self._scan("baseline.example", [_finding()], status="running")
        later = self._scan("baseline.example", [_finding()])
        self.assertIsNone(crp.DB.previous_scan_id("baseline.example", later.scan_id))


class ExplicitTargetPort(unittest.TestCase):
    def test_seed_url_parsing(self):
        seed = crp.seed_url_from_target
        self.assertEqual(seed("http://app.local:3000/shop?x=1"), ("http", "app.local", 3000))
        self.assertEqual(seed("https://app.local"), ("https", "app.local", 443))
        self.assertEqual(seed("127.0.0.1:8443"), ("https", "127.0.0.1", 8443))
        self.assertEqual(seed("127.0.0.1:8080/x"), ("http", "127.0.0.1", 8080))
        for none in ("example.com", "10.0.0.0/24", "ftp://example.com", "http://h:99999", ""):
            self.assertIsNone(seed(none), none)

    def test_port_from_url_is_scanned_even_when_nmap_did_not_cover_it(self):
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]
        try:
            eng = crp.ScanEngine(f"http://127.0.0.1:{port}/app", "Quick", {})
            self.assertEqual(eng.target, "127.0.0.1")
            services = eng._ensure_seed_service([{"host": "127.0.0.1", "port": "22", "service": "ssh"}])
            self.assertIn(f"http://127.0.0.1:{port}", eng._web_base_urls(services))
            # an already-detected port is not duplicated, but is treated as HTTP
            again = eng._ensure_seed_service([{"host": "127.0.0.1", "port": str(port), "service": "unknown"}])
            self.assertEqual(len(again), 1)
            self.assertEqual(again[0]["service"], "http")
        finally:
            srv.close()

    def test_unreachable_seed_port_is_not_invented(self):
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        eng = crp.ScanEngine(f"http://127.0.0.1:{port}", "Quick", {})
        self.assertEqual(eng._ensure_seed_service([]), [])


class AuthenticatedScanPlumbing(unittest.TestCase):
    def test_auth_headers(self):
        eng = crp.ScanEngine("127.0.0.1", "Quick", {"auth_cookie": " session=abc ", "auth_bearer": "tok",
                                                    "auth_headers": ["X-Api-Key: k", "garbage"]})
        self.assertEqual(eng._auth_headers(), ["Cookie: session=abc", "Authorization: Bearer tok", "X-Api-Key: k"])
        self.assertEqual(crp.ScanEngine("127.0.0.1", "Quick", {})._auth_headers(), [])

    def test_header_args_strip_line_breaks(self):
        self.assertEqual(recon_tools._header_args(["Cookie: a=b\r\nX-Injected: 1", "nocolon"]),
                         ["-H", "Cookie: a=b  X-Injected: 1"])

    def test_login_must_be_in_scope(self):
        res = recon_tools.login_for_cookie("https://evil.example/login", "u=a&p=b", {"target.example"})
        self.assertFalse(res["ok"])
        self.assertIn("outside the scan scope", res["error"])

    def test_dast_passes_auth_and_replays_post_forms(self):
        eng = crp.ScanEngine("127.0.0.1", "Quick", {"auth_cookie": "session=abc"})
        eng.data["hosts"] = ["127.0.0.1"]
        eng.data["param_urls"] = ["http://127.0.0.1/p?id=1"]
        eng._post_requests = ['{"request":{"method":"POST","endpoint":"http://127.0.0.1/feedback","body":"msg=x"}}']
        calls = []

        def fake(urls=None, dast=False, headers=None, input_jsonl=None, **kw):
            calls.append({"urls": urls, "headers": headers, "posts": input_jsonl})
            entry = {"template-id": "reflected-xss", "matched-at": "http://127.0.0.1/feedback" if input_jsonl else "http://127.0.0.1/p?id=1",
                     "fuzzing_parameter": "msg" if input_jsonl else "id", "matcher-name": "m",
                     "info": {"name": "Reflected Cross-Site Scripting", "severity": "medium"}}
            return {"available": True, "status": "ok", "seconds": 1.0, "findings": [recon_tools.parse_nuclei_entry(entry)]}
        saved = recon_tools.nuclei_run, recon_tools.find_tool
        recon_tools.nuclei_run, recon_tools.find_tool = fake, lambda n: "/bin/" + n
        try:
            eng.stage_dast_scan([])
        finally:
            recon_tools.nuclei_run, recon_tools.find_tool = saved
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(c["headers"] == ["Cookie: session=abc"] for c in calls))
        self.assertEqual(calls[1]["posts"], eng._post_requests)
        by_param = {f["parameter"]: f for f in eng.data["findings"]}
        self.assertEqual(set(by_param), {"id", "msg"})
        self.assertTrue(by_param["msg"]["evidence"].startswith("POST body"))

    def test_session_material_is_never_exported(self):
        eng = crp.ScanEngine("127.0.0.1", "Quick", {"auth_cookie": "session=SECRETCOOKIE"})
        eng._post_requests = ['{"request":{"raw":"Cookie: session=SECRETCOOKIE"}}']
        self.assertNotIn("SECRETCOOKIE", json.dumps(eng.data))


class TlsCipherParser(unittest.TestCase):
    SAMPLE = """PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
|     compressors:
|       NULL
|     cipher preference: server
|     warnings:
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - F
|     cipher preference: server
|_  least strength: F
"""

    def test_weak_suites_and_warnings(self):
        r = crp.parse_ssl_enum_ciphers(self.SAMPLE)
        self.assertEqual(r["least_strength"], "F")
        self.assertEqual(r["weak_ciphers"], ["TLSv1.0 TLS_RSA_WITH_3DES_EDE_CBC_SHA (C)",
                                             "TLSv1.2 TLS_RSA_WITH_RC4_128_SHA (F)"])
        self.assertEqual(r["warnings"], ["64-bit block cipher 3DES vulnerable to SWEET32 attack"])

    def test_strong_configuration_has_nothing_to_report(self):
        strong = "| ssl-enum-ciphers:\n|   TLSv1.3:\n|     ciphers:\n|       TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A\n|_  least strength: A\n"
        self.assertEqual(crp.parse_ssl_enum_ciphers(strong), {"least_strength": "A", "weak_ciphers": [], "warnings": []})


class Epss(unittest.TestCase):
    def test_scores_come_from_cache_without_network(self):
        cache_dir = tempfile.mkdtemp()
        with open(os.path.join(cache_dir, "epss.json"), "w", encoding="utf-8") as fh:
            json.dump({"CVE-2021-41773": [0.97, time.time()]}, fh)
        original = cve_lookup.requests.get
        cve_lookup.requests.get = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used"))
        try:
            self.assertEqual(cve_lookup.epss_scores(["cve-2021-41773", "not-a-cve"], cache_dir), {"CVE-2021-41773": 0.97})
        finally:
            cve_lookup.requests.get = original

    def test_offline_returns_empty_instead_of_raising(self):
        original = cve_lookup.requests.get

        def boom(*a, **k):
            raise ConnectionError("offline")
        cve_lookup.requests.get = boom
        try:
            self.assertEqual(cve_lookup.epss_scores(["CVE-2020-0001"], tempfile.mkdtemp()), {})
        finally:
            cve_lookup.requests.get = original

    def test_high_epss_is_shown_in_label(self):
        self.assertIn("EPSS 97%", Finding(title="x", cve="CVE-1", epss=0.97).label())
        self.assertNotIn("EPSS", Finding(title="x", cve="CVE-1", epss=0.01).label())


class WebDashboardGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
            from danishrecon.webapp import server
        except Exception as e:           # fastapi/httpx not installed
            raise unittest.SkipTest(f"web dashboard dependencies missing: {e}")
        server.core = crp
        cls.server = server
        cls.client = TestClient(server.app, base_url=f"http://127.0.0.1:{server.PORT}")
        cls.auth = {"X-Scan-Token": server.TOKEN}

    def test_api_requires_token_and_loopback_host(self):
        c = self.client
        self.assertEqual(c.get("/api/scans").status_code, 403)
        self.assertEqual(c.get("/api/scans", headers={"X-Scan-Token": "wrong"}).status_code, 403)
        self.assertEqual(c.get("/api/scans", headers={**self.auth, "Host": "attacker.example"}).status_code, 403)
        self.assertEqual(c.get("/", headers={"Host": "attacker.example"}).status_code, 403)
        self.assertEqual(c.get("/api/scans", headers=self.auth).status_code, 200)

    def test_page_gets_the_token_and_a_csp(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(self.server.TOKEN, r.text)
        self.assertIn("frame-ancestors 'none'", r.headers["content-security-policy"])

    def test_scan_start_needs_authorization_and_a_valid_target(self):
        c = self.client
        r = c.post("/api/scans", json={"target": "example.com"}, headers=self.auth)
        self.assertEqual(r.status_code, 400)
        self.assertIn("authorized", r.json()["detail"])
        r = c.post("/api/scans", json={"target": "--script=evil", "authorized": True}, headers=self.auth)
        self.assertEqual(r.status_code, 400)
        r = c.post("/api/scans", json={"target": "example.com", "authorized": True, "profile": "Nope"}, headers=self.auth)
        self.assertEqual(r.status_code, 400)

    def test_scan_detail_and_triage(self):
        eng = crp.ScanEngine("web.example", "Quick", {})
        eng._add_finding(_finding())
        crp.DB.finish_scan(eng.scan_id, {})
        c = self.client
        d = c.get(f"/api/scans/{eng.scan_id}", headers=self.auth).json()
        self.assertEqual((d["scan"]["target"], len(d["findings"]), d["counts"]["HIGH"]), ("web.example", 1, 1))
        fp = d["findings"][0]["fingerprint"]
        bad = c.post("/api/triage", json={"target": "web.example", "fingerprint": fp, "status": "x"}, headers=self.auth)
        self.assertEqual(bad.status_code, 400)
        ok = c.post("/api/triage", json={"target": "web.example", "fingerprint": fp, "status": "false_positive"}, headers=self.auth)
        self.assertEqual(ok.status_code, 200)
        d = c.get(f"/api/scans/{eng.scan_id}", headers=self.auth).json()
        self.assertEqual((d["findings"][0]["triage"], d["counts"]["HIGH"]), ("false_positive", 0))
        self.assertEqual(c.get("/api/scans/999999", headers=self.auth).status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
