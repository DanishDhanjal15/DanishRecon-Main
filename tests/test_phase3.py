"""Tests for CDN-aware port scanning (fast path, no -sV/-O on CDN edges) and the
nuclei-template category mapping. All offline - nmap and HTTP are stubbed."""
import os
import sys
import tempfile
import unittest

import danishrecon

APP_DIR = os.path.dirname(os.path.abspath(danishrecon.__file__))   # the installed package

if "danishrecon.scan_core" not in sys.modules:
    os.chdir(tempfile.mkdtemp(prefix="cyberrecon_tests_"))
os.environ["DISABLE_GEMINI"] = "true"

from danishrecon import scan_core as crp  # noqa: E402


class _Resp:
    def __init__(self, headers):
        self.headers = headers


class CdnDetection(unittest.TestCase):
    def _with_head(self, headers_or_exc):
        saved = crp.requests.head
        def fake(url, **kw):
            if isinstance(headers_or_exc, Exception):
                raise headers_or_exc
            return _Resp(headers_or_exc)
        crp.requests.head = fake
        self.addCleanup(lambda: setattr(crp.requests, "head", saved))

    def test_detects_cdn_from_server_header(self):
        self._with_head({"Server": "Vercel"})
        eng = crp.ScanEngine("example.com", "Quick", {})
        self.assertEqual(eng._host_behind_cdn("example.com"), "Vercel")

    def test_detects_cdn_from_marker_header(self):
        self._with_head({"Server": "nginx", "cf-ray": "abc123"})
        eng = crp.ScanEngine("example.com", "Quick", {})
        self.assertEqual(eng._host_behind_cdn("example.com"), "Cloudflare")

    def test_plain_server_is_not_a_cdn(self):
        self._with_head({"Server": "Apache/2.4.58"})
        eng = crp.ScanEngine("example.com", "Quick", {})
        self.assertEqual(eng._host_behind_cdn("example.com"), "")

    def test_unreachable_host_is_not_a_cdn(self):
        self._with_head(ConnectionError("down"))
        eng = crp.ScanEngine("example.com", "Quick", {})
        self.assertEqual(eng._host_behind_cdn("example.com"), "")

    def test_port_scan_uses_fast_path_on_cdn_and_skips_os(self):
        self._with_head({"Server": "Vercel"})
        eng = crp.ScanEngine("example.com", "Quick", {"os_detect": True})
        used = {}

        def fake_run_cmd(cmd, timeout=120):
            used["cmd"] = cmd
            used["timeout"] = timeout
            xml = cmd[cmd.index("-oX") + 1]
            with open(xml, "w", encoding="utf-8") as fh:
                fh.write('<?xml version="1.0"?><nmaprun><host><address addr="93.184.216.34" addrtype="ipv4"/>'
                         '<ports><port protocol="tcp" portid="443"><state state="open"/>'
                         '<service name="https"/></port></ports></host></nmaprun>')
            return crp.CmdResult("", status="ok", cmd=cmd)
        eng.run_cmd = fake_run_cmd
        svcs = eng.stage_port_scan(["example.com"])
        self.assertIn("-sT", used["cmd"])            # connect scan, not -sV
        self.assertNotIn("-sV", used["cmd"])
        self.assertNotIn("-O", used["cmd"])          # OS detection skipped on a CDN edge
        self.assertLessEqual(used["timeout"], 200)   # bounded, not the 600s full-scan budget
        self.assertTrue(eng.cdn_detected)
        self.assertEqual([s["port"] for s in svcs], ["443"])

    def test_port_scan_keeps_full_flags_on_non_cdn(self):
        self._with_head({"Server": "Apache/2.4.58"})
        eng = crp.ScanEngine("example.com", "Quick", {"os_detect": True})

        def fake_run_cmd(cmd, timeout=120):
            fake_run_cmd.cmd = cmd
            xml = cmd[cmd.index("-oX") + 1]
            open(xml, "w", encoding="utf-8").write('<?xml version="1.0"?><nmaprun></nmaprun>')
            return crp.CmdResult("", status="ok", cmd=cmd)
        eng.run_cmd = fake_run_cmd
        eng._socket_port_scan = lambda h: []
        eng.stage_port_scan(["example.com"])
        self.assertIn("-sV", fake_run_cmd.cmd)       # version detection kept for a real host
        self.assertIn("-O", fake_run_cmd.cmd)        # OS detection kept
        self.assertFalse(eng.cdn_detected)


class RustScanIntegration(unittest.TestCase):
    def test_greppable_parser(self):
        self.assertEqual(crp.parse_rustscan_ports("1.2.3.4 -> [80,443,8080,22]"), [22, 80, 443, 8080])
        self.assertEqual(crp.parse_rustscan_ports("host -> []"), [])
        self.assertEqual(crp.parse_rustscan_ports("no ports\ngarbage"), [])
        self.assertEqual(crp.parse_rustscan_ports("h -> [70000, 443]"), [443])   # out-of-range dropped

    def test_full_profile_uses_rustscan_then_nmap_sv_on_found_ports(self):
        eng = crp.ScanEngine("example.com", "Full", {})
        eng._host_behind_cdn = lambda h: ""                       # not a CDN
        eng.run_cmd = lambda *a, **k: crp.CmdResult("", status="ok")
        eng._rustscan_ports = lambda host, **k: [22, 80, 443]     # rustscan found these
        captured = {}

        def fake_nmap(cmd, timeout=120):
            captured["cmd"] = cmd
            xml = cmd[cmd.index("-oX") + 1]
            open(xml, "w", encoding="utf-8").write(
                '<?xml version="1.0"?><nmaprun><host><address addr="1.1.1.1" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
                '</ports></host></nmaprun>')
            return crp.CmdResult("", status="ok", cmd=cmd)
        # the first run_cmd call is rustscan (stubbed away); nmap -sV is the real one we inspect
        eng.run_cmd = fake_nmap
        svcs = eng.stage_port_scan(["example.com"])
        self.assertIn("-sV", captured["cmd"])
        self.assertIn("-p", captured["cmd"])
        self.assertEqual(captured["cmd"][captured["cmd"].index("-p") + 1], "22,80,443")
        self.assertNotIn("-p-", captured["cmd"])                  # not the full-range nmap scan
        self.assertEqual([s["port"] for s in svcs], ["80"])

    def test_falls_back_to_nmap_when_rustscan_absent(self):
        eng = crp.ScanEngine("example.com", "Full", {})
        eng._host_behind_cdn = lambda h: ""
        eng._rustscan_ports = lambda host, **k: None             # rustscan not installed
        eng._socket_port_scan = lambda h: []
        captured = {}

        def fake_nmap(cmd, timeout=120):
            captured["cmd"] = cmd
            xml = cmd[cmd.index("-oX") + 1]
            open(xml, "w", encoding="utf-8").write('<?xml version="1.0"?><nmaprun></nmaprun>')
            return crp.CmdResult("", status="ok", cmd=cmd)
        eng.run_cmd = fake_nmap
        eng.stage_port_scan(["example.com"])
        self.assertIn("-p-", captured["cmd"])                    # the normal Full nmap scan

    def test_quick_profile_does_not_use_rustscan(self):
        eng = crp.ScanEngine("example.com", "Quick", {})
        eng._host_behind_cdn = lambda h: ""
        called = {"rs": False}

        def rs(host, **k):
            called["rs"] = True
            return [80]
        eng._rustscan_ports = rs
        eng._socket_port_scan = lambda h: []

        def fake_nmap(cmd, timeout=120):
            xml = cmd[cmd.index("-oX") + 1]
            open(xml, "w", encoding="utf-8").write('<?xml version="1.0"?><nmaprun></nmaprun>')
            return crp.CmdResult("", status="ok", cmd=cmd)
        eng.run_cmd = fake_nmap
        eng.stage_port_scan(["example.com"])
        self.assertFalse(called["rs"])                           # rustscan only for the Full (-p-) profile


class NucleiCategoryMapping(unittest.TestCase):
    def test_template_ids_map_to_categories(self):
        cat = crp.ScanEngine._nuclei_category
        self.assertEqual(cat({"template_id": "prometheus-metrics", "tags": ["exposure"]}), "exposure")
        self.assertEqual(cat({"template_id": "swagger-api", "tags": ["exposure", "api"]}), "exposure")
        self.assertEqual(cat({"template_id": "git-config", "tags": ["exposure"]}), "exposure")
        self.assertEqual(cat({"template_id": "sqli-error-based", "tags": ["sqli"]}), "sqli")
        self.assertEqual(cat({"template_id": "cors-misconfig", "tags": ["misconfig"]}), "cors")
        self.assertEqual(cat({"template_id": "generic-panel", "tags": ["panel"]}), "exposed-panel")
        self.assertEqual(cat({"template_id": "something-takeover", "tags": ["takeover"]}), "takeover")
        self.assertEqual(cat({"template_id": "mystery", "tags": []}), "misconfig")


if __name__ == "__main__":
    unittest.main(verbosity=2)
