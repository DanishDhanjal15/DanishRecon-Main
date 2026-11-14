"""Tests for the structured-finding model and the OSS-tool orchestration layer.

All offline: external tools and the NVD API are replaced by fixtures / stubs.

    python -m unittest discover -s tests -v   (after: pip install -e .)
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
os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["DISABLE_GEMINI"] = "true"

from danishrecon import scan_core as crp  # noqa: E402
from danishrecon import cli  # noqa: E402
from danishrecon import cve_lookup  # noqa: E402
from danishrecon import exploit_search  # noqa: E402
from danishrecon import recon_tools  # noqa: E402
from danishrecon.findings import Finding, dedupe, severity_from_cvss, sort_key, to_sarif  # noqa: E402


class FindingModel(unittest.TestCase):
    def test_defaults_and_normalisation(self):
        f = Finding(title="x", severity="high", confidence="nonsense", port=443)
        self.assertEqual((f.severity, f.confidence, f.port, f.cvss), ("HIGH", "heuristic", "443", 7.5))
        self.assertEqual(Finding(title="x", severity="unknown").severity, "INFO")

    def test_fingerprint_ignores_query_values_and_dedupes(self):
        a = Finding(title="SQLi", source="nuclei-dast", url="http://h/p?id=1'", parameter="id")
        b = Finding(title="SQLi", source="nuclei-dast", url="http://h/p?id=2 OR 1", parameter="id")
        c = Finding(title="SQLi", source="nuclei-dast", url="http://h/p?id=1", parameter="name")
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertNotEqual(a.fingerprint, c.fingerprint)
        self.assertEqual(len(dedupe([a, b, c])), 2)

    def test_severity_from_cvss(self):
        self.assertEqual([severity_from_cvss(x) for x in (9.8, 7.0, 4.0, 0.1, 0)],
                         ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

    def test_sort_puts_known_exploited_first(self):
        items = [Finding(title="a", severity="CRITICAL").to_dict(),
                 Finding(title="b", severity="MEDIUM", kev=True).to_dict(),
                 Finding(title="c", severity="HIGH").to_dict()]
        self.assertEqual([f["title"] for f in sorted(items, key=sort_key)], ["b", "a", "c"])

    def test_sarif_shape(self):
        items = [Finding(title="SQL injection", severity="CRITICAL", source="nuclei-dast",
                         category="sqli", url="http://h/p?id=1", parameter="id").to_dict(),
                 Finding(title="Apache: CVE-2021-41773", severity="CRITICAL", source="nvd",
                         confidence="version-match", cve="CVE-2021-41773", host="h", port=80).to_dict()]
        sarif = to_sarif(items)
        run = sarif["runs"][0]
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(run["results"]), 2)
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][1]["ruleId"], "CVE-2021-41773")
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "http://h/p?id=1")
        json.dumps(sarif)  # must be serialisable


class CveLookup(unittest.TestCase):
    def test_cpe_conversion(self):
        conv = cve_lookup.cpe22_to_23
        self.assertEqual(conv("cpe:/a:apache:http_server:2.4.49"), "cpe:2.3:a:apache:http_server:2.4.49")
        self.assertEqual(conv("cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"), "cpe:2.3:a:openbsd:openssh:7.4")
        self.assertIsNone(conv("cpe:/a:apache:http_server"))        # no version -> too broad
        self.assertIsNone(conv("cpe:/a:vendor:product:*"))
        self.assertIsNone(conv("not-a-cpe"))
        self.assertIsNone(conv("cpe:/a:ven dor:prod:1.0"))           # unsafe characters

    def test_lookup_uses_cache_and_ranks_known_exploited_first(self):
        cache_dir = tempfile.mkdtemp()
        cpe23 = "cpe:2.3:a:apache:http_server:2.4.49"

        def cve(cid, score, kev=False):
            c = {"id": cid, "published": "2021-10-05T00:00:00",
                 "descriptions": [{"lang": "en", "value": f"desc {cid}"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}]}}
            if kev:
                c["cisaExploitAdd"] = "2021-11-03"
            return {"cve": c}
        with open(cve_lookup._cache_file(cache_dir, cpe23), "w", encoding="utf-8") as fh:
            json.dump({"vulnerabilities": [cve("CVE-A", 9.9), cve("CVE-B", 7.5, kev=True), cve("CVE-C", 5.0)]}, fh)

        original = cve_lookup.requests.get
        cve_lookup.requests.get = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used"))
        try:
            res = cve_lookup.lookup("cpe:/a:apache:http_server:2.4.49", cache_dir, limit=2)
        finally:
            cve_lookup.requests.get = original
        self.assertIsNone(res["error"])
        self.assertEqual(res["total"], 3)
        self.assertEqual([c["cve"] for c in res["cves"]], ["CVE-B", "CVE-A"])
        self.assertTrue(res["cves"][0]["kev"])

    def test_network_failure_is_reported_not_raised(self):
        # _last_call far in the past -> the rate-limit pause is skipped
        original, cve_lookup._last_call = cve_lookup.requests.get, 0.0

        def boom(*a, **k):
            raise ConnectionError("offline")
        cve_lookup.requests.get = boom
        try:
            res = cve_lookup.lookup("cpe:/a:x:y:1.0", tempfile.mkdtemp())
        finally:
            cve_lookup.requests.get, cve_lookup._last_call = original, 0.0
        self.assertEqual(res["cves"], [])
        self.assertIn("ConnectionError", res["error"])


class ExploitSearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        rows = [
            "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url",
            '1,exploits/unix/remote/1.py,"vsftpd 2.3.4 - Backdoor Command Execution",2021-04-12,a,remote,unix,,,,1,CVE-2011-2523,,,,,',
            '2,exploits/linux/remote/2.py,"OpenSSH < 7.7 - User Enumeration (2)",2018-08-21,a,remote,linux,,,,1,CVE-2018-15473,,,,,',
            '3,exploits/linux/local/3.c,"OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading",2016-12-23,a,local,linux,,,,1,CVE-2016-10009,,,,,',
            '4,exploits/multiple/webapps/4.py,"Apache Tomcat < 9.0.1 - JSP Upload Bypass",2017-10-09,a,webapps,multiple,,,,1,CVE-2017-12617,,,,,',
            '5,exploits/multiple/webapps/5.sh,"Apache HTTP Server 2.4.49 - Path Traversal & RCE",2021-10-05,a,webapps,multiple,,,,1,CVE-2021-41773,,,,,',
        ]
        with open(os.path.join(cls.dir, "files_exploits.csv"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(rows) + "\n")
        cls._saved = list(exploit_search._CANDIDATE_DIRS)
        exploit_search._CANDIDATE_DIRS[:] = [cls.dir]
        exploit_search._index = None

    @classmethod
    def tearDownClass(cls):
        exploit_search._CANDIDATE_DIRS[:] = cls._saved
        exploit_search._index = None

    def ids(self, product, version):
        return sorted(r["id"] for r in exploit_search.search(product, version))

    def test_exact_version(self):
        self.assertEqual(self.ids("vsftpd", "2.3.4"), ["1"])
        self.assertEqual(self.ids("vsftpd", "3.0.3"), [])

    def test_upper_bound_ranges(self):
        self.assertEqual(self.ids("OpenSSH", "7.4"), ["2"])        # < 7.7 yes, < 7.4 no
        self.assertEqual(self.ids("OpenSSH", "7.2p2"), ["2", "3"])
        self.assertEqual(self.ids("OpenSSH", "9.6"), [])

    def test_other_products_sharing_a_vendor_word_do_not_match(self):
        self.assertEqual(self.ids("Apache httpd", "2.4.49"), ["5"])   # not the Tomcat entry

    def test_version_is_required(self):
        self.assertEqual(exploit_search.search("OpenSSH", ""), [])
        self.assertEqual(exploit_search.search("", "7.4"), [])


class ReconToolHelpers(unittest.TestCase):
    def test_scope(self):
        allowed = {"app.example.com"}
        self.assertTrue(recon_tools.in_scope("https://app.example.com/a?b=1", allowed))
        self.assertTrue(recon_tools.in_scope("http://APP.example.com:8080/", allowed))
        for bad in ("https://example.com/", "https://evil.com/?u=app.example.com",
                    "https://app.example.com.evil.com/", "ftp://app.example.com/", "javascript:alert(1)",
                    "//maps.googleapis.com/maps/api/js"):
            self.assertFalse(recon_tools.in_scope(bad, allowed), bad)

    def test_canonical_param_url(self):
        c = recon_tools.canonical_param_url
        self.assertEqual(c("http://H/p?b=2&a=1"), c("http://h/p?a=9&b=8"))
        self.assertNotEqual(c("http://h/p?a=1"), c("http://h/p?a=1&c=1"))

    def test_parse_nuclei_entry(self):
        entry = {"template-id": "sqli-error-based", "matched-at": "http://h/p?id=1'", "host": "h",
                 "fuzzing_parameter": "id", "extracted-results": ["sqlite3.OperationalError:"],
                 "info": {"name": "Error based SQL Injection", "severity": "critical", "tags": "sqli,dast",
                          "reference": "https://owasp.org/x",
                          "classification": {"cve-id": ["cve-2020-0001"], "cvss-score": 9.8, "cwe-id": ["cwe-89"]}}}
        f = recon_tools.parse_nuclei_entry(entry)
        self.assertEqual((f["severity"], f["cve"], f["cwe"], f["cvss"], f["parameter"]),
                         ("CRITICAL", "CVE-2020-0001", "CWE-89", 9.8, "id"))
        self.assertEqual(f["tags"], ["sqli", "dast"])
        self.assertEqual(f["references"], ["https://owasp.org/x"])
        self.assertIn("sqlite3.OperationalError", f["evidence"])
        self.assertEqual(recon_tools.parse_nuclei_entry({"template-id": "t"})["severity"], "INFO")

    def test_run_tool_reports_missing_binary_and_timeout(self):
        self.assertEqual(recon_tools.run_tool(["definitely-not-a-real-binary-xyz"], 5)["status"], "not_found")
        r = recon_tools.run_tool([sys.executable, "-c", "import time; time.sleep(30)"], budget=1)
        self.assertEqual(r["status"], "timeout")
        self.assertLess(r["seconds"], 15)
        r = recon_tools.run_tool([sys.executable, "-c", "import time; time.sleep(30)"], budget=30,
                                 stop_check=lambda: True)
        self.assertEqual(r["status"], "stopped")


class EngineOrchestration(unittest.TestCase):
    def test_web_base_urls(self):
        eng = crp.ScanEngine("example.com", "Quick", {})
        urls = eng._web_base_urls([
            {"host": "example.com", "port": "80", "service": "http"},
            {"host": "example.com", "port": "443", "service": "https"},
            {"host": "example.com", "port": "8080", "service": "http-alt"},
            {"host": "example.com", "port": "8443", "service": "ssl/http"},
            {"host": "example.com", "port": "22", "service": "ssh"},
            {"host": "example.com", "port": "80", "service": "http"},
        ])
        self.assertEqual(urls, ["http://example.com", "https://example.com",
                                "http://example.com:8080", "https://example.com:8443"])
        self.assertEqual(eng._web_base_urls([]), ["https://example.com", "http://example.com"])

    def test_dast_stage_records_confirmed_findings_and_respects_scope(self):
        eng = crp.ScanEngine("127.0.0.1", "Quick", {})
        eng.data["hosts"] = ["127.0.0.1"]
        eng.data["param_urls"] = ["http://127.0.0.1:8080/product?id=1", "http://third-party.example/x?y=1"]
        seen = {}

        def fake_nuclei(urls, dast=False, **kw):
            seen["urls"], seen["dast"] = list(urls), dast
            return {"available": True, "status": "ok", "seconds": 1.0, "findings": [recon_tools.parse_nuclei_entry({
                "template-id": "sqli-error-based", "matched-at": "http://127.0.0.1:8080/product?id=1'",
                "fuzzing_parameter": "id", "info": {"name": "Error based SQL Injection", "severity": "critical"}})]}
        saved = recon_tools.nuclei_run, recon_tools.find_tool
        recon_tools.nuclei_run, recon_tools.find_tool = fake_nuclei, lambda name: "/bin/" + name
        try:
            eng.stage_dast_scan([])
            eng.stage_dast_scan([])           # a second pass must not duplicate the finding
        finally:
            recon_tools.nuclei_run, recon_tools.find_tool = saved
        self.assertEqual(seen["urls"], ["http://127.0.0.1:8080/product?id=1"])   # out-of-scope URL dropped
        self.assertTrue(seen["dast"])
        self.assertEqual(len(eng.data["findings"]), 1)
        f = eng.data["findings"][0]
        self.assertEqual((f["severity"], f["category"], f["confidence"], f["parameter"]),
                         ("CRITICAL", "sqli", "confirmed", "id"))
        self.assertEqual(eng.data["risk_counts"]["CRITICAL"], 1)
        self.assertEqual(sum("Error based SQL Injection" in v for v in eng.data["vulnerabilities"]), 1)

    def test_dast_stage_without_nuclei_says_not_tested(self):
        eng = crp.ScanEngine("127.0.0.1", "Quick", {})
        eng.data["param_urls"] = ["http://127.0.0.1/p?id=1"]
        logs = []
        eng.log_signal.connect(lambda m, lvl: logs.append(m))
        saved = recon_tools.find_tool
        recon_tools.find_tool = lambda name: None
        try:
            eng.stage_dast_scan([])
        finally:
            recon_tools.find_tool = saved
        self.assertEqual(eng.data["findings"], [])
        self.assertTrue(any("NOT tested" in m for m in logs))


class Cli(unittest.TestCase):
    def test_refuses_without_authorization_flag(self):
        self.assertEqual(cli.main(["example.com"]), 2)

    def test_rejects_invalid_target(self):
        self.assertEqual(cli.main(["--i-am-authorized", "--output-dir", tempfile.mkdtemp(), "bad target;rm"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
