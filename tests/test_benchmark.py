"""Tests for the benchmark scorer (benchmark/run_benchmark.py) and the ground-truth files."""
import json
import os
import sys
import unittest
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # repository root
BENCH = os.path.join(ROOT, "benchmark")
sys.path.insert(0, BENCH)

import run_benchmark as rb  # noqa: E402

PATHOF = lambda f: urlsplit(f.get("url") or "").path or ""


def confirmed(category, url, **kw):
    return {"confidence": "confirmed", "category": category, "url": url,
            "title": kw.pop("title", category), "severity": kw.pop("severity", "MEDIUM"),
            "parameter": kw.pop("parameter", ""), **kw}


class Matching(unittest.TestCase):
    def test_category_list_and_any(self):
        exp = {"path": "/s", "category": ["sqli", "injection"], "parameter": "q"}
        self.assertTrue(rb._matches(confirmed("injection", "http://t/s?q=1", parameter="q"), exp, PATHOF))
        self.assertFalse(rb._matches(confirmed("xss", "http://t/s?q=1", parameter="q"), exp, PATHOF))
        anycat = {"path": "/s", "category": "any"}
        self.assertTrue(rb._matches(confirmed("whatever", "http://t/s"), anycat, PATHOF))

    def test_prefix_is_boundary_aware(self):
        exp = {"path": "/ftp*", "category": ["exposure"]}
        self.assertTrue(rb._matches(confirmed("exposure", "http://t/ftp"), exp, PATHOF))
        self.assertTrue(rb._matches(confirmed("exposure", "http://t/ftp/coupons.bak"), exp, PATHOF))
        self.assertFalse(rb._matches(confirmed("exposure", "http://t/ftpother"), exp, PATHOF))

    def test_wildcard_path_and_any_of(self):
        exp = {"path": "*", "category": ["cors", "misconfig"], "any_of": ["access-control"]}
        self.assertTrue(rb._matches(confirmed("misconfig", "http://t/", title="CORS access-control-allow-origin *"), exp, PATHOF))
        self.assertFalse(rb._matches(confirmed("misconfig", "http://t/", title="unrelated"), exp, PATHOF))

    def test_parameter_required_only_when_named(self):
        exp = {"path": "/r", "category": ["redirect"], "parameter": "to"}
        self.assertFalse(rb._matches(confirmed("redirect", "http://t/r?x=1", parameter="x"), exp, PATHOF))
        self.assertTrue(rb._matches(confirmed("redirect", "http://t/r?to=1", parameter="to"), exp, PATHOF))


class Scoring(unittest.TestCase):
    EXP = {"expected": [
        {"id": "a", "category": ["sqli", "injection"], "path": "/rest/products/search", "parameter": "q"},
        {"id": "b", "category": ["exposure", "listing"], "path": "/ftp*", "any_of": ["ftp", "listing"]},
        {"id": "c", "category": ["cors", "misconfig"], "path": "*", "any_of": ["access-control"]},
    ], "safe_paths": []}

    def test_detected_missed_and_additional(self):
        findings = [
            confirmed("sqli", "http://t/rest/products/search?q=1", parameter="q"),
            confirmed("exposure", "http://t/ftp/x.bak", title="Directory listing"),
            confirmed("misconfig", "http://t/", title="CORS access-control-allow-origin *"),
            confirmed("xss", "http://t/unknown?x=1", parameter="x", severity="HIGH"),
            {"confidence": "version-match", "category": "cve", "url": "http://t/", "title": "old", "severity": "HIGH"},
        ]
        det, miss, fp, other = rb.score(findings, self.EXP)
        self.assertEqual(sorted(e["id"] for e in det), ["a", "b", "c"])
        self.assertEqual(miss, [])
        self.assertEqual(fp, [])                       # unknown endpoint on a real app -> other, not FP
        self.assertTrue(any("xss" in o["title"].lower() for o in other))
        self.assertFalse(any(o.get("confidence") == "version-match" for o in other))  # not confirmed

    def test_missed_is_reported(self):
        det, miss, fp, other = rb.score([], self.EXP)
        self.assertEqual(det, [])
        self.assertEqual({e["id"] for e in miss}, {"a", "b", "c"})

    def test_false_positive_on_declared_safe_path(self):
        exp = {"expected": [{"id": "a", "category": ["sqli"], "path": "/x", "parameter": "q"}], "safe_paths": ["/safe"]}
        _, _, fp, _ = rb.score([confirmed("sqli", "http://t/safe?q=1", parameter="q", title="bogus")], exp)
        self.assertEqual(len(fp), 1)


class GroundTruthFiles(unittest.TestCase):
    def test_files_are_valid(self):
        for name in ("expected.json", "juice-shop.expected.json"):
            with open(os.path.join(BENCH, name), encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertTrue(data.get("name") and data.get("expected"), name)
            for e in data["expected"]:
                self.assertIn("path", e, name)
                self.assertIn("category", e, name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
