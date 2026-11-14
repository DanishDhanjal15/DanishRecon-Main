"""Live CVE lookup against the NVD API 2.0, keyed by the CPE that nmap reports.

Only the product identifier (vendor:product:version) is sent to NVD - never the target.
Results are cached on disk for 7 days. A match means "this version is listed as
affected", which is reported with ``version-match`` confidence, not as a confirmed hit.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Dict, List, Optional

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = 7 * 24 * 3600
_last_call = 0.0


def cpe22_to_23(cpe: str) -> Optional[str]:
    """'cpe:/a:apache:http_server:2.4.49' -> 'cpe:2.3:a:apache:http_server:2.4.49'.

    Returns None when the CPE has no version (too broad to be meaningful) or is not an
    application/OS CPE.
    """
    cpe = (cpe or "").strip()
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")[2:]
    elif cpe.startswith("cpe:/"):
        parts = cpe[5:].split(":")
    else:
        return None
    if len(parts) < 4 or parts[0] not in ("a", "o", "h"):
        return None
    part, vendor, product, version = parts[0], parts[1], parts[2], parts[3]
    if not version or version in ("*", "-") or not re.search(r"\d", version):
        return None
    if not re.fullmatch(r"[A-Za-z0-9._~%+-]+", vendor + product + version):
        return None
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}".lower()


def _cache_file(cache_dir: str, key: str) -> str:
    safe = re.sub(r"[^a-z0-9._-]", "_", key.lower())
    return os.path.join(cache_dir, f"{safe}.json")


def _parse(cve: dict) -> Dict:
    metrics = cve.get("metrics", {})
    score, severity = 0.0, ""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            score = float(data.get("baseScore") or 0.0)
            severity = (data.get("baseSeverity") or metrics[key][0].get("baseSeverity") or "").upper()
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {
        "cve": cve.get("id", ""),
        "cvss": score,
        "severity": severity,
        "description": desc,
        "published": (cve.get("published") or "")[:10],
        "kev": bool(cve.get("cisaExploitAdd")),
        "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
    }


def lookup(cpe: str, cache_dir: str, limit: int = 8, timeout: int = 30,
           api_key: Optional[str] = None) -> Dict:
    """Return {'cpe', 'total', 'cves': [...], 'error'} for an nmap CPE string.

    ``cves`` is sorted known-exploited first, then by CVSS, and truncated to ``limit``.
    """
    global _last_call
    cpe23 = cpe22_to_23(cpe)
    result = {"cpe": cpe23, "total": 0, "cves": [], "error": None}
    if not cpe23:
        result["error"] = "no versioned CPE"
        return result

    os.makedirs(cache_dir, exist_ok=True)
    cache = _cache_file(cache_dir, cpe23)
    raw = None
    if os.path.isfile(cache) and time.time() - os.path.getmtime(cache) < CACHE_TTL:
        try:
            with open(cache, encoding="utf-8") as fh:
                raw = json.load(fh)
        except Exception:
            raw = None

    if raw is None:
        api_key = api_key or os.getenv("NVD_API_KEY") or None
        # NVD public rate limit: 5 requests / 30 s without a key, 50 with one.
        wait = (0.7 if api_key else 6.5) - (time.time() - _last_call)
        if wait > 0:
            time.sleep(wait)
        try:
            _last_call = time.time()
            resp = requests.get(
                NVD_URL,
                params={"virtualMatchString": cpe23, "resultsPerPage": 200},
                headers={"apiKey": api_key} if api_key else {},
                timeout=timeout,
            )
            if resp.status_code != 200:
                result["error"] = f"NVD HTTP {resp.status_code}"
                return result
            raw = resp.json()
            with open(cache, "w", encoding="utf-8") as fh:
                json.dump(raw, fh)
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {str(e)[:120]}"
            return result

    cves = [_parse(v.get("cve", {})) for v in raw.get("vulnerabilities", [])]
    cves = [c for c in cves if c["cve"]]
    cves.sort(key=lambda c: (not c["kev"], -c["cvss"], c["cve"]))
    result["total"] = len(cves)
    result["cves"] = cves[:limit]
    return result


EPSS_URL = "https://api.first.org/data/v1/epss"


def epss_scores(cves: List[str], cache_dir: str, timeout: int = 20) -> Dict[str, float]:
    """EPSS probability (0..1) per CVE id from FIRST.org. Only CVE ids are sent.

    Cached on disk for 7 days; any failure returns what the cache has (possibly nothing).
    """
    cves = sorted({c.upper() for c in cves if re.fullmatch(r"CVE-\d{4}-\d{4,}", c.upper())})
    if not cves:
        return {}
    os.makedirs(cache_dir, exist_ok=True)
    cache_path = os.path.join(cache_dir, "epss.json")
    cache: Dict[str, list] = {}
    if os.path.isfile(cache_path):
        try:
            with open(cache_path, encoding="utf-8") as fh:
                cache = json.load(fh)
        except Exception:
            cache = {}
    now = time.time()
    missing = [c for c in cves if c not in cache or now - cache[c][1] > CACHE_TTL]
    if missing:
        try:
            for i in range(0, len(missing), 80):
                resp = requests.get(EPSS_URL, params={"cve": ",".join(missing[i:i + 80])}, timeout=timeout)
                if resp.status_code != 200:
                    break
                got = {row["cve"].upper(): float(row.get("epss") or 0.0) for row in resp.json().get("data", [])}
                for c in missing[i:i + 80]:
                    cache[c] = [got.get(c, 0.0), now]
            with open(cache_path, "w", encoding="utf-8") as fh:
                json.dump(cache, fh)
        except Exception:
            pass
    return {c: cache[c][0] for c in cves if c in cache}
