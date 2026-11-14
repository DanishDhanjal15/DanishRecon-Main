"""Structured finding model shared by every scan stage.

A finding always says where it came from (``source``) and how sure we are
(``confidence``), so a report can separate confirmed issues from version-based
guesses and plain exposure notes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# confirmed      - a tool observed the vulnerable behaviour (template/matcher hit, real handshake)
# version-match  - the detected product version is listed as affected (not exploited/verified)
# exposure       - a service or file is reachable; not a vulnerability by itself
# heuristic      - weak signal that needs manual verification
CONFIDENCES = ("confirmed", "version-match", "exposure", "heuristic")

_DEFAULT_CVSS = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 0.0}


def normalize_severity(value: Any) -> str:
    s = str(value or "").strip().upper()
    if s in SEVERITIES:
        return s
    return {"UNKNOWN": "INFO", "INFORMATIONAL": "INFO", "MODERATE": "MEDIUM"}.get(s, "INFO")


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


@dataclass
class Finding:
    title: str
    severity: str = "INFO"
    source: str = "engine"            # tool or stage that produced it (nuclei, nvd, tls, ...)
    confidence: str = "confirmed"
    category: str = ""                # sqli, xss, tls, secret, cve, exposure, misconfig, ...
    host: str = ""
    port: str = ""
    url: str = ""
    parameter: str = ""
    cve: str = ""
    cvss: float = 0.0
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    kev: bool = False                 # listed in CISA Known Exploited Vulnerabilities
    epss: float = 0.0                 # FIRST EPSS: probability of exploitation in the next 30 days
    # Non-network findings (malware analysis / traffic analysis) reuse this model:
    file: str = ""                    # file path / name a finding is about (malware module)
    sha256: str = ""                  # file hash (malware module)
    artifact_type: str = ""           # "host" | "file" | "flow" | "packet" (what the finding describes)

    def __post_init__(self):
        self.severity = normalize_severity(self.severity)
        if self.confidence not in CONFIDENCES:
            self.confidence = "heuristic"
        self.port = str(self.port or "")
        try:
            self.cvss = float(self.cvss or 0.0)
        except (TypeError, ValueError):
            self.cvss = 0.0
        if not self.cvss:
            self.cvss = _DEFAULT_CVSS[self.severity]
        try:
            self.epss = round(float(self.epss or 0.0), 5)
        except (TypeError, ValueError):
            self.epss = 0.0

    @property
    def fingerprint(self) -> str:
        """Stable identity used for de-duplication and for tracking across scans."""
        key = "|".join([self.source, self.category, self.title, self.host, self.port,
                        self.url.split("?")[0], self.parameter, self.cve,
                        self.sha256 or self.file]).lower()
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def label(self) -> str:
        """One-line text used by the legacy report lists."""
        where = (self.file or self.url or (f"{self.host}:{self.port}" if self.port else self.host))
        bits = [f"[{self.severity}]", self.title]
        if self.cve:
            bits.append(f"[{self.cve}]")
        if where:
            bits.append(f"@ {where}")
        if self.parameter:
            bits.append(f"(param: {self.parameter})")
        bits.append(f"- {self.source}/{self.confidence}")
        if self.kev:
            bits.append("- KNOWN EXPLOITED (CISA KEV)")
        if self.epss >= 0.1:
            bits.append(f"- EPSS {self.epss:.0%}")
        return " ".join(bits)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


def dedupe(findings: Iterable[Finding]) -> List[Finding]:
    seen, out = set(), []
    for f in findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            out.append(f)
    return out


def sort_key(f: Dict[str, Any]):
    """Order: known-exploited first, then severity, then CVSS."""
    sev = f.get("severity", "INFO")
    return (0 if f.get("kev") else 1,
            SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES),
            -float(f.get("epss") or 0.0),
            -float(f.get("cvss") or 0.0))


_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def to_sarif(findings: List[Dict[str, Any]], tool_name: str = "DanishRecon",
             tool_version: str = "0.4.0") -> Dict[str, Any]:
    """Convert finding dicts to a SARIF 2.1.0 log (for GitHub code scanning / CI)."""
    rules, results, rule_index = [], [], {}
    for f in findings:
        rule_id = f.get("cve") or f"{f.get('source', 'engine')}/{f.get('category') or 'finding'}/" \
                                  f"{hashlib.sha1(f.get('title', '').encode()).hexdigest()[:8]}"
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": (f.get("category") or "finding").replace("-", "_"),
                "shortDescription": {"text": f.get("title", "")[:200]},
                "fullDescription": {"text": (f.get("description") or f.get("title", ""))[:1000]},
                "help": {"text": f.get("remediation") or "Review and remediate this finding."},
                "helpUri": (f.get("references") or [""])[0] or None,
                "properties": {"security-severity": str(f.get("cvss") or 0.0),
                               "tags": ["security", f.get("confidence", "")]},
            })
            if rules[-1]["helpUri"] is None:
                del rules[-1]["helpUri"]
        uri = f.get("url") or f"{f.get('host', '')}:{f.get('port', '')}".strip(":") or "target"
        msg = f.get("title", "")
        if f.get("evidence"):
            msg += f" | evidence: {str(f['evidence'])[:300]}"
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _SARIF_LEVEL.get(f.get("severity", "INFO"), "note"),
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {"cyberrecon/v1": f.get("fingerprint", "")},
            "properties": {"confidence": f.get("confidence", ""), "source": f.get("source", ""),
                           "kev": bool(f.get("kev"))},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool_name, "version": tool_version,
                                      "informationUri": "https://github.com/",
                                      "rules": rules}},
                  "results": results}],
    }


def write_sarif(findings: List[Dict[str, Any]], path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_sarif(findings), fh, indent=2)
    return path
