#!/usr/bin/env python3
"""Measure the scanner against a target with known ground truth.

    python benchmark/run_benchmark.py                 # start the local app, scan it, score it
    python benchmark/run_benchmark.py --min-recall 1.0 --max-false-positives 0   # CI gate

It starts benchmark/ground_truth_app.py on 127.0.0.1, runs the real CLI against it
(with login), then compares the structured findings with benchmark/expected.json:

  detected        expected issue that the scanner reported (same category, path, parameter)
  missed          expected issue that was not reported
  false positive  confirmed finding on a path that is known to be safe

Results are written to <output-dir>/benchmark_result.json and .md.
"""
import argparse
import glob
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until_up(url, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2).read()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def _matches(f, exp, path_of):
    """Does finding ``f`` satisfy expected issue ``exp``?

    - category: a string or a list of acceptable categories (""/"any" = ignore category)
    - path:     exact path, or a path prefix when the expected path ends with '*'
    - parameter: required only when the expected entry names one
    - any_of:   optional list of substrings; at least one must appear in title/url/category
    """
    cats = exp.get("category", "")
    cats = [cats] if isinstance(cats, str) else list(cats)
    if cats and "any" not in cats and f.get("category") not in cats:
        return False
    ep = exp["path"]
    fp = path_of(f)
    if ep == "*":
        pass                                     # any path (e.g. a site-wide header issue)
    elif ep.endswith("*"):
        base = ep[:-1].rstrip("/")               # "/ftp*" -> matches "/ftp" and "/ftp/..."
        if fp != base and not fp.startswith(base + "/"):
            return False
    elif fp != ep:
        return False
    if exp.get("parameter") and f.get("parameter") != exp["parameter"]:
        return False
    if exp.get("any_of"):
        hay = (f.get("title", "") + " " + f.get("url", "") + " " + f.get("category", "")).lower()
        if not any(s.lower() in hay for s in exp["any_of"]):
            return False
    return True


def score(findings, expected):
    """Return (detected, missed, false_positives, other) for a list of finding dicts.

    Only ``confirmed`` findings count as detections / false positives. ``version-match``
    and other lower-confidence findings are listed separately as ``other`` so a real app's
    noise does not distort precision.
    """
    def path_of(f):
        return urlsplit(f.get("url") or "").path or ""

    confirmed = [f for f in findings if f.get("confidence") == "confirmed"]
    detected, missed, matched_ids = [], [], set()
    for exp in expected["expected"]:
        hit = next((f for f in confirmed if _matches(f, exp, path_of)), None)
        if hit:
            matched_ids.add(id(hit))
            detected.append({**exp, "finding": hit.get("title")})
        else:
            missed.append(exp)

    safe = set(expected.get("safe_paths", []))
    # Paths that are legitimately vulnerable (extra true findings there are not FPs).
    vuln_prefixes = [e["path"][:-1] for e in expected["expected"] if e["path"].endswith("*")]
    vuln_paths = {e["path"] for e in expected["expected"] if not e["path"].endswith("*")}
    false_positives, other = [], []
    for f in confirmed:
        if id(f) in matched_ids:
            continue
        p = path_of(f)
        entry = {"title": f.get("title"), "category": f.get("category"), "path": p,
                 "parameter": f.get("parameter"), "severity": f.get("severity")}
        on_vuln = p in vuln_paths or any(p.startswith(pre) for pre in vuln_prefixes)
        if p in safe:
            false_positives.append(entry)
        elif on_vuln:
            other.append(entry)      # extra true issue on a known-vulnerable endpoint
        else:
            # Unknown endpoint on a real app: can't prove it's a false positive, so it is
            # reported as "other" (uncredited) rather than counted against precision.
            other.append(entry)
    return detected, missed, false_positives, other


def main(argv=None):
    ap = argparse.ArgumentParser(description="CyberRecon-Pro ground-truth benchmark")
    ap.add_argument("--output-dir", default=os.path.join(HERE, "out"))
    ap.add_argument("--profile", default="Quick")
    ap.add_argument("--min-recall", type=float, default=0.0, help="fail (exit 1) below this recall")
    ap.add_argument("--max-false-positives", type=int, default=-1, help="fail (exit 1) above this count")
    ap.add_argument("--no-login", action="store_true", help="scan unauthenticated (authenticated issues will be missed)")
    ap.add_argument("--expected", default=os.path.join(HERE, "expected.json"),
                    help="ground-truth file (default: the built-in ground_truth_app)")
    ap.add_argument("--url", default="",
                    help="scan an already-running target at this URL instead of starting the built-in app "
                         "(e.g. a Juice Shop container on http://127.0.0.1:3000)")
    ap.add_argument("--nuclei", action="store_true", help="also run the full nuclei template set (slower, more coverage)")
    args = ap.parse_args(argv)

    with open(args.expected, encoding="utf-8") as fh:
        expected = json.load(fh)
    out_dir = os.path.abspath(args.output_dir)
    os.makedirs(out_dir, exist_ok=True)

    app = None
    if args.url:
        base = args.url.rstrip("/")
    else:
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        app = subprocess.Popen([sys.executable, os.path.join(HERE, "ground_truth_app.py"), str(port)])
    try:
        if not wait_until_up(base + "/", seconds=60 if args.url else 20):
            print(f"target {base} is not reachable", file=sys.stderr)
            return 3
        cmd = [sys.executable, "-W", "ignore", "-m", "danishrecon.cli", base, "--i-am-authorized", "--profile", args.profile,
               "--no-nvd", "--quiet", "--output-dir", out_dir]
        if args.nuclei:
            cmd.append("--nuclei")
        login = expected.get("login")
        if login and not args.no_login:
            cmd += ["--login-url", base + login["path"], "--login-data", login["data"]]
        started = time.time()
        env = dict(os.environ, PYTHONIOENCODING="utf-8", DISABLE_GEMINI="true")
        rc = subprocess.run(cmd, env=env).returncode
        seconds = round(time.time() - started)
        if rc == 3:
            print("scan failed", file=sys.stderr)
            return 3
    finally:
        if app is not None:
            app.terminate()

    files = sorted(glob.glob(os.path.join(out_dir, "results", "findings_*.json")), key=os.path.getmtime)
    with open(files[-1], encoding="utf-8") as fh:
        findings = json.load(fh)

    detected, missed, fps, other = score(findings, expected)
    total = len(expected["expected"])
    recall = len(detected) / total if total else 0.0
    precision = (len(detected) + len(other)) / max(len(detected) + len(other) + len(fps), 1)
    result = {"target": expected["name"], "url": base, "authenticated": bool(login and not args.no_login),
              "profile": args.profile, "nuclei": args.nuclei, "seconds": seconds, "expected": total,
              "detected": len(detected), "missed": len(missed), "additional": len(other),
              "false_positives": len(fps), "recall": round(recall, 3), "precision": round(precision, 3),
              "detail": {"detected": detected, "missed": missed, "false_positives": fps, "additional_true": other}}
    with open(os.path.join(out_dir, "benchmark_result.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    def cat(e):
        c = e.get("category", "")
        return "/".join(c) if isinstance(c, list) else c
    authed = login and not args.no_login
    lines = [f"# Benchmark: {expected['name']}", "",
             f"- Scan: profile `{args.profile}`, {'authenticated' if authed else 'unauthenticated'}"
             f"{', full nuclei' if args.nuclei else ''}, {seconds}s",
             f"- **Detected {len(detected)}/{total}** expected issues (recall {recall:.0%})",
             f"- **False positives: {len(fps)}** (precision {precision:.0%})",
             f"- Additional confirmed findings not in the ground-truth list: {len(other)}", "",
             "| Expected issue | Where | Result |", "|---|---|---|"]
    for e in detected:
        lines.append(f"| {cat(e)} | `{e['path']}` {e.get('parameter', '')} ({e.get('note', '')}) | detected: {e['finding']} |")
    for e in missed:
        lines.append(f"| {cat(e)} | `{e['path']}` {e.get('parameter', '')} ({e.get('note', '')}) | **MISSED** |")
    for f in fps:
        lines.append(f"| - | `{f['path']}` {f['parameter'] or ''} | **FALSE POSITIVE**: {f['title']} |")
    if other:
        lines += ["", "<details><summary>Additional confirmed findings (not scored)</summary>", "",
                  "| Severity | Finding | Where |", "|---|---|---|"]
        for f in other[:60]:
            lines.append(f"| {f['severity']} | {f['title']} | `{f['path']}` {f['parameter'] or ''} |")
        lines.append("</details>")
    md = "\n".join(lines) + "\n"
    with open(os.path.join(out_dir, "benchmark_result.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    print("\n" + md)

    failed = recall < args.min_recall or (0 <= args.max_false_positives < len(fps))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
