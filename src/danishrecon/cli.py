#!/usr/bin/env python3
"""Headless command-line runner for DanishRecon (no GUI, no PIN prompt, no alerts).

    danishrecon scan example.com --i-am-authorized
    danishrecon malware suspicious.exe
    danishrecon sniff capture.pcap

Outputs (in <output-dir>/results/): HTML + Markdown report, scan JSON, CSV, and a SARIF
file that GitHub code scanning / CI systems can ingest.

Exit codes: 0 = finished, below --fail-on threshold
            1 = finished, findings at or above --fail-on
            2 = bad arguments / authorization not confirmed
            3 = scan failed or was interrupted
"""
import argparse
import json
import os
import sys

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def build_parser():
    p = argparse.ArgumentParser(
        prog="danishrecon", description="DanishRecon headless scanner",
        epilog="Only scan systems you own or are explicitly authorized in writing to test.")
    p.add_argument("target", help="hostname, IPv4 address, CIDR range or URL")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="REQUIRED: confirm you are authorized to test this target")
    p.add_argument("--profile", default="Quick", choices=["Quick", "Full", "Stealth", "Custom"])
    p.add_argument("--nuclei", action="store_true", help="also run the full nuclei template set")
    p.add_argument("--dirbuster", action="store_true", help="also run directory brute-forcing")
    p.add_argument("--os-detect", action="store_true", help="nmap OS detection (needs admin/root)")
    p.add_argument("--scripts", action="store_true", help="nmap vuln/auth/default scripts")
    p.add_argument("--no-dast", action="store_true", help="skip nuclei DAST parameter fuzzing")
    p.add_argument("--no-forms", action="store_true",
                   help="do not auto-fill and submit HTML forms during the crawl (POST bodies are then not tested)")
    auth = p.add_argument_group("authenticated scanning")
    auth.add_argument("--cookie", default="", help="session cookie header value, e.g. 'session=abc; csrftoken=x'")
    auth.add_argument("--bearer", default="", help="bearer token sent as 'Authorization: Bearer <token>'")
    auth.add_argument("--header", action="append", default=[], metavar="'Name: value'",
                      help="extra request header (repeatable)")
    auth.add_argument("--login-url", default="", help="form-login URL (must be on the target host)")
    auth.add_argument("--login-data", default="", help="form body for --login-url, e.g. 'user=me&password=secret'")
    p.add_argument("--no-nvd", action="store_true", help="skip the online NVD CVE lookup")
    p.add_argument("--no-amplification", action="store_true",
                   help="skip the DDoS amplification/reflection exposure check (UDP probes)")
    p.add_argument("--ai", action="store_true", help="enable Gemini AI analysis (sends findings to Google)")
    p.add_argument("--output-dir", default=".", help="directory in which 'results/' is created")
    p.add_argument("--fail-on", choices=SEVERITY_ORDER, default=None,
                   help="exit with code 1 if a finding of this severity or higher exists")
    p.add_argument("--fail-on-unconfirmed", action="store_true",
                   help="let version-match / heuristic findings trigger --fail-on too "
                        "(default: only confirmed findings do)")
    p.add_argument("--quiet", action="store_true", help="only print warnings, errors and the summary")
    return p


def cmd_scan(argv=None):
    args = build_parser().parse_args(argv)
    if not args.i_am_authorized:
        print("Refusing to scan: pass --i-am-authorized to confirm you own this target or have\n"
              "explicit written permission to test it.", file=sys.stderr)
        return 2

    out_dir = os.path.abspath(args.output_dir)
    os.makedirs(out_dir, exist_ok=True)
    os.chdir(out_dir)                      # the engine writes to ./results
    if not args.ai:
        os.environ["DISABLE_GEMINI"] = "true"

    from danishrecon import scan_core as engine_mod          # pure-Python engine: no Qt needed
    from danishrecon.findings import sort_key, write_sarif

    try:
        target = engine_mod.normalize_target(args.target)
    except ValueError as e:
        print(f"Invalid target: {e}", file=sys.stderr)
        return 2

    engine = engine_mod.ScanEngine(args.target, args.profile, {   # raw: keeps explicit scheme/port
        "os_detect": args.os_detect, "scripts": args.scripts, "stealth": args.profile == "Stealth",
        "secret_scan": True, "enable_web_vuln": not args.no_dast, "nvd": not args.no_nvd,
        "amplification": not args.no_amplification,
        "nuclei": args.nuclei, "dirbuster": args.dirbuster,
        "auth_bearer": args.bearer, "auth_cookie": args.cookie, "auth_headers": args.header,
        "login_url": args.login_url, "login_data": args.login_data,
        "submit_forms": not args.no_forms,
    })

    def on_log(msg, level):
        if level in ("muted", "debug"):
            return
        if args.quiet and level not in ("warn", "error"):
            return
        print(f"[{level:5s}] {msg}", flush=True)

    outcome = {"done": False}
    engine.log_signal.connect(on_log)
    engine.scan_complete.connect(lambda data: outcome.update(done=True))
    try:
        engine.run()                       # synchronous
    except KeyboardInterrupt:
        engine.stop()
        engine_mod.DB.set_scan_status(engine.scan_id, "stopped")
        print("\nInterrupted.", file=sys.stderr)
        return 3

    if not outcome["done"]:
        print("Scan did not complete - see the log above.", file=sys.stderr)
        return 3

    data = engine.data
    findings = sorted(data.get("findings", []), key=sort_key)
    results_dir = os.path.join(out_dir, "results")
    sarif_path = write_sarif(findings, os.path.join(results_dir, f"scan_{engine.scan_id}.sarif"))
    findings_path = os.path.join(results_dir, f"findings_{engine.scan_id}.json")
    with open(findings_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("\n" + "=" * 64)
    print(f" Target   : {target}   (scan #{engine.scan_id}, {data.get('duration')})")
    print(f" Surface  : {len(data.get('hosts', []))} host(s), {len(data.get('services', []))} service(s), "
          f"{len(data.get('crawled_urls', []))} URL(s) crawled, {len(data.get('param_urls', []))} with parameters, "
          f"{data.get('post_request_count', 0)} form request(s)"
          + ("  [authenticated]" if data.get("authenticated") else ""))
    print(" Findings : " + (", ".join(f"{counts[s]} {s}" for s in
                                      ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if s in counts) or "none"))
    for f in findings[:15]:
        where = f.get("url") or f"{f.get('host')}:{f.get('port')}"
        print(f"   [{f['severity']:8s}] {f['title'][:70]}  ({f['source']}/{f['confidence']})  {where[:60]}")
    if len(findings) > 15:
        print(f"   ... and {len(findings) - 15} more")
    if data.get("stage_errors"):
        print(" Failed stages: " + ", ".join(e["stage"] for e in data["stage_errors"]))
    diff = data.get("diff")
    if diff:
        print(f" vs scan #{diff['previous_scan']}: {len(diff['new'])} new, {len(diff['fixed'])} no longer present, "
              f"{diff['persisting']} still present")
    print(f" Report   : {os.path.abspath(data.get('report_path', ''))}")
    print(f" SARIF    : {sarif_path}")
    print(f" Findings : {findings_path}")
    print("=" * 64)

    if args.fail_on:
        threshold = SEVERITY_ORDER.index(args.fail_on)
        gating = [f for f in findings if args.fail_on_unconfirmed or f.get("confidence") == "confirmed"]
        if any(SEVERITY_ORDER.index(f["severity"].lower()) >= threshold for f in gating):
            return 1
    return 0


def _run_analysis(engine, args, kind, extra_summary=None):
    """Shared driver for the malware / sniff engines: run, print a summary, apply --fail-on."""
    from danishrecon.findings import sort_key

    def on_log(msg, level):
        if level in ("muted", "debug"):
            return
        if getattr(args, "quiet", False) and level not in ("warn", "error"):
            return
        print(f"[{level:5s}] {msg}", flush=True)

    outcome = {"done": False}
    engine.log_signal.connect(on_log)
    engine.scan_complete.connect(lambda d: outcome.update(done=True))
    try:
        engine.run()
    except KeyboardInterrupt:
        engine.stop()
        print("\nInterrupted.", file=sys.stderr)
        return 3
    if not outcome["done"]:
        print(f"{kind} did not complete - see the log above.", file=sys.stderr)
        return 3

    data = engine.data
    findings = sorted(data.get("findings", []), key=sort_key)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("\n" + "=" * 64)
    print(f" {kind}: {data.get('target')}   (scan #{engine.scan_id}, {data.get('duration')})")
    if extra_summary:
        print(extra_summary(data))
    print(" Findings : " + (", ".join(f"{counts[s]} {s}" for s in
                                      ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if s in counts) or "none"))
    for f in findings[:20]:
        where = f.get("file") or f.get("url") or f"{f.get('host', '')}:{f.get('port', '')}".strip(":")
        print(f"   [{f['severity']:8s}] {f['title'][:66]}  {where[:50]}")
    if len(findings) > 20:
        print(f"   ... and {len(findings) - 20} more")
    print(f" Report   : {os.path.abspath(data.get('report_path', ''))}")
    print(f" SARIF    : {os.path.abspath(data.get('sarif_path', ''))}")
    print("=" * 64)

    if getattr(args, "fail_on", None):
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"].lower()) >= threshold for f in findings):
            return 1
    return 0


def cmd_malware(argv=None):
    p = argparse.ArgumentParser(prog="danishrecon malware",
                                description="Static malware analysis of file(s) - files are never executed.")
    p.add_argument("path", nargs="+", help="file(s) or folder(s) to analyze")
    p.add_argument("--reputation", action="store_true",
                   help="look up the file hash on MalwareBazaar (sends only the SHA-256)")
    p.add_argument("--yara-rules", default="", help="path to a YARA rule file or directory")
    p.add_argument("--output-dir", default=".")
    p.add_argument("--fail-on", choices=SEVERITY_ORDER, default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    out_dir = os.path.abspath(args.output_dir)
    os.makedirs(out_dir, exist_ok=True)
    os.chdir(out_dir)
    os.environ["DISABLE_GEMINI"] = "true"
    from danishrecon import analysis_core
    opts = {"reputation": args.reputation}
    if args.yara_rules:
        opts["yara_rules"] = args.yara_rules
    eng = analysis_core.MalwareEngine(args.path, opts)
    return _run_analysis(eng, args, "Malware analysis",
                         lambda d: f" Files    : {d.get('files_analyzed', 0)} analyzed")


def cmd_sniff(argv=None):
    p = argparse.ArgumentParser(prog="danishrecon sniff",
                                description="Network traffic analysis of a .pcap file or a live capture.")
    p.add_argument("source", help="path to a .pcap/.pcapng file, or an interface name with --live")
    p.add_argument("--live", action="store_true",
                   help="capture live from the interface named by 'source' (authorized networks only; needs Npcap/root)")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="REQUIRED with --live: confirm you are authorized to capture on this network")
    p.add_argument("--count", type=int, default=2000, help="live: max packets to capture")
    p.add_argument("--duration", type=int, default=60, help="live: max seconds to capture")
    p.add_argument("--ioc-file", default="", help="file of domains/IPs to flag if seen in the traffic")
    p.add_argument("--output-dir", default=".")
    p.add_argument("--fail-on", choices=SEVERITY_ORDER, default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    if args.live and not args.i_am_authorized:
        print("Refusing live capture: pass --i-am-authorized to confirm you may monitor this network.",
              file=sys.stderr)
        return 2
    out_dir = os.path.abspath(args.output_dir)
    os.makedirs(out_dir, exist_ok=True)
    os.chdir(out_dir)
    os.environ["DISABLE_GEMINI"] = "true"
    from danishrecon import analysis_core
    eng = analysis_core.SnifferEngine(args.source, {
        "live": args.live, "count": args.count, "duration": args.duration,
        "ioc_file": args.ioc_file or None})
    return _run_analysis(eng, args, "Traffic analysis")


def cmd_setup(argv=None):
    from danishrecon import tools
    p = argparse.ArgumentParser(
        prog="danishrecon setup",
        description=f"Install the external tools DanishRecon drives into {tools.TOOLS_DIR} "
                    "(official sources only). Every scan, from any folder, finds them there.")
    p.add_argument("tool", nargs="*",
                   help="what to install: " + ", ".join(sorted(tools.INSTALLERS)) +
                        f" (default: {' '.join(tools.DEFAULT_SET)}; openvas only when named)")
    p.add_argument("--list", action="store_true", help="only show what is installed and where")
    args = p.parse_args(argv)

    def show():
        print()
        print(f"Tools folder: {tools.TOOLS_DIR}")
        for name, where in tools.status().items():
            print(f"  {'OK ' if where else '-- '} {name:10s} {where or 'not installed'}")
        print()

    if args.list:
        show()
        return 0
    wanted = args.tool or list(tools.DEFAULT_SET)
    unknown = [t for t in wanted if t not in tools.INSTALLERS]
    if unknown:
        print("Unknown tool(s): " + ", ".join(unknown), file=sys.stderr)
        return 2
    failed = []
    for name in wanted:
        print(f"[setup] {name}")
        try:
            tools.INSTALLERS[name](print)
        except Exception as e:
            failed.append(name)
            print(f"  FAILED: {e}")
    show()
    if failed:
        print("Not installed: " + ", ".join(failed))
    return 1 if failed else 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    sub = argv[0] if argv else ""
    if sub == "setup":
        return cmd_setup(argv[1:])
    if sub == "malware":
        return cmd_malware(argv[1:])
    if sub == "sniff":
        return cmd_sniff(argv[1:])
    if sub == "scan":                      # explicit; a bare target also works (back-compat)
        return cmd_scan(argv[1:])
    return cmd_scan(argv)


if __name__ == "__main__":
    sys.exit(main())
