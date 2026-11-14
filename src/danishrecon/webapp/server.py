#!/usr/bin/env python3
"""DanishRecon web dashboard (local, single user).

    danishrecon-web                         # http://127.0.0.1:8787
    danishrecon-web --port 9000 --data-dir /path/with/results

Security model: this server can launch scans, so it
  * binds to 127.0.0.1 only,
  * rejects requests whose Host header is not the loopback address (DNS-rebinding guard),
  * requires a per-start random token on every /api call (the page receives it when it
    is served), so another website open in your browser cannot drive it.
"""
import argparse
import os
import secrets
import sys
import threading
import time

WEB_DIR = os.path.dirname(os.path.abspath(__file__))

from fastapi import Depends, FastAPI, HTTPException, Request  # noqa: E402
from fastapi.responses import FileResponse, HTMLResponse  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

TOKEN = secrets.token_urlsafe(32)
PORT = 8787
core = None            # scan_core module, imported in main() after chdir (it opens ./results)
_lock = threading.Lock()
_active = {"engine": None, "thread": None, "scan_id": None, "logs": [], "stage": "", "started": 0.0}

app = FastAPI(title="DanishRecon", docs_url=None, redoc_url=None, openapi_url=None)


def guard(request: Request):
    host = (request.headers.get("host") or "").lower()
    if host not in (f"127.0.0.1:{PORT}", f"localhost:{PORT}"):
        raise HTTPException(status_code=403, detail="bad host")
    if not secrets.compare_digest(request.headers.get("x-scan-token") or "", TOKEN):
        raise HTTPException(status_code=403, detail="missing or invalid token")


class NewScan(BaseModel):
    target: str = Field(..., max_length=300)
    profile: str = "Quick"
    authorized: bool = False
    nuclei: bool = False
    nvd: bool = True
    dast: bool = True
    submit_forms: bool = True
    cookie: str = Field("", max_length=4000)
    bearer: str = Field("", max_length=4000)
    login_url: str = Field("", max_length=500)
    login_data: str = Field("", max_length=1000)


class Triage(BaseModel):
    target: str
    fingerprint: str = Field(..., max_length=64)
    status: str
    note: str = Field("", max_length=500)


def _is_running():
    t = _active["thread"]
    return bool(t and t.is_alive())


def _counts(findings):
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        if f.get("triage") in ("false_positive", "fixed"):
            continue
        c[f.get("severity", "INFO")] = c.get(f.get("severity", "INFO"), 0) + 1
    return c


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    host = (request.headers.get("host") or "").lower()
    if host not in (f"127.0.0.1:{PORT}", f"localhost:{PORT}"):
        raise HTTPException(status_code=403, detail="bad host")
    with open(os.path.join(WEB_DIR, "index.html"), encoding="utf-8") as fh:
        page = fh.read().replace("__SCAN_TOKEN__", TOKEN)
    return HTMLResponse(page, headers={
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                   "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})


@app.get("/api/status", dependencies=[Depends(guard)])
def status():
    from danishrecon import recon_tools
    tools = {n: bool(recon_tools.find_tool(n)) for n in ("nuclei", "katana", "httpx")}
    import shutil
    tools["nmap"] = bool(shutil.which("nmap"))
    return {"running": _is_running(), "active_scan": _active["scan_id"] if _is_running() else None,
            "stage": _active["stage"], "tools": tools, "profiles": list(core.SCAN_PROFILES)}


@app.get("/api/scans", dependencies=[Depends(guard)])
def scans():
    return {"scans": core.DB.list_scans(), "active_scan": _active["scan_id"] if _is_running() else None}


@app.get("/api/scans/{scan_id}", dependencies=[Depends(guard)])
def scan_detail(scan_id: int):
    scan = core.DB.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    from danishrecon.findings import sort_key
    findings = sorted(core.DB.get_findings(scan_id), key=sort_key)
    prev = core.DB.previous_scan_id(scan["target"], scan_id)
    diff = None
    if prev is not None and scan["status"] == "complete":
        d = core.DB.diff_scans(prev, scan_id)
        diff = {"previous_scan": prev, "new": [f["fingerprint"] for f in d["new"]],
                "fixed": [{"severity": f.get("severity"), "title": f.get("title"),
                           "where": f.get("url") or f"{f.get('host')}:{f.get('port')}"} for f in d["fixed"]],
                "persisting": len(d["persisting"])}
    running = _is_running() and _active["scan_id"] == scan_id
    return {"scan": scan, "findings": findings, "counts": _counts(findings), "diff": diff,
            "running": running, "stage": _active["stage"] if running else "",
            "has_report": os.path.isfile(os.path.join(core.RESULTS_DIR, f"report_{scan_id}.html"))}


@app.get("/api/scans/{scan_id}/log", dependencies=[Depends(guard)])
def scan_log(scan_id: int, after: int = 0):
    if _active["scan_id"] != scan_id:
        return {"lines": [], "next": after, "running": False}
    logs = _active["logs"]
    after = max(0, min(int(after), len(logs)))
    return {"lines": logs[after:after + 500], "next": min(len(logs), after + 500), "running": _is_running()}


@app.get("/api/scans/{scan_id}/report", dependencies=[Depends(guard)])
def scan_report(scan_id: int):
    path = os.path.join(core.RESULTS_DIR, f"report_{int(scan_id)}.html")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="no report for this scan")
    # Reports escape scan data, and are additionally sandboxed: no scripts, no network.
    return FileResponse(path, media_type="text/html", headers={
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox",
        "X-Content-Type-Options": "nosniff"})


@app.post("/api/scans", dependencies=[Depends(guard)])
def start_scan(req: NewScan):
    if not req.authorized:
        raise HTTPException(status_code=400, detail="You must confirm you are authorized to test this target.")
    if req.profile not in core.SCAN_PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    try:
        target = core.normalize_target(req.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    with _lock:
        if _is_running():
            raise HTTPException(status_code=409, detail=f"scan #{_active['scan_id']} is still running")
        engine = core.ScanEngine(req.target, req.profile, {   # raw: keeps explicit scheme/port
            "os_detect": False, "scripts": False, "stealth": req.profile == "Stealth", "secret_scan": True,
            "enable_web_vuln": req.dast, "nvd": req.nvd, "nuclei": req.nuclei, "dirbuster": False,
            "auth_cookie": req.cookie, "auth_bearer": req.bearer, "auth_headers": [],
            "login_url": req.login_url, "login_data": req.login_data, "submit_forms": req.submit_forms,
        })
        logs = []
        _active.update(engine=engine, scan_id=engine.scan_id, logs=logs, stage="starting", started=time.time())

        def on_log(msg, level):
            if level not in ("muted", "debug") and len(logs) < 20000:
                logs.append({"t": round(time.time() - _active["started"], 1), "level": level, "msg": str(msg)[:600]})

        engine.log_signal.connect(on_log)
        engine.stage_signal.connect(lambda s: _active.update(stage=str(s)))
        thread = threading.Thread(target=engine.run, name=f"scan-{engine.scan_id}", daemon=True)
        _active["thread"] = thread
        thread.start()
    return {"scan_id": engine.scan_id, "target": target}


@app.post("/api/scans/{scan_id}/stop", dependencies=[Depends(guard)])
def stop_scan(scan_id: int):
    if not _is_running() or _active["scan_id"] != scan_id:
        raise HTTPException(status_code=409, detail="that scan is not running")
    _active["engine"].stop()
    return {"stopping": True}


@app.post("/api/triage", dependencies=[Depends(guard)])
def triage(req: Triage):
    try:
        core.DB.set_triage(req.target, req.fingerprint, req.status, req.note)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True}


def main(argv=None):
    global core, PORT
    ap = argparse.ArgumentParser(description="DanishRecon web dashboard (binds to 127.0.0.1 only)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--data-dir", default=os.getcwd(), help="directory that contains (or will contain) results/")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)
    PORT = args.port

    os.makedirs(args.data_dir, exist_ok=True)
    os.chdir(args.data_dir)
    os.environ.setdefault("DISABLE_GEMINI", "true")
    from danishrecon import scan_core
    core = scan_core
    core.DB.mark_stale_scans()

    url = f"http://127.0.0.1:{PORT}/"
    print(f"\n  DanishRecon dashboard: {url}\n  Data: {os.path.abspath(core.RESULTS_DIR)}\n  (Ctrl+C to stop)\n")
    if not args.no_browser:
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
