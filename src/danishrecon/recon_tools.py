"""Thin, testable wrappers around the ProjectDiscovery tools the pipeline orchestrates.

  httpx   - probe web services, fingerprint technologies
  katana  - crawl an application and collect URLs / parameters / forms
  nuclei  - template-based checks, including DAST (parameter fuzzing) templates

The wrappers only build command lines and parse JSONL output; all detection logic lives
in the upstream tools and their community-maintained templates. Every wrapper honours a
``stop_check`` callback so a user stop kills the child process promptly.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Callable, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

_STATIC_EXT = ("png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot,otf,mp4,mp3,avi,mov,webp,"
               "pdf,zip,gz,tar,rar,7z,exe,dmg,iso,map")

_tool_cache: Dict[str, Optional[str]] = {}


def _candidates(name: str) -> List[str]:
    exe = name + (".exe" if os.name == "nt" else "")
    gopath = os.environ.get("GOPATH") or os.path.join(os.path.expanduser("~"), "go")
    from danishrecon.tools import bin_path       # per-user tools folder (danishrecon setup)
    paths = [str(bin_path(name)),
             os.path.join(gopath, "bin", exe),
             os.path.join(os.path.expanduser("~"), "go", "bin", exe),
             "/usr/local/bin/" + name, "/usr/bin/" + name, "/root/go/bin/" + name]
    which = shutil.which(name)
    if which:
        paths.append(which)
    return paths


def find_tool(name: str) -> Optional[str]:
    """Locate a ProjectDiscovery binary (Go install dir first, then PATH).

    For ``httpx`` the binary is verified, because the unrelated Python ``httpx`` package
    installs a CLI with the same name.
    """
    if name in _tool_cache:
        return _tool_cache[name]
    found = None
    for path in _candidates(name):
        if not (path and os.path.isfile(path)):
            continue
        if name == "httpx":
            try:
                r = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=15)
                if "current version" not in (r.stdout + r.stderr).lower():
                    continue
            except Exception:
                continue
        found = path
        break
    _tool_cache[name] = found
    return found


def run_tool(cmd: List[str], budget: int, stop_check: Optional[Callable[[], bool]] = None) -> Dict:
    """Run ``cmd`` for at most ``budget`` seconds; kill it on timeout or user stop.

    Output goes to temp files (not pipes) so a chatty tool can never dead-lock us.
    """
    out_f = tempfile.TemporaryFile()
    err_f = tempfile.TemporaryFile()
    started = time.time()
    status = "ok"
    try:
        proc = subprocess.Popen(cmd, stdout=out_f, stderr=err_f, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return {"status": "not_found", "stdout": "", "stderr": "", "returncode": None, "seconds": 0.0}
    try:
        while proc.poll() is None:
            if stop_check and stop_check():
                status = "stopped"
                break
            if time.time() - started > budget:
                status = "timeout"
                break
            time.sleep(0.25)
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
        out_f.seek(0)
        err_f.seek(0)
        return {"status": status,
                "stdout": out_f.read().decode("utf-8", errors="replace"),
                "stderr": err_f.read().decode("utf-8", errors="replace"),
                "returncode": proc.returncode,
                "seconds": round(time.time() - started, 1)}
    finally:
        out_f.close()
        err_f.close()


def _jsonl(text: str) -> Iterable[dict]:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _write_list(items: Iterable[str]) -> str:
    fd, path = tempfile.mkstemp(prefix="cyberrecon_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(items) + "\n")
    return path


# ───────────────────────────── scope helpers ──────────────────────────────

def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def in_scope(url: str, allowed_hosts: Iterable[str]) -> bool:
    """True only for http(s) URLs whose host is exactly one of ``allowed_hosts``."""
    parts = urlsplit(url)
    return parts.scheme in ("http", "https") and (parts.hostname or "").lower() in \
        {h.lower() for h in allowed_hosts}


def canonical_param_url(url: str) -> str:
    """Identity of a parameterised URL ignoring values: scheme://host/path?a&b."""
    p = urlsplit(url)
    names = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})
    return urlunsplit((p.scheme, p.netloc.lower(), p.path, "&".join(names), ""))


def _header_args(headers: Optional[List[str]]) -> List[str]:
    """['Cookie: a=b', ...] -> ['-H', 'Cookie: a=b', ...] (CR/LF stripped)."""
    args: List[str] = []
    for h in headers or []:
        h = str(h).replace("\r", " ").replace("\n", " ").strip()
        if ":" in h:
            args += ["-H", h]
    return args


def login_for_cookie(login_url: str, form_data: str, allowed_hosts: Iterable[str],
                     timeout: int = 15) -> Dict:
    """POST ``form_data`` ('user=a&password=b') to ``login_url`` and return the session
    cookies as a Cookie header value. The login URL must be in scope."""
    import requests
    if not in_scope(login_url, allowed_hosts):
        return {"ok": False, "cookie": "", "error": "login URL is outside the scan scope"}
    try:
        session = requests.Session()
        session.verify = False
        resp = session.post(login_url, data=dict(parse_qsl(form_data, keep_blank_values=True)),
                            timeout=timeout, allow_redirects=True)
        cookie = "; ".join(f"{c.name}={c.value}" for c in session.cookies)
        if not cookie:
            return {"ok": False, "cookie": "", "error": f"no session cookie was set (HTTP {resp.status_code})"}
        return {"ok": True, "cookie": cookie, "error": None, "status": resp.status_code}
    except Exception as e:
        return {"ok": False, "cookie": "", "error": f"{type(e).__name__}: {str(e)[:120]}"}


# ─────────────────────────────── httpx ────────────────────────────────────

def httpx_probe(urls: List[str], budget: int = 120, rate: int = 50,
                stop_check: Optional[Callable[[], bool]] = None,
                headers: Optional[List[str]] = None) -> Dict:
    """Probe URLs; returns {'available', 'status', 'results': [{url,status,title,server,tech}]}."""
    binary = find_tool("httpx")
    if not binary:
        return {"available": False, "status": "not_found", "results": []}
    if not urls:
        return {"available": True, "status": "ok", "results": []}
    list_file = _write_list(urls)
    try:
        cmd = [binary, "-l", list_file, "-silent", "-j", "-sc", "-title", "-server", "-td",
               "-timeout", "10", "-rl", str(rate), "-nc", "-duc"] + _header_args(headers)
        r = run_tool(cmd, budget, stop_check)
    finally:
        os.unlink(list_file)
    results = []
    for e in _jsonl(r["stdout"]):
        results.append({
            "url": e.get("url", ""),
            "input": e.get("input", ""),
            "status": e.get("status_code"),
            "title": e.get("title", ""),
            "server": e.get("webserver", ""),
            "tech": e.get("tech") or [],
        })
    return {"available": True, "status": r["status"], "results": results, "seconds": r["seconds"]}


# ─────────────────────────────── katana ───────────────────────────────────

def katana_crawl(start_url: str, depth: int = 3, duration: int = 120, rate: int = 50,
                 stop_check: Optional[Callable[[], bool]] = None,
                 headers: Optional[List[str]] = None, submit_forms: bool = True) -> Dict:
    """Crawl one application, staying on the start URL's exact host.

    Returns {'available', 'status', 'urls', 'param_urls', 'forms'} where ``param_urls`` are
    unique GET URLs with a query string (one per distinct parameter set) and ``forms`` are
    the HTML forms found ({action, method, parameters}).

    ``headers`` (e.g. a session cookie) are sent with every request, so the crawl can reach
    pages behind a login. With ``submit_forms`` katana fills and submits forms with dummy
    values; the resulting non-GET requests are returned in ``post_requests`` as raw katana
    JSONL lines, which nuclei can replay and fuzz (``nuclei_run(input_jsonl=...)``).
    """
    binary = find_tool("katana")
    empty = {"available": bool(binary), "status": "not_found", "urls": [], "param_urls": [],
             "forms": [], "post_requests": []}
    if not binary:
        return empty
    scope = [host_of(start_url)]
    cmd = [binary, "-u", start_url, "-d", str(depth), "-jc", "-kf", "all",
           "-fx", "-fs", "fqdn", "-ct", f"{int(duration)}s", "-rl", str(rate), "-c", "10",
           "-timeout", "10", "-ef", _STATIC_EXT, "-silent", "-j", "-nc", "-duc"]
    if submit_forms:
        cmd.append("-aff")
    cmd += _header_args(headers)
    r = run_tool(cmd, duration + 30, stop_check)

    urls, forms, seen_forms = [], [], set()
    seen_urls = set()
    post_requests, seen_posts = [], set()
    for e in _jsonl(r["stdout"]):
        req = e.get("request") or {}
        endpoint = req.get("endpoint") or ""
        method = (req.get("method") or "GET").upper()
        if method != "GET":
            # a submitted form: keep the full request so its body parameters can be fuzzed
            body_names = tuple(sorted(k for k, _ in parse_qsl(req.get("body") or "", keep_blank_values=True)))
            key = (method, endpoint.split("?")[0], body_names)
            if endpoint and body_names and in_scope(endpoint, scope) and key not in seen_posts:
                seen_posts.add(key)
                post_requests.append(json.dumps(e, separators=(",", ":")))
            continue
        if endpoint and in_scope(endpoint, scope) and endpoint not in seen_urls:
            seen_urls.add(endpoint)
            urls.append(endpoint)
        for form in (e.get("response") or {}).get("forms") or []:
            action = urljoin(endpoint or start_url, form.get("action") or "")
            method = (form.get("method") or "GET").upper()
            params = [p for p in (form.get("parameters") or []) if p]
            key = (action, method, tuple(sorted(params)))
            if params and in_scope(action, scope) and key not in seen_forms:
                seen_forms.add(key)
                forms.append({"action": action, "method": method, "parameters": params})

    # GET forms are just parameterised URLs - make them testable.
    for form in forms:
        if form["method"] == "GET":
            base = form["action"].split("?")[0]
            candidate = base + "?" + urlencode({p: "1" for p in form["parameters"]})
            if candidate not in seen_urls:
                seen_urls.add(candidate)
                urls.append(candidate)

    param_urls, seen_param = [], set()
    for u in urls:
        if "?" in u and urlsplit(u).query:
            key = canonical_param_url(u)
            if key not in seen_param:
                seen_param.add(key)
                param_urls.append(u)

    status = r["status"]
    if status == "ok" and not urls and r["returncode"] not in (0, None):
        status = "error"   # the tool rejected its arguments or crashed - not "nothing found"
    return {"available": True, "status": status, "urls": urls, "param_urls": param_urls,
            "forms": forms, "post_requests": post_requests, "seconds": r["seconds"],
            "stderr_tail": (r["stderr"] or r["stdout"])[-400:] if status == "error" else ""}


# ─────────────────────────────── nuclei ───────────────────────────────────

def parse_nuclei_entry(entry: dict) -> Dict:
    """Normalise one nuclei JSONL result."""
    info = entry.get("info") or {}
    cls = info.get("classification") or {}

    def _join(v):
        if isinstance(v, (list, tuple)):
            return ", ".join(str(x) for x in v if x)
        return str(v or "")

    severity = str(info.get("severity") or "info").upper()
    try:
        cvss = float(cls.get("cvss-score") or 0.0)
    except (TypeError, ValueError):
        cvss = 0.0
    refs = info.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    extracted = entry.get("extracted-results") or []
    evidence_bits = []
    if entry.get("matcher-name"):
        evidence_bits.append(f"matcher={entry['matcher-name']}")
    if extracted:
        evidence_bits.append("extracted=" + ", ".join(str(x) for x in extracted[:3])[:200])
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    return {
        "template_id": entry.get("template-id", ""),
        "name": info.get("name") or entry.get("template-id", "nuclei finding"),
        "severity": "INFO" if severity == "UNKNOWN" else severity,
        "cvss": cvss,
        "cve": _join(cls.get("cve-id")).upper(),
        "cwe": _join(cls.get("cwe-id")).upper(),
        "description": (info.get("description") or "").strip(),
        "remediation": (info.get("remediation") or "").strip(),
        "references": [str(x) for x in refs][:5],
        "matched_at": entry.get("matched-at") or entry.get("url") or entry.get("host") or "",
        "url": entry.get("url") or entry.get("matched-at") or "",
        "host": entry.get("host", ""),
        "parameter": entry.get("fuzzing_parameter") or "",
        "method": entry.get("fuzzing_method") or "",
        "type": entry.get("type", ""),
        "tags": tags,
        "evidence": "; ".join(evidence_bits),
    }


def nuclei_run(urls: List[str], dast: bool = False,
               severities: Optional[List[str]] = None, budget: int = 600, rate: int = 50,
               extra: Optional[List[str]] = None,
               stop_check: Optional[Callable[[], bool]] = None,
               headers: Optional[List[str]] = None,
               input_jsonl: Optional[List[str]] = None) -> Dict:
    """Run nuclei over ``urls``.

    dast=False -> the normal template set (misconfigurations, exposures, known CVEs).
    dast=True  -> only the DAST (fuzzing) templates, which test each URL parameter for
                  injection classes such as SQLi, XSS, SSTI, LFI, open redirect, SSRF.

    ``input_jsonl`` - raw katana JSONL request records (e.g. submitted POST forms); when
    given, nuclei replays those requests instead of ``urls`` and fuzzes their bodies too.
    ``headers`` are added to every request (session cookie / bearer token).
    """
    binary = find_tool("nuclei")
    if not binary:
        return {"available": False, "status": "not_found", "findings": []}
    if not urls and not input_jsonl:
        return {"available": True, "status": "ok", "findings": [], "seconds": 0.0}
    list_file = _write_list(input_jsonl if input_jsonl else urls)
    try:
        # -ni: no interactsh/OAST - nothing about the scan is sent to a third-party server.
        cmd = [binary, "-l", list_file, "-jsonl", "-silent", "-nc", "-duc", "-ot", "-or",
               "-ni", "-rl", str(rate), "-c", "10", "-bs", "10", "-timeout", "10"]
        if input_jsonl:
            cmd += ["-im", "jsonl"]
        cmd += _header_args(headers)
        if dast:
            cmd.append("-dast")
        if severities:
            cmd += ["-severity", ",".join(severities)]
        cmd += list(extra or [])
        r = run_tool(cmd, budget, stop_check)
    finally:
        os.unlink(list_file)
    findings = [parse_nuclei_entry(e) for e in _jsonl(r["stdout"]) if e.get("template-id")]
    status = r["status"]
    if status == "ok" and not findings and r["returncode"] not in (0, None):
        status = "error"
    return {"available": True, "status": status, "findings": findings,
            "seconds": r["seconds"], "stderr_tail": r["stderr"][-600:]}
