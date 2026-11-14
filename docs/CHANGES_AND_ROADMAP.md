# DanishRecon - Changes Log & Roadmap

## v0.7.1

- **`danishrecon setup`**: installs Nikto, the Exploit-DB index, nuclei / katana / httpx /
  subfinder and rustscan from their official releases into `~/.danishrecon/tools`
  (`DANISHRECON_TOOLS` to override); `setup openvas` writes a compose file and starts the
  OpenVAS container when Docker is running; `setup --list` shows what is where.
- Every tool lookup (scan engine, preflight, GUI) searches that folder first, so a pip install
  run from any directory finds the tools. Previously Nikto and the Exploit-DB index were only
  found in the directory the scan was started from ("Nikto script not found").
- OpenVAS: the stage now says exactly why it is skipped (GMP client missing / Docker not
  installed / Docker not running / no container / login failed) and how to fix it; the
  leftover `[!!!OPENVAS!!!]` debug output is gone.
- GUI: optional tools that are not installed (e.g. rustscan) are listed once, quietly,
  instead of as an orange warning; the welcome text shows the real command names.

## v0.7.0 packaging

- The project is now a pip-installable package (`danishrecon`, `src/` layout) with entry
  points `danishrecon`, `danishrecon-gui`, `danishrecon-web`, `danishrecon-preflight` and
  optional extras (`gui`, `web`, `malware`, `ai`, `openvas`).
- Importing the package has no side effects: the results folder and the SQLite database
  are created on first use, in the working directory (or `DANISHRECON_RESULTS`).
- `.env` is read from the working directory. Nikto / Exploit-DB are found via
  `NIKTO_PATH` / `EXPLOITDB_PATH` or a checkout in the working directory.
- Older entries below mention the pre-packaging file names (`cli.py`, `CyberRecon-Pro/`).

## v0.7 - beyond recon: malware + traffic analysis (current)

The project is now a security **toolkit**, not only a vuln scanner. Two new engines
(`analysis_core.py`) reuse the same Finding model, database (findings / triage / diff),
reporting (HTML/JSON/SARIF) and the dashboard's scan list:

- **Malware module (static only - files are never executed):** SHA-256/MD5, file-type by
  magic bytes, Shannon entropy (packer hint), string + IOC extraction (URL/IP/domain/
  registry/BTC), PE import/section analysis (`pefile`), Office VBA macro analysis
  (`oletools`), YARA matching (`yara-python`) with a bundled starter rule set
  (`yara_rules/`), and an opt-in MalwareBazaar hash reputation lookup. Verified: PE imports,
  IOCs and YARA (EICAR/web-shell/PowerShell) all detected; clean files stay quiet.
- **Sniffer module (tshark):** analyzes a .pcap (default) or a live capture (opt-in,
  `--i-am-authorized`, needs Npcap/root). Finds cleartext credentials (HTTP Basic / FTP /
  Telnet / POP3 / IMAP), plain HTTP, insecure protocols, a DNS/HTTP/TLS inventory, top
  talkers, and threat-intel IOC hits. Verified end-to-end on a crafted pcap (5/5 issues).
- **Shared plumbing:** `Finding` gained optional `file` / `sha256` / `artifact_type`; the
  `scans` table gained `scan_type` (recon / malware / sniff) with an auto-migration; CLI is
  now subcommand-based (`scan` / `malware` / `sniff`), with a bare target still defaulting to
  `scan` for back-compat. Dashboard lists all three scan types (shared DB).
- **DDoS amplification/reflection exposure check** (`amplification.py`, new recon stage):
  one small UDP probe per vector (open DNS resolver, NTP monlist, memcached, SSDP, SNMP
  'public', chargen); a service that answers with a larger reply is a confirmed reflector,
  reported with its amplification factor. Defensive - a single probe packet, never a flood.
- **Botnet / DDoS-agent YARA rules** (`yara_rules/botnet.yar`): Mirai, Gafgyt/Bashlite,
  generic DDoS command strings, classic agents (Trinoo/TFN/Stacheldraht/Shaft), IRC bots -
  loaded automatically by the malware module.
- 99 offline tests (30 new for the analysis engines, CDN, rustscan, amplification, botnet).

Out of scope on purpose: malware **detonation / sandboxing** (dangerous on the host - use an
isolated VM/CAPE), and ARP-spoof / MITM capture (active interception, not passive analysis).

### Still to wire
- GUI tabs to *launch* malware/sniffer runs (results are already viewable via the dashboard
  and the HTML/SARIF reports; the desktop GUI only launches recon scans for now).
- Juice Shop benchmark now detects 2/10 + 4 extra confirmed (CORS, /metrics, ...); the
  parameter-level misses need the headless-browser crawl (below).

## v0.6 - real-app benchmark + unified findings

- **Juice Shop benchmark** (`benchmark/juice-shop.expected.json`): 10 issues verified by
  hand against a local OWASP Juice Shop container. `run_benchmark.py` now also scans an
  already-running target (`--url`) against any ground-truth file (`--expected`), with
  category-list / path-prefix / keyword matching. 8 scorer tests added.
- **The benchmark immediately exposed two real gaps, now fixed:**
  1. The full nuclei **template** scan and the **API scanner's CORS / broken-auth**
     findings were written only to the legacy `vulns` table, never to the structured
     findings store - so they were invisible to the report's findings list, the dashboard,
     SARIF, the diff and the benchmark. Both now go through `_add_finding`, with the nuclei
     template id/tags mapped to a finding category (exposure / misconfig / exposed-panel /
     cve / sqli / ...). The template scan now also reuses the crawled URLs and the shared
     tool wrapper, and sends the session cookie.
  2. (already in v0.5) a target URL's explicit port was dropped.
- **Nuclei template scan is now reliable.** The full ~9000-template set timed out (Quick
  budget) before reaching the high-value exposure templates, so nothing was reported.
  The template stage now targets exposure / misconfig / panel / default-login / takeover /
  git / swagger / backup tags (the `Full` profile still runs the whole set), which finishes
  in budget and flags e.g. `/metrics` and `/api-docs`.
- **CDN-aware port scan (fixes the slow danishdhanjal.xyz scan).** A host behind a CDN
  (Vercel, Cloudflare, Netlify, ...) is detected from DNS and from the live Server / CDN
  headers. On such a host the port scan drops to a fast connect scan of the web ports and
  skips `-sV` and `-O`: a Vercel host that took ~95-100 s/host (and produced junk OS guesses)
  now takes ~2 s and still reports 80/443; httpx does the web fingerprinting. OS detection
  is skipped with a clear reason instead of printing unreliable guesses.
- Total 75 offline tests.

### Known gap the benchmark measured
- Against Juice Shop (a single-page app) the crawler finds many URLs but few query
  parameters, because the app's real API calls are issued from JavaScript (XHR) with JSON
  bodies. Katana's `-jc`/`-aff` only partly recovers these, so parameter-level checks
  (search SQLi, login SQLi, open redirect) have low recall there. A headless-browser crawl
  and JSON-body fuzzing are the next step; exposure/misconfig issues (`/metrics`,
  `/api-docs`, `/ftp`, admin config, CORS) are covered by the template scan.

## v0.5 - engine split, authenticated scanning, tracking, dashboard

- **`scan_core.py`**: the scan engine no longer lives in the GUI module and has no Qt
  dependency. The desktop GUI wraps it in a `QThread`; the CLI, the dashboard and the
  Docker image use it directly.
- **Authenticated scanning**: `--cookie`, `--bearer`, `--header`, or `--login-url` +
  `--login-data`; the session is passed to httpx, katana and nuclei. GUI and dashboard
  have the same fields.
- **POST forms**: katana fills and submits forms; nuclei replays those requests and fuzzes
  the body parameters.
- **Target port respected**: `http://host:3000/` used to be reduced to `host`, so an app
  on a non-standard port was never scanned (found by the benchmark).
- **Findings database**: every structured finding is stored per scan; triage status
  (open / fixed / accepted / false positive) is remembered per target; each scan is
  diffed against the previous completed scan of the same target (new / gone / still there).
- **More checks**: TLS cipher-suite audit (nmap `ssl-enum-ciphers`), subdomain-takeover
  templates, EPSS scores on CVEs, 14 more secret patterns.
- **Web dashboard** (`webapp/`): start scans, live log, filter + triage findings, diff.
  Loopback only, per-start API token, Host-header check.
- **Benchmark** (`benchmark/`): ground-truth app + scoring script. Result: 5/5 expected
  issues detected (GET, POST body, behind login, secret), 0 false positives.
- 60 offline tests.

## v0.4 - "Trustworthy results"

The scanner was audited against a local test application with known ground truth. The
audit showed that most report content was static or wrong, so this release is about
accuracy first.

### Before / after on the ground-truth test app

| Ground truth | Before | Now |
|---|---|---|
| Real SQL injection (`/product?id=`) | missed (no crawler, 4 hardcoded paths) | **found** - katana crawl + nuclei DAST, with evidence |
| Real reflected XSS (`/search?q=`) | missed (no XSS check existed) | **found** |
| Safe pages | 5 "CRITICAL SQLi" + 3 "HIGH IDOR" false positives | 0 false positives |
| Exposed AWS key in `/.env` | found | found |
| Python test server on :8080 | reported Apache 2.4.49 RCE CVEs | no invented CVEs |
| Closed port 443 | "TLS Grade A, Let's Encrypt, 75 days" (fabricated) | "no TLS service reachable" |
| Exploit list | searchsploit help text | version-matched Exploit-DB references only |

### Removed fake / static data
- CVEs are no longer assigned from the service name. Built-in rules must match the
  detected version (`matched_cves`), and the NVD is queried by nmap CPE.
- TLS analyzer: the simulated "Grade A" fallback is gone; valid certificates are no longer
  reported as invalid (the certificate is now parsed from the real handshake).
- Nuclei wrapper: no demo findings when nuclei is missing.
- "No WAF detected" is no longer a MEDIUM vulnerability; compliance no longer says "PASS";
  attack paths are labelled hypothetical.
- Nikto / searchsploit error output is no longer listed as findings.

### New
- `findings.py` - structured `Finding` (source, confidence, evidence, CVE, KEV) + SARIF export
- `recon_tools.py` - httpx fingerprinting, katana crawl (same-host scope), nuclei DAST
- `cve_lookup.py` - NVD lookup by CPE with a 7-day cache, CISA KEV flag
- `exploit_search.py` - cross-platform Exploit-DB index search (replaces the bash script)
- `cli.py` - headless runner, `--fail-on` exit codes for CI, mandatory `--i-am-authorized`
- `Dockerfile`, GitHub Actions workflow, offline regression tests (`tests/`)

### Reliability and safety fixes
- Stage isolation: one failing stage is logged and the scan continues (`stage_errors`).
- Stopped / failed scans are finalised in the database and release the GUI; stale
  `running` rows are marked `interrupted` at start-up.
- Target validation (`normalize_target`) - nothing unvalidated reaches nmap / nikto.
- Authorization confirmation per target in the GUI.
- HTML reports escape all scan-derived text.
- Scout assistant binds to `127.0.0.1` instead of `0.0.0.0`.
- GUI: every finding used to trigger a CRITICAL alert (`"" in item` was always true).
- Nuclei: `-timeout` is per request (was given the whole scan budget); CVE ids are read
  from `info.classification`; interactsh disabled.
- Launcher: no hardcoded user paths or phone numbers.

## Roadmap

### Next (engine)
- Split `scan_core.py` further into a `stages/` package with a plugin registry
- Headless-browser crawl for single-page apps (JSON APIs called from JavaScript)
- Logins that need a CSRF token / JavaScript; two-session access-control (IDOR) testing
- Parallel per-host stages, resumable scans, structured logging
- OWASP ZAP baseline as an additional stage (not integrated yet)
- Cloud-bucket checks

### Later (product)
- Dashboard: trend charts over time, multi-user access with authentication
- AI used only for triage and explanation, never for detection
- Scored benchmark against DVWA, Juice Shop and WebGoat (compose file exists; needs
  per-app ground-truth lists) and a comparison with ZAP

### Verify before relying on
- The Docker image was built and scanned the benchmark app correctly from inside the
  container (all expected issues found). The GitHub Actions workflow has not run yet.
- Nikto fails to connect on Windows against some servers but works in the Docker image;
  treat it as Linux/Docker-only.
- The dashboard's API is covered by tests; its page was not checked in a browser yet.
- OWASP ZAP is not integrated; Juice Shop / DVWA have a compose file but no scored run.
