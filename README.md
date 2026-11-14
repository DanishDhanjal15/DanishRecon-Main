# DanishRecon

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)

An open-source **security toolkit** with three modes that share one engine, one database
and one report format:

| Mode | Input | Command |
|---|---|---|
| Recon + web vulnerability scan | a host or URL | `danishrecon scan <target> --i-am-authorized` |
| Static malware analysis | file(s) or a folder | `danishrecon malware <path>` |
| Network traffic analysis | a .pcap, or a live interface | `danishrecon sniff <pcap>` |

It does not reinvent detection engines. It orchestrates proven open-source tools (nmap,
nuclei, katana, httpx, tshark, YARA), keeps every result in one evidence-backed finding
model, and reports only what was actually observed.

> **Authorized use only.** Scan systems you own or have explicit written permission to
> test. The CLI refuses to scan without `--i-am-authorized`, and the GUI and dashboard ask
> for the same confirmation.

## Install

**New machine? Follow [docs/SETUP.md](docs/SETUP.md)** - step-by-step for Windows, Linux
and macOS, plus a pre-scan checklist and fixes for every "not installed" message.

The short version:

```bash
# 1. Python 3.10+, then DanishRecon in a virtual environment
python -m venv danishrecon-venv
danishrecon-venv\Scripts\activate            # Linux/macOS: source danishrecon-venv/bin/activate
pip install "danishrecon[all]"

# 2. nmap (required) - https://nmap.org/download  (Windows: keep "Npcap" ticked)

# 3. the scanning tools, from their official releases, into ~/.danishrecon/tools
danishrecon setup

# 4. Perl for Nikto (Windows: Strawberry Perl), Wireshark for traffic analysis,
#    Docker Desktop only if you want OpenVAS - see docs/SETUP.md

# 5. check
danishrecon-preflight
```

pip installs the Python code only; the extras pick which parts you get:

```bash
pip install danishrecon                 # scan engine + CLI
pip install "danishrecon[gui]"          # + desktop GUI (PyQt5)
pip install "danishrecon[web]"          # + web dashboard
pip install "danishrecon[malware]"      # + YARA, PE and Office-macro analysis
pip install "danishrecon[openvas]"      # + OpenVAS client (also needs Docker)
pip install "danishrecon[all]"          # gui + web + malware + ai
```

The external programs it drives:

| Tool | Needed for | How to get it |
|---|---|---|
| **nmap** (required) | ports, services, TLS cipher audit | https://nmap.org/download |
| nuclei, katana, httpx, subfinder | crawl, injection tests, exposure templates | `danishrecon setup` |
| Nikto + Perl | extra web-server checks | `danishrecon setup nikto` + Perl |
| Exploit-DB index | exploit references for detected versions | `danishrecon setup exploitdb` |
| rustscan (optional) | fast all-ports discovery (`Full` profile) | `danishrecon setup rustscan` |
| tshark / Wireshark | `danishrecon sniff` | https://www.wireshark.org/download.html |
| OpenVAS (optional) | network vulnerability scan | Docker Desktop + `danishrecon setup openvas` |

A missing optional tool is reported in the scan log as "not tested" with the command that
installs it; it never produces simulated results.

## Use

```bash
# recon + vulnerability scan
danishrecon scan example.com --i-am-authorized
danishrecon scan https://app.example.com --i-am-authorized --profile Full --nuclei
danishrecon scan https://app.example.com --i-am-authorized --cookie "session=abc123"
danishrecon scan example.com --i-am-authorized --fail-on high      # exit code 1 for CI

# static malware analysis (files are never executed)
danishrecon malware suspicious.exe
danishrecon malware ./samples --reputation        # + MalwareBazaar lookup (sends the hash only)

# traffic analysis
danishrecon sniff capture.pcap --ioc-file bad_domains.txt
danishrecon sniff "Wi-Fi" --live --i-am-authorized --duration 60

# front-ends
danishrecon-gui                # desktop GUI
danishrecon-web                # dashboard on http://127.0.0.1:8787
```

Every command writes to `./results/` (or `--output-dir`): an HTML report, `scan_<id>.json`,
`findings_<id>.json` and `scan_<id>.sarif`.

## What a scan does

DNS and subdomains, ports and versions (a fast path on CDN hosts), TLS certificate /
protocol / cipher checks, known CVEs for the detected versions (NVD, CISA KEV, EPSS), a
crawl followed by injection tests on every parameter and submitted form (nuclei DAST),
exposure and misconfiguration templates, leaked secrets, DDoS amplification exposure, and
Exploit-DB references. Details: [docs/FEATURES.md](docs/FEATURES.md).

Every finding carries a **source** (which tool) and a **confidence**:

- `confirmed` - a tool observed the vulnerable behaviour
- `version-match` - the detected version is listed as affected (not verified)
- `exposure` - a service is reachable; not a vulnerability by itself
- `heuristic` - weak signal, needs manual review

## Accuracy

The repository ships a benchmark with known ground truth (`benchmark/`):

- Local ground-truth app: **5/5 expected issues detected, 0 false positives**
  (GET parameter, POST body, behind a login, exposed secret).
- OWASP Juice Shop: **2/10 detected, 0 false positives**. Partial on purpose to show: it is
  a single-page app whose API calls come from JavaScript, which the crawler only partly
  discovers.

```bash
python benchmark/run_benchmark.py --min-recall 1.0 --max-false-positives 0
```

## Privacy

Scan data stays on your machine. Four things can leave it, all optional:

- **NVD / EPSS lookup** sends product identifiers and CVE ids only (`--no-nvd` to disable)
- **MalwareBazaar lookup** sends a file hash, only with `--reputation`
- **Gemini analysis** sends finding summaries to Google, only with `--ai`
- **Login alert (GUI)** sends a WhatsApp message through Twilio, only if you configure it in `.env`

nuclei runs with interactsh disabled, so no out-of-band callbacks go to third parties.

## Limitations

- Form login is a plain POST; logins that need a CSRF token, JavaScript or MFA need `--cookie`.
- No access-control (IDOR) testing and no business-logic testing.
- `version-match` CVEs are not verified; distributions back-port fixes.
- Malware analysis is static only. There is no sandbox, by design.
- The Nikto stage is unreliable on Windows.
- The GUI launches recon scans only; malware and traffic analysis run from the CLI.

## Development

```bash
git clone https://github.com/DanishDhanjal15/DanishRecon-Main
cd DanishRecon-Main
pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
[docs/CHANGES_AND_ROADMAP.md](docs/CHANGES_AND_ROADMAP.md).

## License

MIT - see [LICENSE](LICENSE). DanishRecon started as the CyberRecon-Pro hackathon project.
