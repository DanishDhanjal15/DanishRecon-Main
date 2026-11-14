# DanishRecon - Feature Reference

What each stage really does, which tool does it, and how far its results can be trusted.
For setup see [README.md](../README.md).

## Modes

| Mode | Input | What it does |
|---|---|---|
| **Recon + vuln scan** | host / URL | the pipeline below (ports, TLS, CVEs, crawl, DAST, secrets, exposures) |
| **Malware analysis** (static) | file(s) / folder | hash, type, entropy, strings/IOCs, PE imports, Office macros, YARA, optional hash reputation. Files are never executed. |
| **Traffic analysis** | .pcap or live interface | cleartext creds, plain HTTP, insecure protocols, DNS/HTTP/TLS inventory, threat-intel IOC hits (via tshark) |

All three share one Finding model, database (findings / triage / diff), report and SARIF output.

## Finding confidence

| Confidence | Meaning | Example |
|---|---|---|
| `confirmed` | A tool observed the vulnerable behaviour | nuclei DAST matched a SQL error after injecting a parameter |
| `version-match` | The detected version is listed as affected; not verified | NVD lists CVE-2021-41773 for Apache httpd 2.4.49 |
| `exposure` | A service is reachable; not a vulnerability by itself | SSH open on port 22 |
| `heuristic` | Weak signal that needs manual review | JWT-looking string in a page |

## Pipeline

| # | Stage | Tool | Notes |
|---|---|---|---|
| 1 | DNS records, SPF/DMARC | dig / nslookup | missing SPF is reported as MEDIUM |
| 2 | Subdomain discovery | subfinder (fallback: 10 common names) | |
| 3 | Host discovery | TCP connect, nmap `-sn` fallback | |
| 4 | Certificate check | real TLS handshake | expired = HIGH, untrusted = MEDIUM, expiring < 30 d = LOW |
| 5 | Ports / services / versions | nmap (`Quick` top 100, `Custom` top 500, `Stealth` top 1000, `Full` all). RustScan (optional) does fast all-ports discovery for `Full`, then nmap `-sV` on the open ports. | socket fallback when nmap cannot run; CDN hosts use a fast web-port scan |
| 6 | TLS protocol support | handshake per protocol version | TLS 1.0 / 1.1 accepted = MEDIUM; grade is indicative only |
| 6b | TLS cipher audit | nmap `ssl-enum-ciphers` | cipher suites graded C or worse are reported |
| 7 | CVE lookup | NVD API by nmap CPE | `version-match`; CISA KEV flagged and sorted first; EPSS score attached |
| 7b | Subdomain takeover | nuclei takeover templates | domains only |
| 7c | DDoS amplification/reflection exposure | one small UDP probe per vector (DNS/NTP/memcached/SSDP/SNMP/chargen) | confirmed reflectors with amplification factor; defensive, not a flood |
| 8 | WAF detection | wafw00f (fallback: response headers) | informational |
| 9 | Web discovery | httpx + katana | same-host scope, depth 3, time-boxed; uses the session cookie; fills and submits forms |
| 10 | Server checks | Nikto | a failed run is reported as "not tested" |
| 11 | Network vulnerability scan | OpenVAS / GVM (optional, Docker) | skipped when the daemon is not running |
| 12 | API endpoint discovery | built-in path list | |
| 13 | Injection testing (DAST) | nuclei `-dast` on crawled GET parameters and submitted POST forms | SQLi, XSS, SSTI, LFI, RFI, SSRF, XXE, CRLF, open redirect, command injection |
| 14 | Secret scanning | regex over crawled pages / JS / `.env` | values are masked in every output |
| 15 | Template scan (optional) | nuclei default templates | misconfigurations, exposures, known CVEs |
| 16 | Directory discovery (optional) | built-in brute-forcer + DirBuster wordlist | |
| 17 | Exploit references | local Exploit-DB index | exact version or `< x` bound; references only, nothing is executed |
| 18 | Exposure ranking, MITRE mapping | built-in | a CVE is attached only when the version rule matches |
| 19 | AI explanation (optional) | Gemini | explanation only - never used for detection |
| 20 | Reports | built-in | HTML, Markdown, JSON, CSV, PDF, SARIF |

## Tracking

Structured findings are stored per scan. A finding's fingerprint (tool, category, title,
host, port, path, parameter, CVE) stays stable across scans, which gives:

- triage per target: open / fixed / accepted / false positive (web dashboard)
- a diff against the previous completed scan of the same target: new, gone, still present

## Outputs

`results/report_<id>.html`, `report_<id>.md`, `scan_<id>.json`, `vulns_<id>.csv`, and from
the CLI also `findings_<id>.json` (structured findings) and `scan_<id>.sarif`.

## What it does not do

- No exploitation, privilege escalation or brute-forcing of credentials
- Form login is a plain POST - logins needing a CSRF token, JavaScript or MFA need a cookie instead
- No business-logic or access-control (IDOR) testing - that needs two user sessions
- No compliance certification: the compliance section lists controls to review
- "Potential attack paths" are hypothetical scenarios derived from exposed service types

## Scope and safety controls

- Targets are validated before use (hostname / IPv4 / CIDR only)
- The GUI asks for authorization once per target; the CLI requires `--i-am-authorized`
- Crawling and fuzzing stay on the scanned host(s); third-party hosts are never tested
- nuclei runs without interactsh (no out-of-band callbacks to external servers)
