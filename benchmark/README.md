# Benchmark

Measures what the scanner actually finds against targets whose vulnerabilities are known.

## 1. Ground-truth app (scored automatically)

`ground_truth_app.py` is a small deliberately vulnerable app that binds to 127.0.0.1 only.
Its issues - and its known-safe endpoints - are listed in `expected.json`.

```bash
python benchmark/run_benchmark.py
python benchmark/run_benchmark.py --min-recall 1.0 --max-false-positives 0   # regression gate
python benchmark/run_benchmark.py --no-login      # shows what is missed without a session
```

The runner starts the app on a free port, runs the real CLI against it (with form login),
and scores the structured findings:

| | meaning |
|---|---|
| detected | an expected issue reported with the same category, path and parameter |
| missed | an expected issue that was not reported |
| false positive | a confirmed finding on an endpoint that is known to be safe |

Current result (profile `Quick`, authenticated): **5/5 detected, 0 false positives**.

On OWASP Juice Shop (a real SPA, see below) the scanner currently detects **2/10 + 4 extra
confirmed, 0 false positives** - partial by design, since most of its API is JS-driven.

It covers GET parameters, a POST form body, an endpoint behind a login, and an exposed
secret - plus three safe endpoints designed to trip naive checks (a page that mentions
"database", a page whose length changes on every request, and an HTML-escaped echo).

Needs on PATH: nmap, katana, nuclei (with templates).

## 2. OWASP Juice Shop (scored against a real app)

`juice-shop.expected.json` lists 10 issues that were **verified by hand** against a local
Juice Shop container on 2026-11-14 (SQL injection in product search and in login, an open
redirect, exposed `/ftp` `/encryptionkeys` `/support/logs` listings, `/metrics`,
`/api-docs`, the unauthenticated admin configuration, and a wildcard CORS header). Only
issues an external web scanner could reach are listed - client-side-only, CAPTCHA and
pure business-logic challenges are left out on purpose.

```bash
docker compose -f benchmark/docker-compose.yml up -d juice-shop
python benchmark/run_benchmark.py --url http://127.0.0.1:3000 \
    --expected benchmark/juice-shop.expected.json --nuclei
docker compose -f benchmark/docker-compose.yml down
```

**Recall here is expected to be partial, and that is the point.** Juice Shop is a
single-page app: most endpoints are called over JavaScript XHR, which an external crawler
only partly discovers. This run shows where the crawler and the template/DAST coverage
need to improve; `benchmark_result.md` lists what was detected, what was missed, and any
extra confirmed findings. It is a yardstick, not a pass/fail gate.

## 3. DVWA (manual)

```bash
docker compose -f benchmark/docker-compose.yml up -d dvwa
danishrecon scan http://127.0.0.1:4280 --i-am-authorized --profile Quick --no-nvd
docker compose -f benchmark/docker-compose.yml down
```

DVWA needs a first-run database setup (`/setup.php`) and its login carries a CSRF token, so
a plain form login will not work - grab a `PHPSESSID` from a browser session and pass it
with `--cookie` for authenticated coverage.
