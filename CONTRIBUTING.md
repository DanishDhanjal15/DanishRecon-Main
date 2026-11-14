# Contributing

```bash
pip install -e ".[dev]"
python -m unittest discover -s tests -v
python benchmark/run_benchmark.py --min-recall 1.0 --max-false-positives 0   # needs nmap, katana, nuclei
```

Rules that keep the results trustworthy:

1. **No simulated or static findings.** A finding must come from something a tool observed.
   If a tool is missing or fails, say "not tested".
2. **Every finding goes through `Finding`** (`findings.py`) with a `source` and a `confidence`.
3. **Detection changes need the benchmark.** If you change what is detected, run
   `benchmark/run_benchmark.py`; recall must stay 100% with zero false positives on the
   ground-truth app.
4. **Stay in scope.** Requests go only to the scanned host(s).
5. Tests are offline: stub external tools and network calls.
