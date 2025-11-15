# Another Approach — Lightweight Python Snippet Vulnerability Detector

Small, self-contained pipeline for ingesting Python code snippets, detecting likely vulnerabilities (AST + regex + heuristics), mapping to CWE, optional CVE hints, and computing F1 vs provided gold.

## Input
- JSONL or CSV with columns/fields:
  - `id` (string)
  - `code` (string; full snippet content)
  - `gold_total` (int; optional)
  - `gold_locations` (optional; list of `[start_line, end_line]` pairs)

## Output
- Per-snippet JSON in `outputs/json/ID.json`
- Aggregate CSV `outputs/aggregate.csv`

## Run
```bash
python anotherapproach\run.py --input data.jsonl --format jsonl --out-dir anotherapproach\outputs
```

## Extend
- Add detectors in `detectors.py`
- Map new patterns to CWE in `cwe.py`
- Add CVE mapping by integrating OSV/NVD offline DBs (out of scope here)


