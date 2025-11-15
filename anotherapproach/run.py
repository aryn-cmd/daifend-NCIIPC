import argparse
import json
from pathlib import Path
from typing import List, Tuple, Dict, Any

from .detectors import run_all_detectors, merge_overlaps
from .metrics import match_by_count, match_by_locations
from .io_utils import read_jsonl, read_csv, ensure_dirs, write_snippet_json, write_aggregate_csv


def parse_gold_locations(raw) -> List[Tuple[int, int]]:
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except Exception:
            return []
    else:
        data = raw
    out: List[Tuple[int, int]] = []
    for item in data:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            out.append((int(item[0]), int(item[1])))
    return out


def main():
    ap = argparse.ArgumentParser(description="Lightweight Python snippet vulnerability detector")
    ap.add_argument("--input", required=True, help="Path to JSONL or CSV file")
    ap.add_argument("--format", choices=["jsonl", "csv"], required=True)
    ap.add_argument("--out-dir", required=True, help="Output directory for results")
    args = ap.parse_args()

    ensure_dirs(args.out_dir)

    # ingest
    it = read_jsonl(args.input) if args.format == "jsonl" else read_csv(args.input)

    aggregate_rows: List[Dict[str, Any]] = []

    for rec in it:
        rec_id = str(rec.get("id", "unknown"))
        code = rec.get("code", "")
        gold_total = rec.get("gold_total")
        gold_locations = parse_gold_locations(rec.get("gold_locations"))

        findings = [f.to_dict() for f in merge_overlaps(run_all_detectors(code))]
        det_locs = [(f["start_line"], f["end_line"]) for f in findings]

        # metrics
        tp = fp = fn = 0
        f1 = None
        if gold_locations:
            tp, fp, fn, f1 = match_by_locations(det_locs, gold_locations)
        elif gold_total is not None and str(gold_total).strip() != "":
            try:
                g = int(gold_total)
            except Exception:
                g = 0
            tp, fp, fn, f1 = match_by_count(len(findings), g)

        payload = {
            "id": rec_id,
            "findings": findings,
            "metrics": {"tp": tp, "fp": fp, "fn": fn, "f1": f1},
        }
        write_snippet_json(args.out_dir, rec_id, payload)

        aggregate_rows.append({
            "id": rec_id,
            "detected": len(findings),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "f1": f1,
        })

    write_aggregate_csv(str(Path(args.out_dir) / "aggregate.csv"), aggregate_rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


