import csv
import json
from pathlib import Path
from typing import Iterator, Dict, Any, List


def read_jsonl(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def read_csv(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield row


def ensure_dirs(out_dir: str):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    Path(out_dir, "json").mkdir(parents=True, exist_ok=True)


def write_snippet_json(out_dir: str, rec_id: str, payload: Dict[str, Any]):
    p = Path(out_dir, "json", f"{rec_id}.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def write_aggregate_csv(out_path: str, rows: List[Dict[str, Any]]):
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


