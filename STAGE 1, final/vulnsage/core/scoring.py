"""
core/scoring.py
---------------
Calculate vulnerability detection accuracy (Precision, Recall, F1)
based on predicted results vs. ground truth.

Also logs timing and per-language stats.
"""

import os
import json
import time
from typing import List, Dict, Any, Tuple


def load_json(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, "r", encoding="utf8") as fh:
        return json.load(fh)


def compute_metrics(predicted: List[Dict[str, Any]], truth: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compare predicted vs truth using CWE and file/line match.
    """
    start = time.time()
    tp = fp = fn = 0
    matched = []

    # Convert truth to searchable index
    truth_index = {(t["file"], t["line"], t["cwe"]): t for t in truth}

    for pred in predicted:
        key = (pred["file"], pred["line"], pred["cwe"])
        if key in truth_index:
            tp += 1
            matched.append(key)
        else:
            fp += 1

    # Count missed ones
    for key in truth_index.keys():
        if key not in matched:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    elapsed = round((time.time() - start) * 1000, 2)

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "time_ms": elapsed
    }


def evaluate(predicted_path: str, truth_path: str, save: bool = True) -> Dict[str, Any]:
    """
    Load data, compute metrics, save results.
    """
    predicted = load_json(predicted_path)
    truth = load_json(truth_path)

    result = compute_metrics(predicted, truth)

    if save:
        os.makedirs("output", exist_ok=True)
        outp = os.path.join("output", "scoring_results.json")
        with open(outp, "w", encoding="utf8") as fo:
            json.dump(result, fo, indent=2)
        print(f"[INFO] Scoring results saved: {outp}")

    print(f"[SCORE] TP={result['true_positives']} FP={result['false_positives']} FN={result['false_negatives']}")
    print(f"[SCORE] Precision={result['precision']} Recall={result['recall']} F1={result['f1_score']} Time={result['time_ms']} ms")

    return result


# CLI
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Compute detection accuracy (F1 score).")
    parser.add_argument("--pred", required=True, help="Predicted merged results JSON path")
    parser.add_argument("--truth", required=True, help="Ground truth JSON path")
    args = parser.parse_args()

    evaluate(args.pred, args.truth)
