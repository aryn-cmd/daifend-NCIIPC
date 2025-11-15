from typing import List, Tuple, Dict, Any


def f1_from_counts(tp: int, fp: int, fn: int) -> float:
    if tp == 0 and (fp > 0 or fn > 0):
        return 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    if prec + rec == 0:
        return 0.0
    return 2 * prec * rec / (prec + rec)


def match_by_count(detected: int, gold_total: int) -> Tuple[int, int, int, float]:
    tp = min(detected, gold_total)
    fp = max(0, detected - tp)
    fn = max(0, gold_total - tp)
    return tp, fp, fn, f1_from_counts(tp, fp, fn)


def _overlap(a: Tuple[int, int], b: Tuple[int, int]) -> int:
    s = max(a[0], b[0])
    e = min(a[1], b[1])
    return max(0, e - s + 1)


def match_by_locations(detections: List[Tuple[int, int]], gold_locations: List[Tuple[int, int]], min_overlap_ratio: float = 0.3) -> Tuple[int, int, int, float]:
    used_gold = set()
    tp = 0
    for det in detections:
        for i, gold in enumerate(gold_locations):
            if i in used_gold:
                continue
            ov = _overlap(det, gold)
            if ov == 0:
                continue
            ratio = ov / max(1, gold[1] - gold[0] + 1)
            if ratio >= min_overlap_ratio:
                used_gold.add(i)
                tp += 1
                break
    fp = max(0, len(detections) - tp)
    fn = max(0, len(gold_locations) - tp)
    return tp, fp, fn, f1_from_counts(tp, fp, fn)


