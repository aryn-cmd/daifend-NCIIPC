"""
core/merge_results.py
---------------------
Combine rule-based vulnerability findings and dependency CVE matches
into a unified dataset for scoring and reporting.
"""

import os
import json
from typing import Any, List, Dict, Optional
from json import JSONDecodeError


def load_findings(path: str) -> Any:
    """
    Load JSON findings (from rule_engine or cve_mapper outputs).
    Returns parsed JSON or None on error.
    """
    if not path:
        return None
    if not os.path.exists(path):
        print(f"[WARN] File not found: {path}")
        return None
    try:
        with open(path, "r", encoding="utf8") as fh:
            return json.load(fh)
    except (JSONDecodeError, OSError) as exc:
        print(f"[ERROR] Failed to load JSON from {path}: {exc}")
        return None


def normalize_rule_findings(rule_findings: Any) -> List[Dict[str, Any]]:
    """
    Normalize structure of rule-based results. Accepts a list of dicts.
    """
    normalized: List[Dict[str, Any]] = []

    # Support two input shapes:
    # 1) A flattened list of detection dicts (old format)
    # 2) A scan result dict from rule_engine.scan_repository containing 'findings_per_file'
    items: List[Dict[str, Any]] = []
    if isinstance(rule_findings, dict) and rule_findings.get("findings_per_file"):
        # flatten findings_per_file -> each detection dict
        for file_block in rule_findings.get("findings_per_file", []):
            for det in file_block.get("detections", []):
                items.append(det)
    elif isinstance(rule_findings, list):
        items = rule_findings
    else:
        return []

    for i, f in enumerate(items, start=1):
        if not isinstance(f, dict):
            continue
        file_path = f.get("file", "") or ""
        # application: top-level folder under which file resides (or file basename)
        try:
            dirname = os.path.dirname(file_path)
            if dirname:
                application = os.path.basename(dirname) or "unknown"
            else:
                application = os.path.splitext(os.path.basename(file_path))[0] or "unknown"
        except Exception:
            application = "unknown"

        try:
            accuracy = float(f.get("confidence", f.get("accuracy", 0.8)))
        except (TypeError, ValueError):
            accuracy = 0.8

        try:
            time_ms = float(f.get("time_ms", f.get("detection_time_ms", 0.0)))
        except (TypeError, ValueError):
            time_ms = 0.0

        # use relative path for file column so report shows folder + filename
        rel_file = os.path.relpath(file_path) if file_path else "unknown"
        normalized.append({
            "ser": i,
            "application": application,
            "language": _infer_language(file_path),
            "vulnerability": f.get("vulnerability", f.get("rule_id", "Unknown issue")),
            "cve": f.get("cve", "") or "",
            "cwe": f.get("cwe", "") or "",
            "file": rel_file,
            "line": f.get("line", "-"),
            "accuracy": round(accuracy, 2),
            "time_ms": time_ms,
            "type": "code"
        })
    return normalized


def normalize_cve_findings(cve_data: Any) -> List[Dict[str, Any]]:
    """
    Normalize structure of dependency-level CVE matches.
    Accepts either a single dict (with keys 'repo' and 'cve_matches') or a list of such dicts.
    """
    normalized: List[Dict[str, Any]] = []

    datasets = []
    if isinstance(cve_data, list):
        datasets = cve_data
    elif isinstance(cve_data, dict):
        datasets = [cve_data]
    else:
        return normalized

    idx = 1
    for ds in datasets:
        if not isinstance(ds, dict):
            continue
        repo = ds.get("repo") or ds.get("repository") or "unknown"
        matches = ds.get("cve_matches") or ds.get("matches") or []
        if not isinstance(matches, list):
            continue
        for m in matches:
            if not isinstance(m, dict):
                continue
            entry = m.get("entry", {}) if isinstance(m.get("entry", {}), dict) else {}
            package = m.get("package") or m.get("name") or "unknown"
            version = m.get("version") or ""
            vuln_desc = f"Dependency vuln: {package} {version}".strip()
            cve_id = entry.get("cve", "") or ""
            cwe = entry.get("cwe", "") or entry.get("cwe_ids", "") or ""

            normalized.append({
                "ser": idx,
                "application": os.path.basename(repo) if repo else "unknown",
                "language": "dependency",
                "vulnerability": vuln_desc,
                "cve": cve_id,
                "cwe": cwe,
                "file": m.get("file", "manifest/lock"),
                "line": m.get("line", "-"),
                "accuracy": round(float(m.get("confidence", 0.95)), 2) if m.get("confidence") is not None else 0.95,
                "time_ms": float(m.get("time_ms", 0.0)) if m.get("time_ms") is not None else 0.0,
                "type": "dependency"
            })
            idx += 1

    return normalized


def _infer_language(file_path: str) -> str:
    """
    Infer language from file extension (for rule findings).
    """
    ext = os.path.splitext(file_path or "")[1].lower()
    mapping = {
        ".py": "python",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".hpp": "cpp",
        ".java": "java",
        ".php": "php",
        ".phtml": "php",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".rb": "ruby",
    }
    return mapping.get(ext, "unknown")


def merge_results(rule_findings_path: str, cve_results_path: str, output_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Merge rule-engine and dependency mapper outputs.
    Returns the merged list of normalized findings.
    """
    rule_findings = load_findings(rule_findings_path)
    cve_results = load_findings(cve_results_path)

    normalized_rule = normalize_rule_findings(rule_findings)
    normalized_cve = normalize_cve_findings(cve_results)

    all_results = normalized_rule + normalized_cve

    # Re-assign serial numbers sequentially across the merged results
    for i, r in enumerate(all_results, start=1):
        r["ser"] = i

    if output_path:
        outdir = os.path.dirname(output_path) or "output"
        os.makedirs(outdir, exist_ok=True)
        try:
            with open(output_path, "w", encoding="utf8") as fo:
                json.dump(all_results, fo, indent=2, ensure_ascii=False)
            print(f"[INFO] Merged results saved to {output_path}")
        except OSError as exc:
            print(f"[ERROR] Failed to write output file {output_path}: {exc}")

    print(f"[SUMMARY] {len(normalized_rule)} code vulns + {len(normalized_cve)} dependency vulns merged. Total: {len(all_results)}")
    return all_results


# CLI
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Merge rule-engine and CVE mapper results.")
    parser.add_argument("--rule", required=True, help="Path to findings JSON from rule_engine")
    parser.add_argument("--cve", required=True, help="Path to cve_matches JSON from cve_mapper")
    parser.add_argument("--out", required=False, default=os.path.join("output", "merged_results.json"),
                        help="Path to write merged JSON (default: output/merged_results.json)")
    args = parser.parse_args()

    merge_results(args.rule, args.cve, args.out)
