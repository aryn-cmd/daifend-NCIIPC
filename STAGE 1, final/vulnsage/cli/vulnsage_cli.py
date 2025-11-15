"""
vulnsage/cli/vulnsage_cli.py
----------------------------
Unified launcher for VulnSage pipeline.

Usage:
    python vulnsage/cli/vulnsage_cli.py --repo "<path_to_repo>" --name "MyStartup" [--truth "data/ground_truth.json"]
"""

from __future__ import annotations

import argparse
import inspect
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable, List, Optional

# Ensure package root is on sys.path so `core` package can be imported reliably
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from core import (
        discover,
        rule_engine,
        cve_mapper,
        merge_results,
        scoring,
        report_builder,
    )
except Exception as e:
    print(f"[ERROR] Failed to import core modules: {e}")
    sys.exit(1)


def _find_callable(module: Any, candidates: Iterable[str]) -> Optional[Callable]:
    """Return first callable attribute from module whose name is in candidates."""
    for name in candidates:
        fn = getattr(module, name, None)
        if callable(fn):
            return fn
    return None


def _try_call(func: Callable, patterns: List[tuple]) -> Any:
    """
    Try calling func with several (args, kwargs) patterns.
    patterns: list of (args_list, kwargs_dict)
    Returns the result of the first successful call, otherwise raises the last exception.
    """
    last_exc = None
    for args, kwargs in patterns:
        try:
            return func(*args, **kwargs)
        except TypeError as e:
            # likely wrong signature; try next pattern
            last_exc = e
        except Exception:
            # unexpected runtime error from function — re-raise immediately
            raise
    # If we reach here, no pattern matched
    raise last_exc if last_exc is not None else RuntimeError("No callable patterns provided")


def _iter_len(maybe_iterable: Any) -> Optional[int]:
    try:
        return len(maybe_iterable)
    except Exception:
        try:
            return sum(1 for _ in maybe_iterable)
        except Exception:
            return None


def run_vulnsage_pipeline(repo_path: str, project_name: str, truth_path: str | None = None) -> None:
    """
    Runs the full vulnerability detection workflow.
    """
    repo = Path(repo_path).expanduser().resolve()
    if not repo.exists():
        print(f"[ERROR] Repository not found: {repo}")
        return

    if truth_path:
        truth = Path(truth_path).expanduser().resolve()
        if not truth.exists():
            print(f"[WARN] Ground-truth file not found: {truth} — skipping F1 computation.")
            truth = None
    else:
        truth = None

    start_time = time.time()
    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n🚀 [1/6] DISCOVERING SOURCE FILES...")
    discovered_files = []
    discover_fn = _find_callable(discover, ["discover_files", "discover", "find_files", "find_repo_files", "list_files"])
    if not discover_fn:
        print("[WARN] No discover function found in core.discover — skipping discovery step.")
    else:
        try:
            patterns = [
                ([str(repo)], {}),
                ([], {"repo_path": str(repo)}),
                ([], {"root": str(repo)}),
            ]
            discovered_files = _try_call(discover_fn, patterns) or []
            count = _iter_len(discovered_files)
            if count is not None:
                print(f"[INFO] {count} source files found in {repo}")
            else:
                print(f"[INFO] Discovery completed for {repo}")
        except Exception as e:
            print(f"[ERROR] Discover step failed: {e}")
            return

    print("\n🧩 [2/6] RUNNING RULE ENGINE...")
    rule_output = output_dir / f"findings_{project_name}.json"
    rule_fn = _find_callable(rule_engine, ["scan_repository", "scan_repo", "scan", "run", "apply_rules"])
    if not rule_fn:
        print("[WARN] No rule engine function found in core.rule_engine — skipping rule engine step.")
    else:
        try:
            # call rule_engine.scan_repository with repo path
            rule_scan_result = rule_engine.scan_repository(str(repo), cve_db=None, verbose=False)
            os.makedirs("output", exist_ok=True)
            rule_engine.save_findings(rule_scan_result, str(rule_output))
            print(f"[INFO] Rule-based results saved → {rule_output}")
        except Exception as e:
            print(f"[ERROR] Rule engine failed: {e}")
            return

    print("\n🔍 [3/6] RUNNING DEPENDENCY CVE MAPPER...")
    cve_output = output_dir / f"cve_matches_{project_name}.json"
    osv_index_path = Path("data") / "osv_index.json"
    cve_fn = _find_callable(cve_mapper, ["scan_dependencies", "scan_deps", "map_dependencies", "map_cves", "scan"])
    if osv_index_path.exists():
        try:
            # If the OSV file looks like a list of OSV records or a single large OSV export,
            # build a compact index first and then map repo dependencies to CVEs.
            print(f"[INFO] Building compact CVE index from OSV data: {osv_index_path}")
            # build_index_from_osv accepts a list of paths; it will write nothing unless out_path provided
            compact_index = cve_mapper.build_index_from_osv([str(osv_index_path)], out_path=None)
            cve_result = cve_mapper.map_repo_dependencies_to_cves(str(repo), compact_index)
            os.makedirs("output", exist_ok=True)
            import json
            with open(cve_output, "w", encoding="utf8") as fo:
                json.dump(cve_result, fo, indent=2)
            print(f"[INFO] CVE mapping results saved → {cve_output}")
        except Exception as e:
            print(f"[WARN] CVE mapping failed: {e} — continuing without dependency matches.")
            cve_output = None
    else:
        if not osv_index_path.exists():
            print(f"[WARN] CVE index not found: {osv_index_path} — skipping dependency scan.")
        else:
            print("[WARN] No CVE mapper function found in core.cve_mapper — skipping dependency scan.")
        cve_output = None

    print("\n📦 [4/6] MERGING RESULTS...")
    merged_output = output_dir / f"merged_results_{project_name}.json"
    merge_fn = _find_callable(merge_results, ["merge_results", "merge", "combine", "merge_all"])
    if not merge_fn:
        print("[WARN] No merge function found in core.merge_results — skipping merge step.")
    else:
        try:
            left = str(rule_output)
            right = str(cve_output) if cve_output else str(rule_output)
            patterns = [
                ([left, right, str(merged_output)], {}),
                ([left, str(merged_output)], {}),
                ([], {"left": left, "right": right, "out": str(merged_output)}),
            ]
            _try_call(merge_fn, patterns)
            print(f"[INFO] Merged results saved → {merged_output}")
        except Exception as e:
            print(f"[ERROR] Merging results failed: {e}")
            return

    print("\n📊 [5/6] GENERATING REPORTS...")
    report_fn = _find_callable(report_builder, ["build_reports", "build_report", "generate_reports", "generate_report"])
    if not report_fn:
        print("[WARN] No report builder function found in core.report_builder — skipping report generation.")
    else:
        try:
            patterns = [
                ([str(merged_output)], {"startup_name": project_name}),
                ([str(merged_output)], {"project_name": project_name}),
                ([str(merged_output), project_name], {}),
                ([str(merged_output)], {}),
            ]
            _try_call(report_fn, patterns)
            print(f"[INFO] Reports generated for {project_name}")
        except Exception as e:
            print(f"[ERROR] Report generation failed: {e}")
            return

    if truth:
        print("\n🧮 [6/6] COMPUTING F1 SCORE...")
        score_fn = _find_callable(scoring, ["evaluate", "score", "compute_scores", "compute_f1", "evaluate_scores"])
        if not score_fn:
            print("[WARN] No scoring function found in core.scoring — skipping scoring.")
        else:
            try:
                patterns = [
                    ([str(merged_output), str(truth)], {}),
                    ([str(merged_output)], {"truth": str(truth)}),
                    ([], {"pred": str(merged_output), "truth": str(truth)}),
                ]
                _try_call(score_fn, patterns)
            except Exception as e:
                print(f"[WARN] Scoring failed: {e}")
    else:
        print("\nℹ️  [6/6] No ground-truth provided — skipping F1 computation.")

    elapsed = round((time.time() - start_time), 2)
    print(f"\n✅ Pipeline completed successfully in {elapsed} seconds.")
    print(f"📁 Reports and outputs are available in the '{output_dir}/' folder.\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run VulnSage full vulnerability detection pipeline.")
    parser.add_argument("--repo", required=True, help="Path to repository or code folder to scan.")
    parser.add_argument("--name", default="VulnSage", help="Project or startup name.")
    parser.add_argument("--truth", help="(Optional) Ground-truth JSON file for F1 scoring.")
    args = parser.parse_args()

    run_vulnsage_pipeline(args.repo, args.name, args.truth)


if __name__ == "__main__":
    main()
