from core.rule_engine import scan_repository, save_findings, flatten_findings
from core.scoring import evaluate
import json
import os


def main():
    repo = os.path.join(os.getcwd(), "test_repo")
    if not os.path.exists(repo):
        print(f"[WARN] test_repo not found at {repo}. Create a small repo for testing or pass a different path.")

    print("[RUN] Scanning repository (best-effort)...")
    res = scan_repository(repo, cve_db=None, verbose=True)
    out = save_findings(res)
    print(f"[DONE] Scan saved to {out}")

    flat = flatten_findings(res)
    # save flat findings for scoring/consumers
    out_flat = os.path.join(os.path.dirname(out), "findings.flat.json")
    with open(out_flat, "w", encoding="utf8") as fh:
        json.dump(flat, fh, indent=2)
    print(f"[DONE] Flat findings written to {out_flat} (records={len(flat)})")

    # optional: if ground truth present, evaluate
    gt = os.path.join(os.getcwd(), "ground_truth.json")
    if os.path.exists(gt):
        print("[INFO] ground_truth.json found, running evaluation...")
        evaluate(out_flat, gt)


if __name__ == "__main__":
    main()
