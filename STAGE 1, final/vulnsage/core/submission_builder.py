"""
core/submission_builder.py
-------------------------
Build submission-ready XLSX files (one file per software stack) that follow the PS01 requirements:
- separate sheet per language
- single CVE column (falls back to CWE if CVE is missing)
- include required columns and additional provenance columns

Usage: run as a script. It will read merged_results JSON files from the output folder and create
submission XLSX files in the same output folder. It also creates a zip named AIGR-00000.zip (placeholder).
"""
import os
import json
from typing import List, Dict, Any

try:
    import openpyxl
    from openpyxl import Workbook
except Exception:
    openpyxl = None

import zipfile


DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'output')


def load_merged(path: str) -> List[Dict[str, Any]]:
    with open(path, 'r', encoding='utf8') as fh:
        return json.load(fh)


def group_by_language(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        lang = (f.get('language') or 'unknown').lower()
        groups.setdefault(lang, []).append(f)
    return groups


def build_workbook_for_stack(merged_path: str, out_xlsx: str):
    findings = load_merged(merged_path)
    groups = group_by_language(findings)

    # Ensure output dir
    os.makedirs(os.path.dirname(out_xlsx), exist_ok=True)

    if openpyxl is None:
        raise RuntimeError('openpyxl is required to build XLSX submissions. Install it in the environment.')

    wb = Workbook()
    # We'll remove the default sheet and create sheets per language
    default = wb.active
    wb.remove(default)

    # Columns requested by the user (exact order):
    headers = [
        'SNo',
        'Primary Language of Benchmark',
        'Vulnerability',
        'CVE ID',
        'Severity',
        'Common Weakness Enumeration (CWE) Id',
        'file name with path',
        'line number',
        'Code Snippet at the line'
    ]

    for lang, items in sorted(groups.items()):
        # sheet name must be <= 31 chars
        sheet_name = lang[:31]
        ws = wb.create_sheet(title=sheet_name)
        ws.append(headers)
        for i, f in enumerate(items, start=1):
            cve_val = (f.get('cve') or '').strip()
            cwe_val = (f.get('cwe') or '').strip()
            severity = f.get('severity') or ''
            vuln_name = f.get('vulnerability') or f.get('rule_id') or ''

            file_path = f.get('file') or ''
            line_no = f.get('line') or ''
            # extract code snippet (context +/-2 lines)
            snippet = ''
            try:
                if file_path and os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf8', errors='ignore') as fh:
                        lines = fh.readlines()
                        try:
                            ln = int(line_no)
                        except Exception:
                            ln = None
                        if ln and 1 <= ln <= len(lines):
                            start = max(0, ln - 3)
                            end = min(len(lines), ln + 2)
                            snippet = ''.join(lines[start:end]).strip()
            except Exception:
                snippet = ''

            row = [
                i,
                lang,
                vuln_name,
                cve_val or '',
                severity,
                cwe_val or '',
                file_path,
                line_no,
                snippet
            ]
            ws.append(row)

    wb.save(out_xlsx)
    print(f'[INFO] Submission XLSX generated: {out_xlsx}')
    return out_xlsx


def build_submissions_for_files(merged_files: List[str], out_dir: str = None) -> List[str]:
    out_dir = out_dir or os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'output'))
    os.makedirs(out_dir, exist_ok=True)
    produced: List[str] = []
    for merged in merged_files:
        base = os.path.splitext(os.path.basename(merged))[0]
        # derive a compact name: e.g., merged_results_DAIFEND_S1_2.json -> DAIFEND_S1_2
        if base.startswith('merged_results_'):
            short = base[len('merged_results_'):]
        else:
            short = base
        out_xlsx = os.path.join(out_dir, f'AIGR-00000_{short}.xlsx')
        build_workbook_for_stack(merged, out_xlsx)
        produced.append(out_xlsx)
    return produced


def make_zip(files: List[str], zip_path: str):
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            arcname = os.path.basename(f)
            zf.write(f, arcname=arcname)
    print(f'[INFO] Created zip: {zip_path}')
    return zip_path


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Create submission XLSX files (one per merged JSON) and zip them')
    parser.add_argument('--merged', nargs='+', help='Paths to merged_results JSON files', required=False)
    parser.add_argument('--outdir', help='Output directory (default: output/)', required=False)
    parser.add_argument('--zip', help='Create AIGR zip (path). If provided, will zip the generated XLSX files.', required=False)
    parser.add_argument('--aigr-id', help='AIGR ID to use in filenames (e.g. 12345). If omitted, uses 00000.', required=False)
    args = parser.parse_args()

    if not args.merged:
        # default: use merged_results files in the workspace top-level output folder
        default_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'output'))
        args.merged = [
            os.path.join(default_dir, 'merged_results_DAIFEND_S1_1.json'),
            os.path.join(default_dir, 'merged_results_DAIFEND_S1_2.json'),
            os.path.join(default_dir, 'merged_results_DAIFEND_S1_3.json'),
            os.path.join(default_dir, 'merged_results_DAIFEND_S1_4.json'),
            os.path.join(default_dir, 'merged_results_DAIFEND_stack2.json')
        ]

    aigr_id = (args.aigr_id or '00000').strip()
    # rename produced files to include AIGR ID pattern
    # The build_submissions_for_files function names output files with AIGR-00000_<short>.xlsx; we'll move/rename them
    produced = build_submissions_for_files(args.merged, args.outdir)
    renamed = []
    for p in produced:
        dirp = os.path.dirname(p)
        base = os.path.basename(p)
        # base like AIGR-00000_short.xlsx
        parts = base.split('_', 1)
        if len(parts) == 2:
            _, rest = parts
        else:
            rest = base
        new_name = f'AIGR-{aigr_id}_{rest}'
        new_path = os.path.join(dirp, new_name)
        try:
            os.replace(p, new_path)
        except Exception:
            # fallback to copy
            import shutil
            shutil.copyfile(p, new_path)
        renamed.append(new_path)

    zip_path = args.zip or os.path.join(args.outdir or DEFAULT_OUTPUT_DIR, f'AIGR-{aigr_id}.zip')
    make_zip(renamed, zip_path)
