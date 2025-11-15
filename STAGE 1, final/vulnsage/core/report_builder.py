"""
core/report_builder.py
----------------------
Generate Excel and JSON reports in Stage-I format.
"""

import os
import json
# openpyxl is imported lazily inside create_excel_report to allow running without the package;
# if openpyxl is not installed, create_excel_report will write a CSV fallback instead.
import csv
from typing import List, Dict, Any


LANG_DISPLAY = {
    'c': 'C',
    'cpp': 'C++',
    'java': 'Java',
    'python': 'Python',
    'php': 'PHP',
    'csharp': 'C#',
}

# Simple in-memory file read cache to avoid re-reading large files repeatedly
FILE_CONTENT_CACHE: Dict[str, List[str]] = {}


def load_findings(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Findings file not found: {path}")
    with open(path, "r", encoding="utf8") as fh:
        data = json.load(fh)
    # merged_results may be a dict with a list under 'findings' or 'results'
    if isinstance(data, dict):
        for key in ("findings", "results", "detections", "flat"):
            if key in data and isinstance(data[key], list):
                return data[key]
        # otherwise assume it contains a list under top-level
        for v in data.values():
            if isinstance(v, list):
                return v
        raise ValueError("Findings JSON dict does not contain a list of findings")
    if not isinstance(data, list):
        raise ValueError("Findings JSON must be a list of findings or a dict containing one")
    return data

def create_excel_report(findings: List[Dict[str, Any]], startup_name: str = "VulnSage"):
    os.makedirs("output", exist_ok=True)
    out_xlsx = os.path.join("output", f"GC_PS_01_{startup_name}.xlsx")

    # Desired columns (PS01):
    headers = [
        "SNo",
        "Primary Language of Benchmark",
        "Vulnerability",
        "CVE ID",
        "Severity",
        "Common Weakness Enumeration (CWE) Id",
        "file name with path",
        "line number",
        "Code Snippet at the line",
    ]

    # Group findings by language, but filter out non-vulnerabilities
    by_lang: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        # keep only items that look like real vulnerabilities: have an id or a high numeric score
        has_id = bool(f.get("vulnerability") or f.get("rule_id") or f.get("id"))
        numeric_score = None
        for key in ("accuracy", "confidence", "score", "probability"):
            if key in f:
                try:
                    numeric_score = float(f[key])
                    break
                except Exception:
                    pass
        keep = False
        if has_id:
            keep = True
        elif numeric_score is not None and numeric_score >= 0.6:
            keep = True
        if not keep:
            continue
        # infer language when missing
        lang = (f.get("language") or f.get("lang") or "").lower()
        if not lang or lang == 'unknown':
            fp = f.get('file', '')
            ext = os.path.splitext(fp)[1].lower()
            ext_map = {
                '.py': 'python', '.java': 'java', '.js': 'javascript', '.ts': 'typescript',
                '.c': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.h': 'c', '.cs': 'csharp', '.php': 'php'
            }
            lang = ext_map.get(ext, 'unknown')
        by_lang.setdefault(lang, []).append(f)

    # Try to import openpyxl; fallback to CSV per-language if not available
    try:
        import importlib
        openpyxl = importlib.import_module("openpyxl")
        Workbook = getattr(openpyxl, "Workbook")
        styles = importlib.import_module("openpyxl.styles")
        Font = getattr(styles, "Font")
        PatternFill = getattr(styles, "PatternFill")
        Alignment = getattr(styles, "Alignment")
        utils = importlib.import_module("openpyxl.utils")
        get_column_letter = getattr(utils, "get_column_letter")
    except ModuleNotFoundError:
        # Create one CSV per language
        out_files = []
        for lang, items in by_lang.items():
            disp = LANG_DISPLAY.get(lang, lang.title())
            out_csv = os.path.join("output", f"GC_PS_01_{startup_name}_{disp}.csv")
            with open(out_csv, "w", encoding="utf8", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(headers)
                # merge adjacent detections to avoid one-row-per-line for contiguous matches
                merged_items = _merge_adjacent_detections(items)
                for i, det in enumerate(merged_items, start=1):
                    cve_id = _extract_cve_from_det(det)
                    cwe = det.get("cwe") or det.get("cwe_id") or _extract_cwe_from_det(det)
                    snippet = _extract_code_snippet(det)
                    # For CSV fallback, CVE field holds the CVE ID if present
                    cve_field = cve_id or ""
                    # format line number: single or range
                    s = det.get("start_line")
                    e = det.get("end_line")
                    # display thresholds: if range is large, show count to avoid extremely long-looking ranges
                    # normalize line field to always present a 'start-end' string when possible
                    try:
                        si = int(s) if s is not None else None
                    except Exception:
                        try:
                            si = int(str(det.get("line") or s).split("-")[0])
                        except Exception:
                            si = None
                    try:
                        ei = int(e) if e is not None else None
                    except Exception:
                        try:
                            parts = str(det.get("line") or e).split("-")
                            ei = int(parts[-1]) if parts else si
                        except Exception:
                            ei = si
                    if si is None:
                        line_field = str(det.get("line") or "")
                    else:
                        if ei is None:
                            ei = si
                        span = ei - si + 1
                        if span > 1000:
                            line_field = f"{si}-{ei} ({span} lines - entire file)"
                        elif span > 50:
                            line_field = f"{si}-{ei} ({span} lines)"
                        else:
                            line_field = f"{si}-{ei}"
                    writer.writerow([
                        i,
                        disp,
                        _format_vuln_field(det),
                        cve_field,
                        _get_severity(det),
                        cwe or "",
                        det.get("file", ""),
                        line_field,
                        snippet,
                    ])
            out_files.append(out_csv)
        print(f"[INFO] openpyxl not available; CSV reports generated: {out_files}")
        return out_files

    wb = Workbook()
    # remove default sheet created if we will create per-language sheets
    default = wb.active
    wb.remove(default)

    # set a high page size; only split sheets if extremely large
    MAX_ROWS_PER_SHEET = 100000
    for lang, items in by_lang.items():
        # skip languages with no items after filtering
        if not items:
            continue
        disp = LANG_DISPLAY.get(lang, lang.title())

    # Group by vulnerability id to keep similar vulnerabilities together
        groups: List[List[Dict[str, Any]]] = []
        cur_group = []
        last_vid = None
        for det in items:
            vid = det.get("vulnerability") or det.get("rule_id") or det.get("id") or "unknown"
            if last_vid is None:
                last_vid = vid
            if vid != last_vid:
                # flush current group
                if cur_group:
                    groups.append(cur_group)
                cur_group = [det]
                last_vid = vid
            else:
                cur_group.append(det)
        if cur_group:
            groups.append(cur_group)

    # paginate groups into sheets of up to MAX_ROWS_PER_SHEET each
        sheet_index = 1
        cur_sheet_rows = 0
        ws = None
        # sequential serial number per language across all sheets
        serial_no = 1
        header_fill = PatternFill(fill_type="solid", fgColor="003366")
        header_font = Font(color="FFFFFF", bold=True)

        def _new_sheet():
            nonlocal sheet_index, ws, cur_sheet_rows
            # sheet title: use language display name; append index if multiple sheets
            name = f"{disp}" if sheet_index == 1 else f"{disp}_{sheet_index}"
            sheet_index += 1
            sheet_name = name[:31]
            ws_local = wb.create_sheet(title=sheet_name)
            ws_local.append(headers)
            for col in range(1, len(headers) + 1):
                cell = ws_local.cell(row=1, column=col)
                cell.fill = header_fill
                cell.font = header_font
                cell.alignment = Alignment(horizontal="center", vertical="center")
            cur_sheet_rows = 0
            return ws_local

        ws = _new_sheet()
        row_counter = 1
        for group in groups:
            # merge adjacent detections within this vulnerability group
            merged_group = _merge_adjacent_detections(group)
            gsize = len(group)
            # if group too large to fit remaining rows, and group itself > MAX, split it across sheets
            if cur_sheet_rows + gsize > MAX_ROWS_PER_SHEET:
                # if group itself larger than sheet size, we will fill current sheet and continue
                if cur_sheet_rows >= MAX_ROWS_PER_SHEET:
                    ws = _new_sheet()
            # iterate through group's detections
            for det in merged_group:
                # if current sheet is full, create a new one
                if cur_sheet_rows >= MAX_ROWS_PER_SHEET:
                    ws = _new_sheet()
                cve_id = _extract_cve_from_det(det)
                cwe = det.get("cwe") or det.get("cwe_id") or _extract_cwe_from_det(det)
                # keep CVE and CWE separate per PS01: CVE column contains CVE ID(s), CWE column contains CWE Id
                cve_field = cve_id or ""
                # use cached snippet extraction
                snippet = _extract_code_snippet(det)
                vuln_text = _format_vuln_field(det)
                # append using sequential serial_no
                # format line column to show range if present
                s = det.get("start_line")
                e = det.get("end_line")
                try:
                    si = int(s) if s is not None else None
                except Exception:
                    try:
                        si = int(str(det.get("line") or s).split("-")[0])
                    except Exception:
                        si = None
                try:
                    ei = int(e) if e is not None else None
                except Exception:
                    try:
                        parts = str(det.get("line") or e).split("-")
                        ei = int(parts[-1]) if parts else si
                    except Exception:
                        ei = si
                if si is None:
                    line_field = str(det.get("line") or "")
                else:
                    if ei is None:
                        ei = si
                    span = ei - si + 1
                    if span > 1000:
                        line_field = f"{si}-{ei} ({span} lines - entire file)"
                    elif span > 50:
                        line_field = f"{si}-{ei} ({span} lines)"
                    else:
                        line_field = f"{si}-{ei}"
                ws.append([
                    serial_no,
                    disp,
                    vuln_text,
                    cve_field,
                    _get_severity(det),
                    cwe or "",
                    det.get("file", ""),
                    line_field,
                    snippet,
                ])
                serial_no += 1
                cur_sheet_rows += 1

        # auto-size columns modestly for all sheets of this language
        for i in range(1, sheet_index):
            sheet_name = f"{disp}_{i}"[:31]
            if sheet_name in wb.sheetnames:
                ws2 = wb[sheet_name]
                for col_idx in range(1, len(headers) + 1):
                    letter = get_column_letter(col_idx)
                    ws2.column_dimensions[letter].width = 22

    wb.save(out_xlsx)
    print(f"[INFO] Excel report generated: {out_xlsx}")
    return out_xlsx


def _extract_cve_from_det(det: Dict[str, Any]) -> str:
    # prefer explicit CVE field
    if det.get("cve"):
        return str(det.get("cve"))
    # try list of matches
    cm = det.get("cve_matches") or det.get("cves")
    if isinstance(cm, list) and cm:
        first = cm[0]
        return str(first.get("cve") or first.get("id") or first)
    # no CVE available
    return ""


def _extract_cwe_from_det(det: Dict[str, Any]) -> str:
    # try several common keys
    if det.get("cwe"):
        return str(det.get("cwe"))
    if det.get("cwe_id"):
        return str(det.get("cwe_id"))
    # prefer candidate CWEs provided by the scanner heuristics
    cc = det.get("candidate_cwes") or det.get("candidate_cwe")
    if isinstance(cc, list) and cc:
        return ",".join(cc)
    if isinstance(cc, str) and cc:
        return cc
    # sometimes rule id encodes CWE (not reliable)
    return ""


def _extract_code_snippet(det: Dict[str, Any]) -> str:
    path = det.get("file")
    # support merged detections with start_line/end_line
    start_line = det.get("start_line") or det.get("line")
    end_line = det.get("end_line") or det.get("line")
    if not path or not start_line:
        return det.get("evidence", "")
    try:
        # use a cache to avoid repeated disk reads for large runs
        if path in FILE_CONTENT_CACHE:
            lines = FILE_CONTENT_CACHE[path]
        else:
            with open(path, "r", encoding="utf8", errors="ignore") as fh:
                lines = fh.readlines()
            FILE_CONTENT_CACHE[path] = lines
        try:
            s = int(start_line) - 1
        except Exception:
            return det.get("evidence", "")
        if end_line is not None:
            try:
                e = int(end_line) - 1
            except Exception:
                e = s
        else:
            e = s
        # clamp
        s = max(0, min(s, len(lines) - 1))
        e = max(s, min(e, len(lines) - 1))
        # limit block size to avoid huge Excel cells
        MAX_LINES = 10
        block_lines = lines[s:e+1]
        if len(block_lines) > MAX_LINES:
            # keep head and tail with ellipsis
            head = block_lines[:5]
            tail = block_lines[-5:]
            combined = head + ["...\n"] + tail
        else:
            combined = block_lines
        # join and strip trailing newlines
        snippet = "".join(combined).strip()
        # collapse internal newlines to single-line display if desired
        return snippet
    except Exception:
        return det.get("evidence", "")


def _merge_adjacent_detections(dets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Merge adjacent detections in the same file that belong to the same vulnerability
    into a single detection with start_line/end_line to avoid filling the report with
    one-row-per-line when the rule matches contiguous code.
    """
    if not dets:
        return []
    # sort by file then line
    try:
        sorted_d = sorted(dets, key=lambda d: (d.get("file", ""), int(d.get("line") or d.get("start_line") or 0)))
    except Exception:
        sorted_d = dets[:]
    merged: List[Dict[str, Any]] = []
    cur = None
    for d in sorted_d:
        if cur is None:
            cur = dict(d)
            # initialize start/end
            try:
                cur["start_line"] = int(d.get("line") or d.get("start_line") or 0)
            except Exception:
                cur["start_line"] = d.get("line") or d.get("start_line")
            try:
                cur["end_line"] = int(d.get("line") or d.get("end_line") or cur.get("start_line") or 0)
            except Exception:
                cur["end_line"] = cur.get("start_line")
            continue
        # same file and same vulnerability -> consider merge when lines contiguous or very close
        same_file = (str(cur.get("file")) == str(d.get("file")))
        same_vuln = (str(cur.get("vulnerability") or cur.get("rule_id") or "") == str(d.get("vulnerability") or d.get("rule_id") or ""))
        try:
            this_line = int(d.get("line") or d.get("start_line") or 0)
        except Exception:
            this_line = None
        last_end = cur.get("end_line")
        if same_file and same_vuln and this_line is not None and isinstance(last_end, int) and this_line <= (last_end + 1):
            # extend current block
            cur["end_line"] = max(last_end, this_line)
            # merge confidence/evidence conservatively
            try:
                cur_conf = float(cur.get("confidence") or 0.0)
                d_conf = float(d.get("confidence") or 0.0)
                cur["confidence"] = max(cur_conf, d_conf)
            except Exception:
                pass
            # append evidence of last line for reference
            if d.get("evidence"):
                cur.setdefault("evidence_lines", []).append(d.get("evidence"))
            continue
        else:
            # flush current
            merged.append(cur)
            cur = dict(d)
            try:
                cur["start_line"] = int(d.get("line") or d.get("start_line") or 0)
            except Exception:
                cur["start_line"] = d.get("line") or d.get("start_line")
            try:
                cur["end_line"] = int(d.get("line") or d.get("end_line") or cur.get("start_line") or 0)
            except Exception:
                cur["end_line"] = cur.get("start_line")
    if cur is not None:
        merged.append(cur)
    return merged


def _get_severity(det: Dict[str, Any]) -> str:
    """Return a textual severity. Prefer explicit 'severity' if present.

    Otherwise, try numeric fields like 'accuracy' or 'confidence' and map
    them to High/Medium/Low/Info.
    """
    if det is None:
        return "Unknown"
    sev = det.get("severity")
    if sev:
        return str(sev)

    # numeric heuristics
    for key in ("accuracy", "confidence", "score", "probability"):
        v = det.get(key)
        if v is None:
            continue
        try:
            fv = float(v)
        except Exception:
            continue
        if fv >= 0.85:
            return "High"
        if fv >= 0.6:
            return "Medium"
        if fv >= 0.3:
            return "Low"
        return "Info"

    return "Unknown"


def _format_vuln_field(det: Dict[str, Any]) -> str:
    # Compose a readable vulnerability field: rule id plus description for clarity
    title = det.get("vulnerability") or det.get("rule_id") or det.get("id") or "Vulnerability"
    desc = det.get("description") or det.get("message") or det.get("fix") or ""
    if desc:
        return f"{title} — {desc}"
    return title


def create_json_report(findings: List[Dict[str, Any]]):
    os.makedirs("output", exist_ok=True)
    out_path = os.path.join("output", "final_results.json")
    with open(out_path, "w", encoding="utf8") as fo:
        json.dump(findings, fo, indent=2)
    print(f"[INFO] JSON report generated: {out_path}")
    return out_path


def build_reports(merged_results_path: str, startup_name: str = "VulnSage"):
    findings = load_findings(merged_results_path)
    excel_path = create_excel_report(findings, startup_name)
    json_path = create_json_report(findings)
    print(f"[SUMMARY] Reports built successfully.\nExcel: {excel_path}\nJSON: {json_path}")


# CLI
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Build Excel + JSON vulnerability reports.")
    parser.add_argument("--input", required=True, help="Merged results JSON path")
    parser.add_argument("--name", default="VulnSage", help="Startup/project name")
    args = parser.parse_args()

    build_reports(args.input, args.name)
