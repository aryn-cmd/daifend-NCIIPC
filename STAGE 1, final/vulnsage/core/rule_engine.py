"""
core/rule_engine.py

Responsibilities:
- Load per-language rule JSON files from rules/<language>_rules.json
- Scan repository files for matches (regex or simple substring)
- Track timings: per-file time_ms and per-detection detector_ms
- Attach CWE from rule metadata
- Optionally attach CVE hints via a passed-in cve_db dict (lightweight match by import or package tokens)
- Write findings to output/findings.json

Rule JSON expectations (list of rule objects). Each rule may include:
{
  "id": "py-sql-injection",
  "language": "python",
  "patterns": ["re:\\bexecute\\s*\\(", " + "],   # string values; "re:" prefix means regex
  "cwe": "CWE-89",
  "severity": "high",
  "description": "...",
  "fix": "..."
}

Usage example:
    from core.rule_engine import scan_repository, save_findings
    findings = scan_repository("./test_repo", cve_db=None)
    save_findings(findings, "output/findings.json")
"""

import os
import re
import json
import time
from datetime import datetime
from typing import List, Dict, Optional, Any

RULES_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
OUTPUT_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")

# Common CWE lists per language — used as lightweight candidates when a rule omits an explicit CWE.
# These are curated common CWE IDs relevant to each language's typical weaknesses.
LANGUAGE_CWE_LIST = {
    "c": [
        "CWE-119",  # Buffer Errors
        "CWE-120",  # Buffer Copy without Checking Size of Input
        "CWE-170",  # Improper Null Termination
        "CWE-252",  # Unchecked Return Value
        "CWE-703",  # Improper Check or Handling of Exceptional Conditions
    ],
    "cpp": [
        "CWE-120",
        "CWE-134",  # Use of Externally-Controlled Format String
        "CWE-416",  # Use After Free
        "CWE-119",
    ],
    "python": [
        "CWE-89",   # SQL Injection
        "CWE-78",   # Command Injection
        "CWE-502",  # Deserialization of Untrusted Data
        "CWE-798",  # Use of Hard-coded Credentials
    ],
    "java": [
        "CWE-89",
        "CWE-611",  # XXE
        "CWE-502",
        "CWE-327",  # Use of a Broken or Risky Cryptographic Algorithm
    ],
    "php": [
        "CWE-89",
        "CWE-79",
        "CWE-98",
        "CWE-502",
        "CWE-22",   # Path Traversal
    ],
}


# -------------------------
# Utility functions
# -------------------------
def load_rules(language: str) -> List[Dict[str, Any]]:
    """
    Load rules for a language from rules/<language>_rules.json
    Returns a list of rule dicts.
    """
    path = os.path.join(RULES_FOLDER, f"{language}_rules.json")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Rules file not found for language '{language}': {path}")
    with open(path, "r", encoding="utf8") as fh:
        rules = json.load(fh)
    # Normalize: ensure patterns list
    for r in rules:
        pats = r.get("patterns")
        if pats is None:
            # support single pattern field
            p = r.get("pattern") or r.get("match") or ""
            r["patterns"] = [p] if p else []
        else:
            r["patterns"] = list(pats)
        # default confidence
        if "confidence" not in r:
            r["confidence"] = 0.75
        # support flag to match entire file (multi-line regex)
        if "match_entire_file" not in r:
            r["match_entire_file"] = False
    return rules


def detect_language_by_ext(filename: str) -> Optional[str]:
    """
    Very simple extension-based language detection.
    """
    ext = os.path.splitext(filename)[1].lower()
    map_ext = {
        ".py": "python",
        ".java": "java",
        ".js": "javascript",
        ".ts": "typescript",
        # treat C files with 'c' rules (we keep C++ as 'cpp')
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        # header files may be C or C++; prefer 'c' to find C-specific rules
        ".h": "c",
        ".cs": "csharp",
        ".php": "php",
        ".go": "go",
        ".rb": "ruby",
    }
    return map_ext.get(ext)


def read_file_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf8", errors="ignore") as f:
        return f.readlines()


def ensure_output_folder():
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# -------------------------
# CVE best-effort helper (optional)
# -------------------------
def _extract_import_tokens_from_code(lines: List[str]) -> List[str]:
    """Very light-weight extraction of imported package names for Python/Java/JS etc."""
    tokens = set()
    for ln in lines:
        ln = ln.strip()
        # python imports
        if ln.startswith("import ") or ln.startswith("from "):
            parts = re.split(r"\s+", ln)
            for p in parts[1:]:
                token = p.split(".")[0].strip(",")
                if token:
                    tokens.add(token)
        # java imports
        if ln.startswith("import "):
            parts = ln.split()
            if len(parts) > 1:
                token = parts[1].split(".")[0]
                tokens.add(token)
        # require / const require in JS/PHP-ish lines
        m = re.search(r'require\([\'"]([^\'"]+)[\'"]\)', ln)
        if m:
            pkg = m.group(1).split("/")[0]
            tokens.add(pkg)
        # php use or include patterns
        if "use " in ln or "include" in ln or "require" in ln:
            # crude tokenization
            parts = re.findall(r"[A-Za-z0-9_\.\/\-]+", ln)
            if parts:
                tokens.add(parts[-1].split(".")[0])
    return list(tokens)


def attach_cve_hints(find: Dict[str, Any], code_lines: List[str], cve_db: Optional[Dict[str, Any]]):
    """
    Best-effort attach CVE hints to a finding based on simple import/package token matches
    cve_db expected to be a dict keyed by package name or 'pkg:version' returning list of CVE entries.
    This is intentionally lightweight; a dedicated dependency analyzer should be used for full mapping.
    """
    if not cve_db:
        return
    tokens = _extract_import_tokens_from_code(code_lines)
    matches = []
    for t in tokens:
        # try direct lookup
        if t in cve_db:
            matches.extend(cve_db[t])
        # try lowercase
        if t.lower() in cve_db:
            matches.extend(cve_db[t.lower()])
    if matches:
        # deduplicate by CVE id if present
        seen = set()
        dedup = []
        for m in matches:
            cid = m.get("cve") or m.get("id") or json.dumps(m)
            if cid not in seen:
                seen.add(cid)
                dedup.append(m)
        find["cve_matches"] = dedup


# -------------------------
# Core scanning functions
# -------------------------
def _pattern_is_regex(pat: str) -> bool:
    return isinstance(pat, str) and pat.startswith("re:")


def _compile_pattern(pat: str):
    """
    If the pattern is prefixed with 're:' treat it as a regex and compile.
    Otherwise return None (we'll use substring check).
    """
    if _pattern_is_regex(pat):
        try:
            # allow DOTALL for multi-line patterns
            return re.compile(pat[len("re:"):], flags=re.DOTALL)
        except re.error:
            # invalid regex -> fallback to substring
            return None
    return None


def _match_patterns_on_line(line: str, patterns: List[str]) -> Optional[str]:
    """
    Try each pattern; return the matching pattern string if matched, else None.
    Patterns starting with 're:' use regex, others are substring (case-sensitive).
    """
    for pat in patterns:
        # support regex patterns prefixed with 're:' (case-insensitive by default)
        if _pattern_is_regex(pat):
            regex = _compile_pattern(pat)
            if regex and regex.search(line):
                return pat
            # if compile failed, fallback to substring match using the regex body
            plain = pat[len("re:"):]
            if plain and plain in line:
                return pat
        else:
            # variable placeholder support: {{VAR}} -> match identifier-like token
            if "{{VAR}}" in pat:
                # replace placeholder with a permissive pattern for quick substring-like match
                parts = pat.split("{{VAR}}")
                if all(p in line for p in parts if p):
                    return pat
            # case-insensitive substring check
            if pat.lower() in line.lower():
                return pat
    return None


def scan_file_with_rules(file_path: str, rules: List[Dict[str, Any]], cve_db: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Scan a single file with a list of rules. Return:
      {
        "file": file_path,
        "file_time_ms": <float>,
        "detections": [ { ... } ],
        "file_lines": <optional count>
      }
    Each detection includes timing_ms for the single detection.
    """
    start_file = time.perf_counter()
    lines = read_file_lines(file_path)
    detections = []
    # join entire content for multi-line matching (future extension)
    full_text = "".join(lines)

    # First handle file-level rules (match_entire_file) once per file to avoid per-line duplication
    for rule in rules:
        if rule.get("match_entire_file", False):
            patterns = rule.get("patterns", [])
            start_det = time.perf_counter()
            detect = False
            detect_pattern = None
            for p in patterns:
                if _pattern_is_regex(p):
                    regex = _compile_pattern(p)
                    if regex and regex.search(full_text):
                        detect = True
                        detect_pattern = p
                        break
                    plain = p[len("re:"):]
                    if plain and plain in full_text:
                        detect = True
                        detect_pattern = p
                        break
                else:
                    if p in full_text:
                        detect = True
                        detect_pattern = p
                        break
            end_det = time.perf_counter()
            if detect:
                det_time_ms = (end_det - start_det) * 1000.0
                finding = {
                    "file": file_path,
                    # use full-file range for file-level matches; reporting will trim snippet length
                    "line": 1,
                    "start_line": 1,
                    "end_line": len(lines),
                    "language": rule.get("language"),
                    "rule_id": rule.get("id"),
                    "vulnerability": rule.get("id"),
                    "pattern_matched": detect_pattern,
                    "cwe": rule.get("cwe"),
                    "severity": rule.get("severity"),
                    "description": rule.get("description"),
                    "fix": rule.get("fix"),
                    "confidence": float(rule.get("confidence", 0.75)),
                    "detection_time_ms": round(det_time_ms, 3),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "evidence": "",
                }
                try:
                    attach_cve_hints(finding, lines, cve_db)
                except Exception:
                    pass
                detections.append(finding)

    # iterate line-by-line (easy to attribute line numbers) for non-file-level rules
    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n")
        for rule in rules:
            # skip rules that were file-level (we already handled them)
            if rule.get("match_entire_file", False):
                continue
            patterns = rule.get("patterns", [])
            detect = False
            detect_pattern = None
            start_det = time.perf_counter()
            # local (per-line) matching
            matched = _match_patterns_on_line(line, patterns)
            if matched:
                detect = True
                detect_pattern = matched
            end_det = time.perf_counter()
            if detect:
                det_time_ms = (end_det - start_det) * 1000.0
                finding = {
                    "file": file_path,
                    "line": lineno,
                    "language": rule.get("language"),
                    "rule_id": rule.get("id"),
                    "vulnerability": rule.get("id"),
                    "pattern_matched": detect_pattern,
                    "cwe": rule.get("cwe"),
                    "severity": rule.get("severity"),
                    "description": rule.get("description"),
                    "fix": rule.get("fix"),
                    "confidence": float(rule.get("confidence", 0.75)),
                    "detection_time_ms": round(det_time_ms, 3),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "evidence": line.strip()
                }
                # optional attach CVE hints (best-effort)
                try:
                    attach_cve_hints(finding, lines, cve_db)
                except Exception:
                    # keep scanning even if CVE attach fails
                    pass

                # If the rule omitted an explicit CWE, provide candidate CWEs for the language
                if not finding.get("cwe"):
                    lang = finding.get("language") or detect_language_by_ext(file_path) or "unknown"
                    # normalize common ext->lang
                    lang = lang.lower()
                    candidates = LANGUAGE_CWE_LIST.get(lang)
                    if candidates:
                        # attach candidate_cwes rather than overwriting cwe
                        finding["candidate_cwes"] = candidates

                detections.append(finding)
    # Post-processing: basic function-level heuristics to boost confidence
    # Group detections by enclosing function (naive: find nearest previous line with a function-like pattern)
    def _find_func_start(idx_line: int, all_lines: List[str]) -> int:
        # search backwards for a line that looks like 'type name(...) {'
        for i in range(idx_line - 1, -1, -1):
            if re.search(r"\)\s*\{\s*$", all_lines[i]):
                return i + 1
            # also catch patterns like 'void name(' spanning multi-line signatures by looking for '){'
            if re.search(r"\w+\s+\w+\s*\([^)]*$", all_lines[i]):
                return i + 1
        return 0

    # Build mapping: func_start_line -> list of detection indexes
    func_map = {}
    for idx, det in enumerate(detections):
        fs = _find_func_start(det['line'], lines)
        func_map.setdefault(fs, []).append(idx)

    # Apply heuristics per function
    for fs, idxs in func_map.items():
        # collect rule ids present
        rids = [detections[i]['rule_id'] for i in idxs]
        has_malloc = any('malloc' in rid for rid in rids)
        has_memcpy = any('memcpy' in detections[i].get('pattern_matched', '') or 'memcpy' in detections[i].get('evidence', '') for i in idxs)
        # boost when both malloc and memcpy appear in same function
        if has_malloc and has_memcpy:
            for i in idxs:
                detections[i]['confidence'] = min(1.0, float(detections[i].get('confidence', 0.75)) + 0.2)
        # vsnprintf termination heuristic: if vsnprintf found, look for '\\0' or manual termination nearby
        for i in idxs:
            if 'vsnprintf' in (detections[i].get('pattern_matched') or '') or 'vsnprintf' in detections[i].get('evidence', ''):
                # search next 6 lines for \0 or manual termination
                start = detections[i]['line']
                end = min(len(lines), start + 6)
                block = ''.join(lines[start:end])
                if re.search(r"\\0|\\\'\\0\\\'|last\s*==\s*'\\0'|if\s*\(.*\\0.*\)", block):
                    detections[i]['confidence'] = min(1.0, float(detections[i].get('confidence', 0.7)) + 0.1)

        # Generic cross-language co-occurrence boost:
        # If a function/block contains multiple detections and at least one is high severity,
        # increase confidence for all detections in that block slightly. This helps promote
        # findings where sources and sinks co-occur (e.g. user-input + SQL exec) across languages.
        for fs, idxs in func_map.items():
            if len(idxs) <= 1:
                continue
            severities = [str(detections[i].get('severity', '')).lower() for i in idxs]
            if any(s == 'high' for s in severities):
                for i in idxs:
                    detections[i]['confidence'] = min(1.0, float(detections[i].get('confidence', 0.75)) + 0.15)

    end_file = time.perf_counter()
    file_time_ms = (end_file - start_file) * 1000.0
    return {
        "file": file_path,
        "file_time_ms": round(file_time_ms, 3),
        "file_lines": len(lines),
        "detections": detections
    }


def scan_repository(repo_root: str, cve_db: Optional[Dict[str, Any]] = None, verbose: bool = False) -> Dict[str, Any]:
    """
    Walk repo_root recursively, detect language by extension, load per-language rules,
    and scan each file. Returns a result dict:
    {
      "repo": repo_root,
      "start_time": "<iso>",
      "end_time": "<iso>",
      "total_time_ms": <float>,
      "files_scanned": N,
      "findings": [ ... per-file results ... ],
      "summary": { total_detections, total_files, avg_detection_time_ms, ... }
    }
    """
    repo_start = time.perf_counter()
    findings_per_file = []
    total_detections = 0
    total_det_time = 0.0
    files_scanned = 0

    # cache rules per language
    rules_cache: Dict[str, List[Dict[str, Any]]] = {}

    for root, dirs, files in os.walk(repo_root):
        # filter out common large dirs
        dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'venv', '__pycache__', 'build', 'dist')]
        for fn in files:
            file_path = os.path.join(root, fn)
            lang = detect_language_by_ext(fn)
            if not lang:
                continue
            # load rules for language (cache)
            if lang not in rules_cache:
                try:
                    rules_cache[lang] = load_rules(lang)
                except FileNotFoundError:
                    # no rules defined for this language — skip
                    rules_cache[lang] = []
            rules = rules_cache[lang]
            if not rules:
                if verbose:
                    print(f"[INFO] No rules for language {lang}, skipping file {file_path}")
                continue

            if verbose:
                print(f"[SCAN] {file_path} (lang={lang}, rules={len(rules)})")
            files_scanned += 1
            file_result = scan_file_with_rules(file_path, rules, cve_db=cve_db)
            total_detections += len(file_result.get("detections", []))
            for d in file_result.get("detections", []):
                total_det_time += float(d.get("detection_time_ms", 0.0))
            findings_per_file.append(file_result)

    repo_end = time.perf_counter()
    total_time_ms = (repo_end - repo_start) * 1000.0
    avg_det_time = (total_det_time / total_detections) if total_detections else 0.0

    result = {
        "repo": repo_root,
        "start_time": datetime.utcnow().isoformat() + "Z",
        "end_time": datetime.utcnow().isoformat() + "Z",
        "total_time_ms": round(total_time_ms, 3),
        "files_scanned": files_scanned,
        "total_detections": total_detections,
        "avg_detection_time_ms": round(avg_det_time, 3),
        "findings_per_file": findings_per_file
    }
    return result


def save_findings(scan_result: Dict[str, Any], output_file: Optional[str] = None) -> str:
    """
    Save the scan result to output/findings.json by default (create folder if needed).
    Returns path of written file.
    """
    ensure_output_folder()
    # By default, write a flattened findings.json for easier downstream consumption
    if not output_file:
        output_file = os.path.join(OUTPUT_FOLDER, "findings.json")

    with open(output_file, "w", encoding="utf8") as fh:
        json.dump(scan_result, fh, indent=2)
    return output_file


def flatten_findings(scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert the scan_repository result into a flat list of detection dicts.
    Each detection will include file, line, language, cwe, severity, description, fix, timestamp, and optional cve_matches.
    """
    flat: List[Dict[str, Any]] = []
    for file_block in scan_result.get("findings_per_file", []):
        for det in file_block.get("detections", []):
            file_path = det.get("file", file_block.get("file"))
            rel_path = os.path.relpath(file_path, start=os.getcwd())
            # determine language: prefer detection, fall back to file extension mapping
            lang = det.get("language")
            if not lang:
                # infer from file extension
                ext = os.path.splitext(file_path)[1].lower()
                ext_map = {
                    ".py": "python",
                    ".java": "java",
                    ".js": "javascript",
                    ".ts": "typescript",
                    ".c": "c",
                    ".cpp": "cpp",
                    ".cc": "cpp",
                    ".h": "c",
                    ".cs": "csharp",
                    ".php": "php",
                    ".go": "go",
                    ".rb": "ruby",
                }
                lang = ext_map.get(ext) or "unknown"

            item = {
                "file": rel_path,
                "line": det.get("line"),
                "language": lang,
                "vulnerability": det.get("vulnerability") or det.get("rule_id"),
                "cwe": det.get("cwe"),
                # include candidate CWEs if provided by scanner heuristics
                "candidate_cwes": det.get("candidate_cwes"),
                "severity": det.get("severity"),
                "description": det.get("description"),
                "fix": det.get("fix"),
                "timestamp": det.get("timestamp"),
                "detection_time_ms": det.get("detection_time_ms"),
                "evidence": det.get("evidence"),
            }
            if "cve_matches" in det:
                item["cve_matches"] = det["cve_matches"]
            flat.append(item)
    return flat


# -------------------------
# If run directly, quick demo (for dev)
# -------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run rule-based scan on a repository")
    parser.add_argument("--repo", "-r", required=True, help="Path to repository to scan")
    parser.add_argument("--cve_db", help="Optional local CVE DB JSON file for lightweight matching")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    cve_db = None
    if args.cve_db:
        try:
            with open(args.cve_db, "r", encoding="utf8") as f:
                cve_db = json.load(f)
            print(f"[INFO] Loaded CVE DB with {len(cve_db)} keys")
        except Exception as e:
            print(f"[WARN] Failed to load cve_db: {e}")

    res = scan_repository(args.repo, cve_db=cve_db, verbose=args.verbose)
    outp = save_findings(res)
    print(f"[DONE] Results saved to {outp}")
    print(f"Summary: files={res['files_scanned']}, detections={res['total_detections']}, total_time_ms={res['total_time_ms']}")
