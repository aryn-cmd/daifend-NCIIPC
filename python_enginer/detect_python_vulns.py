#!/usr/bin/env python3
"""
detect_python_vulns.py
Simple prototype for locating vulnerabilities in Python snippets,
mapping to CWE, and computing F1 given gold_total or gold_locations.
"""

import ast, re, json, sys, argparse
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

# --- Config / mapping ---
CWE_MAP = {
    "eval_exec": ("CWE-94", "Code Injection"),
    "subprocess": ("CWE-78", "OS Command Injection"),
    "pickle": ("CWE-502", "Deserialization of Untrusted Data"),
    "sql_string_concat": ("CWE-89", "SQL Injection"),
    "hardcoded_secret": ("CWE-798", "Hard-coded Credentials"),
    "weak_crypto": ("CWE-327", "Broken Cryptographic Algorithm"),
    "path_traversal": ("CWE-22", "Path Traversal"),
}

# Add CWE mappings for C/Java heuristics
CWE_MAP.update({
    "strcpy": ("CWE-120", "Buffer Copy without Checking Size"),
    "gets": ("CWE-242", "Use of Insecure Function"),
    "system_c": ("CWE-78", "OS Command Injection"),
    "sql_string_concat": ("CWE-89", "SQL Injection"),
    "unsafe_deserialization_java": ("CWE-502", "Deserialization of Untrusted Data"),
})

# Regex detectors (quick heuristics)
RE_HARDCODED_SECRET = re.compile(r"(?:API_KEY|SECRET|PASSWORD|passwd|token)[\"'\s:=]{1,5}['\"][^'\"]{8,}['\"]", re.I)
RE_BASE64_LIKE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")  # long base64
RE_MD5 = re.compile(r"\bhashlib\.md5\b")

# --- Utility functions ---
def load_jsonl(path: str):
    with open(path, "r", encoding="utf8") as f:
        for ln in f:
            if ln.strip():
                yield json.loads(ln)

def snippet_lines(code: str):
    return code.splitlines()


def list_repo_files(repo_path: str) -> List[str]:
    """List source files recursively under repo_path for supported languages."""
    exts = {"py", "c", "h", "cpp", "java"}
    out = []
    for root, dirs, files in __import__('os').walk(repo_path):
        for f in files:
            if f.split('.')[-1].lower() in exts:
                out.append(__import__('os').path.join(root, f))
    return out

# --- Detectors ---
def detect_eval_exec(tree: ast.AST) -> List[Dict]:
    hits = []
    class EvalVisitor(ast.NodeVisitor):
        def visit_Call(self, node):
            try:
                func = node.func
                name = getattr(func, 'id', None) or getattr(func, 'attr', None)
                if name in ("eval","exec","execfile"):
                    hits.append((node.lineno, node.end_lineno if hasattr(node,'end_lineno') else node.lineno, "eval_exec"))
            except Exception:
                pass
            self.generic_visit(node)
    EvalVisitor().visit(tree)
    return [{"type":"eval_exec","start":s,"end":e,"confidence":0.95} for s,e,_ in hits]

def detect_subprocess(tree: ast.AST) -> List[Dict]:
    hits=[]
    class SubVisitor(ast.NodeVisitor):
        def visit_Import(self,node):
            self.generic_visit(node)
        def visit_Attribute(self,node):
            # look for subprocess.* or os.system
            try:
                val = node.value
                if isinstance(val, ast.Name) and val.id in ("subprocess","os") and getattr(node, "attr", "") in ("system","popen","call","run"):
                    hits.append((node.lineno, getattr(node, "end_lineno", node.lineno), "subprocess"))
            except Exception:
                pass
            self.generic_visit(node)
    SubVisitor().visit(tree)
    return [{"type":"subprocess","start":s,"end":e,"confidence":0.9} for s,e,_ in hits]

def detect_pickle(tree: ast.AST) -> List[Dict]:
    hits=[]
    class PickleVisitor(ast.NodeVisitor):
        def visit_Attribute(self,node):
            try:
                if getattr(node, "attr", "") in ("load","loads") and isinstance(node.value, ast.Name) and node.value.id in ("pickle","cPickle"):
                    hits.append((node.lineno, getattr(node,'end_lineno',node.lineno), "pickle"))
            except Exception:
                pass
            self.generic_visit(node)
    PickleVisitor().visit(tree)
    return [{"type":"pickle","start":s,"end":e,"confidence":0.9} for s,e,_ in hits]

def detect_sql_string_concat(tree: ast.AST) -> List[Dict]:
    hits=[]
    class SQLVisitor(ast.NodeVisitor):
        def visit_Call(self,node):
            # heuristically detect .execute("..."+var) or f"select {var}" passed into execute
            try:
                if getattr(node.func, "attr", "").lower() == "execute":
                    for arg in node.args:
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add,)):
                            hits.append((node.lineno, getattr(node,'end_lineno',node.lineno),"sql_string_concat"))
                        if isinstance(arg, ast.JoinedStr):
                            # f-string passed to execute is risky
                            hits.append((node.lineno, getattr(node,'end_lineno',node.lineno),"sql_string_concat"))
                        if isinstance(arg, ast.Constant) and isinstance(arg.value,str) and ("%" in arg.value or "{}" in arg.value):
                            # string formatting maybe used.
                            hits.append((node.lineno, getattr(node,'end_lineno',node.lineno),"sql_string_concat"))
            except Exception:
                pass
            self.generic_visit(node)
    SQLVisitor().visit(tree)
    # dedup
    seen=set()
    out=[]
    for s,e,t in hits:
        if (s,e,t) not in seen:
            seen.add((s,e,t)); out.append({"type":t,"start":s,"end":e,"confidence":0.9})
    return out

def regex_detectors(code: str) -> List[Dict]:
    hits=[]
    for m in RE_HARDCODED_SECRET.finditer(code):
        s = code[:m.start()].count("\n")+1
        e = code[:m.end()].count("\n")+1
        hits.append({"type":"hardcoded_secret","start":s,"end":e,"confidence":0.95})
    m_b64 = RE_BASE64_LIKE.search(code)
    if m_b64:
        s = code[:m_b64.start()].count("\n")+1
        hits.append({"type":"hardcoded_secret","start":s,"end":s,"confidence":0.6})
    m_md5 = RE_MD5.search(code)
    if m_md5:
        # line of occurrence
        s = code[:m_md5.start()].count("\n")+1
        hits.append({"type":"weak_crypto","start":s,"end":s,"confidence":0.8})
    return hits


# --- Simple C/Java detectors (heuristic regexes) ---
RE_STRCPY = re.compile(r"\bstrcpy\s*\(")
RE_GETS = re.compile(r"\bgets\s*\(")
RE_SYSTEM_C = re.compile(r"\bsystem\s*\(")
RE_SQL_CONCAT_C = re.compile(r"\bexecute\s*\(|\bsqlite3_exec\s*\(")

def detect_c_java(code: str, path: Optional[str]=None) -> List[Dict]:
    """Heuristic detections for C/C++/Java source files using regexes."""
    hits = []
    lines = code.splitlines()
    for i, line in enumerate(lines, start=1):
        if RE_STRCPY.search(line):
            hits.append({"type":"strcpy","start":i,"end":i,"confidence":0.9})
        if RE_GETS.search(line):
            hits.append({"type":"gets","start":i,"end":i,"confidence":0.95})
        if RE_SYSTEM_C.search(line):
            hits.append({"type":"system_c","start":i,"end":i,"confidence":0.8})
        if RE_SQL_CONCAT_C.search(line):
            hits.append({"type":"sql_string_concat","start":i,"end":i,"confidence":0.8})
        # Java-specific heuristics (simple): deserialize from ObjectInputStream
        if "ObjectInputStream" in line or "readObject(" in line:
            hits.append({"type":"unsafe_deserialization_java","start":i,"end":i,"confidence":0.85})
    return hits

# --- Postprocess & merge overlapping hits ---
def merge_hits(hits: List[Dict]) -> List[Dict]:
    if not hits:
        return []
    # sort by start line
    hits = sorted(hits, key=lambda x:(x["start"], -x.get("confidence",0)))
    merged=[]
    cur = hits[0].copy()
    for h in hits[1:]:
        if h["start"] <= cur["end"]+1:
            # overlap -> extend and maybe combine types
            cur["end"] = max(cur["end"], h["end"])
            # append type list
            if isinstance(cur.get("types"), list):
                if h["type"] not in cur["types"]:
                    cur["types"].append(h["type"])
            else:
                cur["types"] = [cur["type"], h["type"]] if h["type"]!=cur["type"] else [cur["type"]]
            cur["confidence"] = max(cur.get("confidence",0), h.get("confidence",0))
        else:
            # finalize cur
            if "types" not in cur:
                cur["types"] = [cur["type"]]
            merged.append(cur)
            cur = h.copy()
    if "types" not in cur:
        cur["types"] = [cur["type"]]
    merged.append(cur)
    return merged

# --- Map type -> CWE info ---
def attach_cwe(hit: Dict) -> Dict:
    # take first type for mapping
    t = hit.get("types",[hit.get("type")])[0]
    if t in CWE_MAP:
        hit["cwe"], hit["cwe_desc"] = CWE_MAP[t]
    else:
        hit["cwe"], hit["cwe_desc"] = ("CWE-000", "Unknown")
    return hit

# --- Matching detections to gold (if gold locations provided) ---
def match_to_gold(detections: List[Dict], gold_locations: List[Tuple[int,int]]) -> Tuple[int,int,int]:
    # returns TP, FP, FN
    matched = set()
    tp = 0
    for di, d in enumerate(detections):
        ds, de = d["start"], d["end"]
        found=False
        for gi, (gs, ge) in enumerate(gold_locations):
            # consider match if overlap >= 1 line
            if not (de < gs or ds > ge):
                found=True
                matched.add(gi)
                break
        if found:
            tp += 1
    fp = len(detections) - tp
    fn = len(gold_locations) - len(matched)
    return tp, fp, fn

# --- Compute F1 when only gold_total known (conservative heuristic) ---
def compute_f1_from_counts(detected_count: int, gold_total: int) -> Tuple[float,float,float]:
    tp = min(detected_count, gold_total)
    fp = max(0, detected_count - tp)
    fn = max(0, gold_total - tp)
    precision = tp / (tp+fp) if (tp+fp)>0 else 0.0
    recall = tp / (tp+fn) if (tp+fn)>0 else 0.0
    f1 = 2*precision*recall/(precision+recall) if (precision+recall)>0 else 0.0
    return precision, recall, f1

# --- Main per-snippet processing ---
def analyze_snippet(snippet: Dict) -> Dict:
    code = snippet.get("code","")
    recs=[]
    # AST based detectors
    try:
        tree = ast.parse(code)
    except Exception as e:
        tree = None
    if tree:
        recs.extend(detect_eval_exec(tree))
        recs.extend(detect_subprocess(tree))
        recs.extend(detect_pickle(tree))
        recs.extend(detect_sql_string_concat(tree))
    # regex detectors
    recs.extend(regex_detectors(code))

    # merge and attach CWE
    merged = merge_hits(recs)
    for m in merged:
        attach_cwe(m)
        # add snippet text
        lines = snippet_lines(code)
        s = max(1, m["start"]-1)
        e = min(len(lines), m["end"])
        m["snippet"] = "\n".join(lines[s:e])
    # form output
    out = {
        "id": snippet.get("id"),
        "detections": merged,
        "detected_count": len(merged)
    }

    # scoring
    gold_total = snippet.get("gold_total")
    gold_locations = snippet.get("gold_locations")  # optional list of [start,end]
    if gold_locations:
        tp,fp,fn = match_to_gold(merged, gold_locations)
        precision = tp / (tp+fp) if (tp+fp)>0 else 0.0
        recall = tp / (tp+fn) if (tp+fn)>0 else 0.0
        f1 = 2*precision*recall/(precision+recall) if (precision+recall)>0 else 0.0
        out["metrics"] = {"tp":tp,"fp":fp,"fn":fn,"precision":precision,"recall":recall,"f1":f1}
    elif gold_total is not None:
        precision, recall, f1 = compute_f1_from_counts(len(merged), gold_total)
        out["metrics"] = {"precision":precision,"recall":recall,"f1":f1,"gold_total":gold_total,"detected":len(merged)}
    else:
        out["metrics"] = None
    return out


def detect_language_from_path(path: str) -> str:
    ext = path.split('.')[-1].lower()
    if ext in ("py",):
        return "python"
    if ext in ("c","h","cpp","cc","cxx"):
        return "c"
    if ext in ("java",):
        return "java"
    return "unknown"


def analyze_file(path: str, language: Optional[str]=None) -> Dict:
    """Analyze a source file and return a detection record similar to analyze_snippet."""
    with open(path, 'r', encoding='utf8', errors='ignore') as f:
        code = f.read()
    lang = language or detect_language_from_path(path)
    recs = []
    if lang == 'python':
        try:
            tree = ast.parse(code)
        except Exception:
            tree = None
        if tree:
            recs.extend(detect_eval_exec(tree))
            recs.extend(detect_subprocess(tree))
            recs.extend(detect_pickle(tree))
            recs.extend(detect_sql_string_concat(tree))
        recs.extend(regex_detectors(code))
    elif lang in ('c','java'):
        recs.extend(detect_c_java(code, path=path))
        # still run regex-based secret/crypto detectors
        recs.extend(regex_detectors(code))
    else:
        # fallback: run regex detectors
        recs.extend(regex_detectors(code))

    merged = merge_hits(recs)
    for m in merged:
        attach_cwe(m)
        lines = snippet_lines(code)
        s = max(1, m['start']-1)
        e = min(len(lines), m['end'])
        m['snippet'] = '\n'.join(lines[s:e])
    out = {
        'path': path,
        'language': lang,
        'detections': merged,
        'detected_count': len(merged)
    }
    return out

# --- CLI & IO ---
def main():
    parser = argparse.ArgumentParser(description="Detect simple vulnerabilities in Python/C/Java sources or JSONL snippets")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", "-i", help="input JSONL file with fields id, code, gold_total (opt) or gold_locations (opt)")
    group.add_argument("--repo", "-r", help="local repository path to scan (recursively)")
    parser.add_argument("--output", "-o", default="results.jsonl", help="output JSONL with detections + metrics")
    parser.add_argument("--language", "-l", help="optional language override: python, c, java")
    args = parser.parse_args()

    outs = []
    with open(args.output, "w", encoding="utf8") as fo:
        if args.input:
            for rec in load_jsonl(args.input):
                r = analyze_snippet(rec)
                fo.write(json.dumps(r, ensure_ascii=False) + "\n")
                outs.append(r)
        else:
            # repo scanning
            repo_path = args.repo
            # if it's a URL, attempt to clone into a temp dir
            import os, tempfile, subprocess
            target = repo_path
            if repo_path.startswith("http://") or repo_path.startswith("https://") or repo_path.endswith(".git"):
                td = tempfile.mkdtemp(prefix='repo_')
                try:
                    subprocess.check_call(["git","clone",repo_path,td])
                    target = td
                except Exception as e:
                    print(f"Failed to clone {repo_path}: {e}")
                    return
            files = list_repo_files(target)
            for p in files:
                r = analyze_file(p, language=args.language)
                fo.write(json.dumps(r, ensure_ascii=False) + "\n")
                outs.append(r)

    # print a small summary
    total = len(outs)
    total_detected = sum(r.get('detected_count',0) for r in outs)
    print(f"Scanned {total} items, total detections: {total_detected}")
    print(f"Output written to {args.output}")

if __name__=="__main__":
    main()
