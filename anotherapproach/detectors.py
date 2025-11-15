import ast
import re
from typing import List, Dict, Any, Tuple

from .cwe import CWES


class Finding:
    def __init__(self, ftype: str, start: int, end: int, snippet: str, confidence: float):
        self.ftype = ftype
        self.start = start
        self.end = end
        self.snippet = snippet
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        meta = CWES.get(self.ftype, {"cwe": "CWE-unknown", "name": self.ftype})
        return {
            "type": self.ftype,
            "cwe": meta["cwe"],
            "title": meta["name"],
            "start_line": self.start,
            "end_line": self.end,
            "snippet": self.snippet,
            "confidence": self.confidence,
        }


def _extract_snippet(lines: List[str], start: int, end: int, pad: int = 0) -> str:
    s = max(1, start - pad) - 1
    e = min(len(lines), end + pad)
    return "".join(lines[s:e])


class AstDetectors(ast.NodeVisitor):
    def __init__(self, code: str):
        self.code = code
        self.lines = code.splitlines(keepends=True)
        self.findings: List[Finding] = []

    def visit_Call(self, node: ast.Call):
        name = _get_call_name(node)
        # eval/exec
        if name in {"eval", "exec"}:
            self._add("EVAL_EXEC", node)

        # pickle.load/loads
        if name in {"pickle.load", "pickle.loads"}:
            self._add("PICKLE_LOAD", node)

        # subprocess with shell=True or string command
        if name and name.startswith("subprocess."):
            shell_true = any(
                isinstance(kw, ast.keyword) and kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            args_concat = any(_is_str_concat(arg) for arg in node.args)
            if shell_true or args_concat:
                self._add("SUBPROCESS_SHELL", node)

        # suspicious SQL execution by concatenation
        if name in {"execute", "executemany", "executescript"}:
            if node.args and _is_str_concat(node.args[0]):
                self._add("SQL_STRING_CONCAT", node)

        # open with write/append potentially unsafe
        if name == "open":
            mode = _second_arg_constant_str(node)
            if mode and any(m in mode for m in ["w", "a", "+"]):
                self._add("PATH_TRAVERSAL", node)

        # requests without verify=True
        if name and name.startswith("requests."):
            has_verify_kw = any(isinstance(kw, ast.keyword) and kw.arg == "verify" for kw in node.keywords)
            if not has_verify_kw:
                self._add("REQUESTS_INSECURE", node)

        self.generic_visit(node)

    def _add(self, ftype: str, node: ast.AST, conf: float = 0.9):
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start)
        snippet = _extract_snippet(self.lines, start, end)
        self.findings.append(Finding(ftype, start, end, snippet, conf))


def _get_call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return _attr_full_name(node.func)
    return ""


def _attr_full_name(attr: ast.Attribute) -> str:
    parts = []
    cur = attr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return ".".join(parts)


def _is_str_concat(expr: ast.AST) -> bool:
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(expr, ast.JoinedStr):
        return True
    return False


def _second_arg_constant_str(node: ast.Call) -> str:
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
        return node.args[1].value
    return ""


SECRET_REGEXES = [
    re.compile(r"(?i)(api|secret|token|passwd|password|pwd)\s*=\s*['\"]([^'\"]{6,})['\"]"),
]

WEAK_CRYPTO_REGEXES = [
    re.compile(r"hashlib\.(md5|sha1)\s*\(")
]

BASE64_BLOB = re.compile(r"['\"][A-Za-z0-9+/]{40,}={0,2}['\"]")


def regex_detectors(code: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = code.splitlines(keepends=True)
    for i, line in enumerate(lines, start=1):
        for rgx in SECRET_REGEXES:
            if rgx.search(line):
                findings.append(Finding("HARDCODED_CREDENTIAL", i, i, line, 0.85))
        for rgx in WEAK_CRYPTO_REGEXES:
            if rgx.search(line):
                findings.append(Finding("WEAK_CRYPTO", i, i, line, 0.8))
        if BASE64_BLOB.search(line):
            findings.append(Finding("HARDCODED_CREDENTIAL", i, i, line, 0.6))
    return findings


def run_all_detectors(code: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        tree = ast.parse(code)
        v = AstDetectors(code)
        v.visit(tree)
        findings.extend(v.findings)
    except SyntaxError:
        pass
    findings.extend(regex_detectors(code))
    return findings


def merge_overlaps(findings: List[Finding]) -> List[Finding]:
    if not findings:
        return findings
    findings = sorted(findings, key=lambda f: (f.start, f.end))
    merged: List[Finding] = []
    cur = findings[0]
    for f in findings[1:]:
        if f.start <= cur.end and f.ftype == cur.ftype:
            cur.end = max(cur.end, f.end)
            cur.confidence = max(cur.confidence, f.confidence)
            if len(f.snippet) > len(cur.snippet):
                cur.snippet = f.snippet
        else:
            merged.append(cur)
            cur = f
    merged.append(cur)
    return merged


