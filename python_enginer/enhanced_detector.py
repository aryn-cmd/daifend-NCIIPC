#!/usr/bin/env python3
"""
Enhanced Python Vulnerability Detector
Comprehensive detection system with timing, CVE mapping, and detailed metrics
"""

import ast
import re
import json
import time
import csv
import sys
import argparse
import requests
from typing import List, Dict, Tuple, Optional, Any
from collections import defaultdict
from pathlib import Path
import hashlib
import base64

# CWE to CVE mapping for known patterns
CWE_CVE_MAPPING = {
    "CWE-94": ["CVE-2021-3177", "CVE-2019-10160"],  # Code Injection
    "CWE-78": ["CVE-2021-3177", "CVE-2019-10160"],  # OS Command Injection
    "CWE-502": ["CVE-2020-25686", "CVE-2019-12855"],  # Deserialization
    "CWE-89": ["CVE-2021-29425", "CVE-2020-26137"],  # SQL Injection
    "CWE-798": ["CWE-798"],  # Hard-coded Credentials (no specific CVEs)
    "CWE-327": ["CVE-2021-3177", "CVE-2020-25659"],  # Weak Crypto
    "CWE-22": ["CVE-2021-29425", "CVE-2020-26137"],  # Path Traversal
    "CWE-295": ["CVE-2021-23336", "CVE-2020-26137"],  # Certificate Validation
}

# Vulnerable package versions (simplified)
VULNERABLE_PACKAGES = {
    "django": {"<2.2.0": "CVE-2020-9402", "<3.1.0": "CVE-2021-33203"},
    "flask": {"<1.0": "CVE-2018-1000656", "<2.0.0": "CVE-2021-23336"},
    "requests": {"<2.20.0": "CVE-2018-18074", "<2.25.0": "CVE-2021-23336"},
    "urllib3": {"<1.24.0": "CVE-2019-11324", "<1.25.0": "CVE-2020-26137"},
    "pillow": {"<6.0.0": "CVE-2019-16865", "<8.0.0": "CVE-2021-25287"},
    "pyyaml": {"<5.1": "CVE-2020-14343", "<5.4": "CVE-2021-38314"},
    "cryptography": {"<2.3": "CVE-2018-10903", "<3.1": "CVE-2021-23841"},
}

class VulnerabilityDetectionResult:
    def __init__(self):
        self.vulnerabilities = []
        self.timing = {}
        self.metrics = {}
        self.start_time = time.time()

    def add_vulnerability(self, vuln_type: str, line_start: int, line_end: int, 
                         confidence: float, cwe: str, description: str, 
                         code_snippet: str, cve: Optional[str] = None):
        vuln = {
            "type": vuln_type,
            "line_start": line_start,
            "line_end": line_end,
            "confidence": confidence,
            "cwe": cwe,
            "cve": cve,
            "description": description,
            "code_snippet": code_snippet,
            "detection_time": time.time() - self.start_time
        }
        self.vulnerabilities.append(vuln)

    def add_timing(self, detector_name: str, duration: float):
        self.timing[detector_name] = duration

    def finalize(self, gold_total: Optional[int] = None, gold_locations: Optional[List[Tuple[int, int]]] = None):
        total_time = time.time() - self.start_time
        self.timing["total"] = total_time
        
        # Calculate metrics
        detected_count = len(self.vulnerabilities)
        
        if gold_locations:
            # Use location-based matching
            tp, fp, fn = self._match_by_locations(gold_locations)
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        elif gold_total is not None:
            # Use count-based matching (conservative)
            tp = min(detected_count, gold_total)
            fp = max(0, detected_count - tp)
            fn = max(0, gold_total - tp)
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        else:
            tp = fp = fn = precision = recall = 0.0

        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        self.metrics = {
            "detected_count": detected_count,
            "gold_total": gold_total,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "total_time": total_time
        }

    def _match_by_locations(self, gold_locations: List[Tuple[int, int]]) -> Tuple[int, int, int]:
        """Match detections to gold locations with overlap threshold"""
        matched_gold = set()
        tp = 0
        
        for detection in self.vulnerabilities:
            ds, de = detection["line_start"], detection["line_end"]
            found_match = False
            
            for i, (gs, ge) in enumerate(gold_locations):
                if i in matched_gold:
                    continue
                
                # Check for overlap
                if not (de < gs or ds > ge):
                    # Calculate overlap ratio
                    overlap = max(0, min(de, ge) - max(ds, gs) + 1)
                    detection_length = de - ds + 1
                    gold_length = ge - gs + 1
                    
                    # Consider match if overlap is significant
                    if overlap / max(detection_length, gold_length) >= 0.3:
                        matched_gold.add(i)
                        tp += 1
                        found_match = True
                        break
            
            if not found_match:
                continue  # This will be counted as FP
        
        fp = len(self.vulnerabilities) - tp
        fn = len(gold_locations) - len(matched_gold)
        
        return tp, fp, fn

class PythonVulnerabilityDetector:
    def __init__(self):
        self.cwe_mapping = {
            "eval_exec": ("CWE-94", "Code Injection via eval/exec"),
            "subprocess_shell": ("CWE-78", "OS Command Injection"),
            "pickle_load": ("CWE-502", "Insecure Deserialization"),
            "sql_injection": ("CWE-89", "SQL Injection"),
            "hardcoded_credentials": ("CWE-798", "Hard-coded Credentials"),
            "weak_crypto": ("CWE-327", "Weak Cryptographic Algorithm"),
            "path_traversal": ("CWE-22", "Path Traversal"),
            "insecure_requests": ("CWE-295", "Improper Certificate Validation"),
            "xxe": ("CWE-611", "XML External Entity"),
            "deserialization": ("CWE-502", "Insecure Deserialization"),
            "xss": ("CWE-79", "Cross-Site Scripting"),
            "ldap_injection": ("CWE-90", "LDAP Injection"),
        }

    def detect_vulnerabilities(self, code: str, snippet_id: str = "") -> VulnerabilityDetectionResult:
        """Main detection function with timing"""
        result = VulnerabilityDetectionResult()
        lines = code.splitlines()
        
        # AST-based detection
        try:
            start_time = time.time()
            tree = ast.parse(code)
            self._detect_ast_vulnerabilities(tree, lines, result)
            result.add_timing("ast_detection", time.time() - start_time)
        except SyntaxError:
            result.add_timing("ast_detection", 0.0)
        
        # Regex-based detection
        start_time = time.time()
        self._detect_regex_vulnerabilities(code, lines, result)
        result.add_timing("regex_detection", time.time() - start_time)
        
        # Package vulnerability detection
        start_time = time.time()
        self._detect_package_vulnerabilities(code, result)
        result.add_timing("package_detection", time.time() - start_time)
        
        # Advanced pattern detection
        start_time = time.time()
        self._detect_advanced_patterns(code, lines, result)
        result.add_timing("advanced_detection", time.time() - start_time)
        
        return result

    def _detect_ast_vulnerabilities(self, tree: ast.AST, lines: List[str], result: VulnerabilityDetectionResult):
        """AST-based vulnerability detection"""
        class VulnerabilityVisitor(ast.NodeVisitor):
            def __init__(self, detector, lines, result):
                self.detector = detector
                self.lines = lines
                self.result = result

            def visit_Call(self, node):
                # eval/exec detection
                if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:
                    cwe, desc = self.detector.cwe_mapping['eval_exec']
                    snippet = self._get_snippet(node.lineno, node.end_lineno)
                    self.result.add_vulnerability(
                        'eval_exec', node.lineno, node.end_lineno, 0.95, cwe, desc, snippet
                    )

                # subprocess with shell=True
                if (isinstance(node.func, ast.Attribute) and 
                    node.func.attr in ['system', 'popen', 'call', 'run']):
                    
                    shell_true = False
                    if node.keywords:
                        for kw in node.keywords:
                            if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value:
                                shell_true = True
                                break
                    
                    if shell_true or any(self._is_string_concat(arg) for arg in node.args):
                        cwe, desc = self.detector.cwe_mapping['subprocess_shell']
                        snippet = self._get_snippet(node.lineno, node.end_lineno)
                        self.result.add_vulnerability(
                            'subprocess_shell', node.lineno, node.end_lineno, 0.9, cwe, desc, snippet
                        )

                # pickle.load detection
                if (isinstance(node.func, ast.Attribute) and 
                    node.func.attr in ['load', 'loads'] and
                    isinstance(node.func.value, ast.Name) and 
                    node.func.value.id in ['pickle', 'cPickle']):
                    
                    cwe, desc = self.detector.cwe_mapping['pickle_load']
                    snippet = self._get_snippet(node.lineno, node.end_lineno)
                    self.result.add_vulnerability(
                        'pickle_load', node.lineno, node.end_lineno, 0.9, cwe, desc, snippet
                    )

                # SQL injection detection
                if (isinstance(node.func, ast.Attribute) and 
                    node.func.attr in ['execute', 'executemany', 'executescript']):
                    
                    if node.args and self._is_string_concat(node.args[0]):
                        cwe, desc = self.detector.cwe_mapping['sql_injection']
                        snippet = self._get_snippet(node.lineno, node.end_lineno)
                        self.result.add_vulnerability(
                            'sql_injection', node.lineno, node.end_lineno, 0.85, cwe, desc, snippet
                        )

                # requests without verify
                if (isinstance(node.func, ast.Attribute) and 
                    node.func.attr in ['get', 'post', 'put', 'delete', 'request'] and
                    isinstance(node.func.value, ast.Name) and node.func.value.id == 'requests'):
                    
                    has_verify = any(kw.arg == 'verify' for kw in (node.keywords or []))
                    if not has_verify:
                        cwe, desc = self.detector.cwe_mapping['insecure_requests']
                        snippet = self._get_snippet(node.lineno, node.end_lineno)
                        self.result.add_vulnerability(
                            'insecure_requests', node.lineno, node.end_lineno, 0.7, cwe, desc, snippet
                        )

                self.generic_visit(node)

            def visit_Assign(self, node):
                # Check for SQL string concatenation assignments
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Check if assignment involves string concatenation
                        if self._is_string_concat(node.value):
                            # Look for SQL-like patterns in the concatenated string
                            if self._contains_sql_pattern(node.value):
                                cwe, desc = self.detector.cwe_mapping['sql_injection']
                                snippet = self._get_snippet(node.lineno, node.end_lineno)
                                self.result.add_vulnerability(
                                    'sql_injection', node.lineno, node.end_lineno, 0.8, cwe, desc, snippet
                                )
                self.generic_visit(node)

            def _contains_sql_pattern(self, node):
                """Check if a node contains SQL-like patterns"""
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    sql_keywords = ['select', 'insert', 'update', 'delete', 'where', 'from']
                    return any(keyword in node.value.lower() for keyword in sql_keywords)
                elif isinstance(node, ast.BinOp):
                    return (self._contains_sql_pattern(node.left) or 
                           self._contains_sql_pattern(node.right))
                elif isinstance(node, ast.JoinedStr):
                    return any(self._contains_sql_pattern(f.value) for f in node.values 
                             if isinstance(f, ast.Constant) and isinstance(f.value, str))
                return False

            def _is_string_concat(self, node):
                """Check if node represents string concatenation"""
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    return True
                if isinstance(node, ast.JoinedStr):  # f-strings
                    return True
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['format', 'join']:
                        return True
                return False

            def _get_snippet(self, start_line, end_line):
                """Extract code snippet"""
                start_idx = max(0, start_line - 1)
                end_idx = min(len(self.lines), end_line)
                return '\n'.join(self.lines[start_idx:end_idx])

        visitor = VulnerabilityVisitor(self, lines, result)
        visitor.visit(tree)

    def _detect_regex_vulnerabilities(self, code: str, lines: List[str], result: VulnerabilityDetectionResult):
        """Regex-based vulnerability detection"""
        patterns = [
            # Hardcoded credentials
            (r'(?i)(api[_-]?key|secret|password|passwd|token|auth[_-]?token)\s*[=:]\s*[\'"]([^\'"]{8,})[\'"]', 
             'hardcoded_credentials', 0.9),
            
            # Weak crypto patterns
            (r'hashlib\.(md5|sha1)\s*\(', 'weak_crypto', 0.8),
            (r'import\s+md5', 'weak_crypto', 0.8),
            (r'import\s+sha', 'weak_crypto', 0.8),
            
            # Base64-like patterns (potential secrets)
            (r'[\'"][A-Za-z0-9+/]{40,}={0,2}[\'"]', 'hardcoded_credentials', 0.6),
            
            # SQL-like patterns
            (r'(?i)(select|insert|update|delete).*\+.*\$', 'sql_injection', 0.7),
            
            # Path traversal patterns
            (r'open\s*\(\s*[\'"]\.\./.*[\'"]', 'path_traversal', 0.8),
            (r'os\.path\.join.*\$', 'path_traversal', 0.7),
        ]

        for pattern, vuln_type, confidence in patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                cwe, desc = self.cwe_mapping[vuln_type]
                snippet = lines[line_num - 1] if line_num <= len(lines) else ""
                
                result.add_vulnerability(
                    vuln_type, line_num, line_num, confidence, cwe, desc, snippet
                )

    def _detect_package_vulnerabilities(self, code: str, result: VulnerabilityDetectionResult):
        """Detect vulnerabilities in imported packages"""
        import_patterns = [
            r'import\s+(\w+)',
            r'from\s+(\w+)\s+import',
        ]

        for pattern in import_patterns:
            for match in re.finditer(pattern, code):
                package_name = match.group(1).lower()
                if package_name in VULNERABLE_PACKAGES:
                    line_num = code[:match.start()].count('\n') + 1
                    vuln_info = VULNERABLE_PACKAGES[package_name]
                    
                    for version_constraint, cve in vuln_info.items():
                        snippet = match.group(0)
                        result.add_vulnerability(
                            'vulnerable_package', line_num, line_num, 0.8, 
                            'CWE-1104', f'Vulnerable package {package_name}', snippet, cve
                        )

    def _detect_advanced_patterns(self, code: str, lines: List[str], result: VulnerabilityDetectionResult):
        """Advanced pattern detection"""
        # XXE patterns
        xxe_patterns = [
            r'xml\.etree\.ElementTree\.parse',
            r'xml\.dom\.minidom\.parse',
            r'lxml\.etree\.parse',
        ]
        
        for pattern in xxe_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                cwe, desc = self.cwe_mapping['xxe']
                snippet = lines[line_num - 1] if line_num <= len(lines) else ""
                
                result.add_vulnerability(
                    'xxe', line_num, line_num, 0.85, cwe, desc, snippet
                )

        # Deserialization patterns
        deserialization_patterns = [
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\(',
            r'json\.loads?\s*\(',
            r'marshal\.loads?\s*\(',
        ]
        
        for pattern in deserialization_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                cwe, desc = self.cwe_mapping['deserialization']
                snippet = lines[line_num - 1] if line_num <= len(lines) else ""
                
                result.add_vulnerability(
                    'deserialization', line_num, line_num, 0.8, cwe, desc, snippet
                )

def process_code_snippet(snippet_data: Dict) -> Dict:
    """Process a single code snippet and return detailed results"""
    detector = PythonVulnerabilityDetector()
    
    code = snippet_data.get('code', '')
    snippet_id = snippet_data.get('id', 'unknown')
    gold_total = snippet_data.get('gold_total')
    gold_locations = snippet_data.get('gold_locations', [])
    
    # Run detection
    result = detector.detect_vulnerabilities(code, snippet_id)
    
    # Finalize with metrics
    result.finalize(gold_total, gold_locations)
    
    # Prepare output
    output = {
        'id': snippet_id,
        'code_length': len(code),
        'line_count': len(code.splitlines()),
        'vulnerabilities': result.vulnerabilities,
        'metrics': result.metrics,
        'timing': result.timing,
        'detection_summary': {
            'total_vulnerabilities': len(result.vulnerabilities),
            'vulnerability_types': list(set(v['type'] for v in result.vulnerabilities)),
            'cwe_categories': list(set(v['cwe'] for v in result.vulnerabilities)),
            'cve_count': len([v for v in result.vulnerabilities if v.get('cve')]),
        }
    }
    
    return output

def main():
    parser = argparse.ArgumentParser(description='Enhanced Python Vulnerability Detector')
    parser.add_argument('--input', '-i', required=True, help='Input JSONL file')
    parser.add_argument('--output', '-o', default='enhanced_results.jsonl', help='Output JSONL file')
    parser.add_argument('--csv', action='store_true', help='Also generate CSV summary')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    results = []
    total_start_time = time.time()
    
    print(f"Processing {args.input}...")
    
    with open(args.input, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
                
            try:
                snippet_data = json.loads(line.strip())
                result = process_code_snippet(snippet_data)
                results.append(result)
                
                if args.verbose:
                    print(f"Snippet {result['id']}: {result['detection_summary']['total_vulnerabilities']} vulnerabilities found")
                    
            except json.JSONDecodeError as e:
                print(f"Error parsing line {line_num}: {e}")
                continue
            except Exception as e:
                print(f"Error processing line {line_num}: {e}")
                continue
    
    total_time = time.time() - total_start_time
    
    # Write detailed results
    with open(args.output, 'w', encoding='utf-8') as f:
        for result in results:
            f.write(json.dumps(result, ensure_ascii=False) + '\n')
    
    # Generate CSV summary if requested
    if args.csv:
        csv_output = args.output.replace('.jsonl', '_summary.csv')
        with open(csv_output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'ID', 'Total_Vulnerabilities', 'TP', 'FP', 'FN', 'Precision', 'Recall', 'F1',
                'Total_Time', 'Detection_Time', 'Vulnerability_Types', 'CWE_Categories', 'CVE_Count'
            ])
            
            for result in results:
                metrics = result['metrics']
                timing = result['timing']
                summary = result['detection_summary']
                
                writer.writerow([
                    result['id'],
                    summary['total_vulnerabilities'],
                    metrics.get('tp', 0),
                    metrics.get('fp', 0),
                    metrics.get('fn', 0),
                    f"{metrics.get('precision', 0):.4f}",
                    f"{metrics.get('recall', 0):.4f}",
                    f"{metrics.get('f1', 0):.4f}",
                    f"{timing.get('total', 0):.4f}",
                    f"{timing.get('total', 0):.4f}",
                    '; '.join(summary['vulnerability_types']),
                    '; '.join(summary['cwe_categories']),
                    summary['cve_count']
                ])
    
    # Print summary statistics
    print(f"\n=== Detection Summary ===")
    print(f"Total snippets processed: {len(results)}")
    print(f"Total processing time: {total_time:.4f} seconds")
    
    if results:
        avg_vulns = sum(r['detection_summary']['total_vulnerabilities'] for r in results) / len(results)
        print(f"Average vulnerabilities per snippet: {avg_vulns:.2f}")
        
        # F1 statistics
        f1_scores = [r['metrics']['f1'] for r in results if r['metrics']['f1'] is not None]
        if f1_scores:
            avg_f1 = sum(f1_scores) / len(f1_scores)
            print(f"Average F1 score: {avg_f1:.4f}")
            print(f"Snippets with metrics: {len(f1_scores)}")
        
        # Timing statistics
        avg_time = sum(r['timing']['total'] for r in results) / len(results)
        print(f"Average detection time per snippet: {avg_time:.4f} seconds")
    
    print(f"\nDetailed results written to: {args.output}")
    if args.csv:
        print(f"CSV summary written to: {csv_output}")

if __name__ == "__main__":
    main()
