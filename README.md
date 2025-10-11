# Python Vulnerability Detection Engine

A comprehensive Python vulnerability detection system that analyzes code snippets for security vulnerabilities, maps them to CWE/CVE categories, and provides detailed metrics including timing and F1 scores.

## 🎯 Features

- **Multi-Type Detection**: SQL Injection, Command Injection, Code Injection, Hardcoded Credentials, Weak Cryptography, Deserialization vulnerabilities, Path Traversal, XXE, and more
- **CWE/CVE Mapping**: Automatic mapping to Common Weakness Enumeration (CWE) and Common Vulnerabilities and Exposures (CVE)
- **Timing Metrics**: Detailed timing measurements for each detection phase
- **F1 Score Calculation**: Comprehensive True Positive/False Positive/False Negative analysis
- **Real Dataset**: Sample dataset with real open-source code snippets containing known vulnerabilities

## 🚀 Quick Start

### 1. Generate Sample Dataset
```bash
python python_enginer/dataset_generator.py
```

### 2. Run Comprehensive Analysis
```bash
python python_enginer/run_detection.py --generate-dataset
```

### 3. Test with Smaller Dataset
```bash
python python_enginer/run_detection.py --test-mode
```

## 📊 Output Files

The system generates three main output files:

1. **`detailed_results.jsonl`** - Detailed per-snippet results with vulnerabilities, timing, and metrics
2. **`summary.csv`** - CSV summary for easy analysis in spreadsheet tools
3. **`vulnerability_report.json`** - Comprehensive report with distributions and statistics

## 🔍 Vulnerability Types Detected

| Vulnerability Type | CWE | Description |
|-------------------|-----|-------------|
| SQL Injection | CWE-89 | SQL queries with string concatenation or f-strings |
| Command Injection | CWE-78 | subprocess calls with shell=True or os.system |
| Code Injection | CWE-94 | eval() and exec() function usage |
| Hardcoded Credentials | CWE-798 | API keys, passwords, tokens in source code |
| Weak Cryptography | CWE-327 | MD5, SHA1, and other weak hash functions |
| Insecure Deserialization | CWE-502 | pickle.loads(), yaml.load() usage |
| Path Traversal | CWE-22 | File operations without proper path validation |
| XXE | CWE-611 | XML parsing without external entity protection |
| Insecure Requests | CWE-295 | HTTP requests without SSL verification |

## 📈 Metrics and Performance

### F1 Score Calculation
- **Location-based**: When `gold_locations` are provided, uses line overlap matching
- **Count-based**: When only `gold_total` is provided, uses conservative count matching
- **True Positives**: Correctly identified vulnerabilities
- **False Positives**: Incorrectly flagged code as vulnerable
- **False Negatives**: Missed actual vulnerabilities

### Timing Metrics
- **Total Detection Time**: End-to-end processing time per snippet
- **AST Detection Time**: Time spent on syntax tree analysis
- **Regex Detection Time**: Time spent on pattern matching
- **Package Detection Time**: Time spent on dependency analysis
- **Advanced Detection Time**: Time spent on complex pattern detection

## 🗂️ Dataset Format

Input JSONL format:
```json
{
  "id": "unique_identifier",
  "code": "python code string",
  "gold_total": 2,
  "gold_locations": [[10, 10], [15, 15]],
  "description": "Optional description"
}
```

## 🛠️ Usage Examples

### Basic Detection
```bash
python python_enginer/enhanced_detector.py --input dataset.jsonl --output results.jsonl --csv
```

### Comprehensive Analysis
```bash
python python_enginer/run_detection.py --input my_dataset.jsonl --output-dir my_results
```

### Generate and Test
```bash
python python_enginer/run_detection.py --generate-dataset --test-mode
```

## 📋 Sample Vulnerabilities in Dataset

The generated dataset includes real-world examples:

1. **SQL Injection**: Django/Flask apps with string concatenation in queries
2. **Command Injection**: subprocess calls with user input
3. **Hardcoded Credentials**: API keys and database passwords in source
4. **Weak Cryptography**: MD5/SHA1 usage for password hashing
5. **Insecure Deserialization**: pickle.loads() with untrusted data
6. **Path Traversal**: File operations without validation
7. **Complex Multi-Vulnerability**: Real Flask/Django apps with multiple issues

## 🔧 Extending the System

### Adding New Detectors
1. Add detection logic in `enhanced_detector.py`
2. Update CWE mapping in the `cwe_mapping` dictionary
3. Add CVE references in `CWE_CVE_MAPPING`

### Custom Vulnerability Patterns
```python
# Add to _detect_regex_vulnerabilities method
patterns.append((
    r'your_pattern_here',
    'vulnerability_type',
    confidence_score
))
```

## 📊 Sample Output

```json
{
  "id": "sql_injection_1",
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "line_start": 8,
      "line_end": 8,
      "confidence": 0.85,
      "cwe": "CWE-89",
      "cve": "CVE-2021-29425",
      "description": "SQL Injection",
      "code_snippet": "query = \"SELECT * FROM users WHERE id = \" + user_id",
      "detection_time": 0.0234
    }
  ],
  "metrics": {
    "detected_count": 1,
    "tp": 1,
    "fp": 0,
    "fn": 0,
    "precision": 1.0,
    "recall": 1.0,
    "f1": 1.0,
    "total_time": 0.0456
  }
}
```

## 🎯 Use Cases

- **Security Auditing**: Analyze codebases for security vulnerabilities
- **CI/CD Integration**: Automated security scanning in development pipelines
- **Research**: Study vulnerability patterns in open-source code
- **Training**: Generate datasets for ML-based vulnerability detection
- **Compliance**: Ensure code meets security standards

## 📚 References

- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVE Database](https://cve.mitre.org/)
- [Python AST Documentation](https://docs.python.org/3/library/ast.html)
