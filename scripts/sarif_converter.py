#!/usr/bin/env python3
"""
SARIF 2.1.0 Converter for NCIIPC Security Baseline
Converts various SAST tool outputs to standardized SARIF format
"""

import json
import xml.etree.ElementTree as ET
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse
from datetime import datetime
import yaml

class SARIFConverter:
    """Converts SAST tool outputs to SARIF 2.1.0 format"""
    
    def __init__(self, output_dir: str = "/app/sarif-output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # CWE mapping for different tools
        self.cwe_mappings = self._load_cwe_mappings()
        
        # Base SARIF structure
        self.base_sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": []
        }
    
    def _load_cwe_mappings(self) -> Dict[str, Dict[str, str]]:
        """Load CWE mappings for different SAST tools"""
        return {
            "bandit": {
                "B101": "CWE-259",  # Use of hard-coded password
                "B102": "CWE-259",  # exec_used
                "B103": "CWE-78",   # set_bad_file_permissions
                "B104": "CWE-259",  # hardcoded_bind_all_interfaces
                "B105": "CWE-259",  # hardcoded_password_string
                "B106": "CWE-259",  # hardcoded_password_funcarg
                "B107": "CWE-259",  # hardcoded_password_default
                "B108": "CWE-377",  # hardcoded_tmp_directory
                "B110": "CWE-311",  # try_except_pass
                "B201": "CWE-78",   # flask_debug_true
                "B301": "CWE-502",  # pickle
                "B302": "CWE-502",  # marshal
                "B303": "CWE-327",  # md5
                "B304": "CWE-327",  # des
                "B305": "CWE-327",  # cipher
                "B306": "CWE-327",  # mktemp_q
                "B307": "CWE-327",  # eval
                "B308": "CWE-327",  # mark_safe
                "B309": "CWE-327",  # httpsconnection
                "B310": "CWE-327",  # urllib_urlopen
                "B311": "CWE-259",  # random
                "B312": "CWE-327",  # telnetlib
                "B313": "CWE-327",  # xml_bad_cElementTree
                "B314": "CWE-327",  # xml_bad_ElementTree
                "B315": "CWE-327",  # xml_bad_expatreader
                "B316": "CWE-327",  # xml_bad_expatbuilder
                "B317": "CWE-327",  # xml_bad_sax
                "B318": "CWE-327",  # xml_bad_minidom
                "B319": "CWE-327",  # xml_bad_pulldom
                "B320": "CWE-327",  # xml_bad_etree
                "B321": "CWE-327",  # ftplib
                "B322": "CWE-327",  # input
                "B323": "CWE-327",  # unverified_context
                "B324": "CWE-327",  # hashlib_new_insecure_functions
                "B325": "CWE-327",  # tempnam
                "B501": "CWE-295",  # request_with_no_cert_validation
                "B502": "CWE-295",  # ssl_with_bad_version
                "B503": "CWE-295",  # ssl_with_bad_defaults
                "B504": "CWE-295",  # ssl_with_no_version
                "B505": "CWE-295",  # weak_cryptographic_key
                "B506": "CWE-295",  # yaml_load
                "B507": "CWE-295",  # ssh_no_host_key_verification
                "B601": "CWE-78",   # paramiko_calls
                "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
                "B603": "CWE-78",   # subprocess_without_shell_equals_true
                "B604": "CWE-78",   # any_other_function_with_shell_equals_true
                "B605": "CWE-78",   # start_process_with_a_shell
                "B606": "CWE-78",   # start_process_with_no_shell
                "B607": "CWE-78",   # start_process_with_partial_path
                "B608": "CWE-78",   # hardcoded_sql_expressions
                "B609": "CWE-78",   # linux_commands_wildcard_injection
                "B610": "CWE-78",   # django_extra_used
                "B611": "CWE-78",   # django_rawsql_used
                "B612": "CWE-78",   # log_injection
                "B613": "CWE-78",   # python_jwt_used
                "B614": "CWE-78",   # django_middleware_disabled
                "B615": "CWE-78",   # django_csrf_middleware_disabled
                "B701": "CWE-78",   # jinja2_autoescape_false
                "B702": "CWE-78",   # use_of_mako_templates
                "B703": "CWE-78",   # django_mark_safe
                "B704": "CWE-78",   # use_of_mako_templates
                "B801": "CWE-78",   # assert_used
            },
            "semgrep": {
                "owasp-a1": "CWE-89",   # SQL Injection
                "owasp-a2": "CWE-79",   # Cross-Site Scripting
                "owasp-a3": "CWE-259",  # Sensitive Data Exposure
                "owasp-a4": "CWE-22",   # XML External Entities
                "owasp-a5": "CWE-434",  # Broken Access Control
                "owasp-a6": "CWE-78",   # Security Misconfiguration
                "owasp-a7": "CWE-327",  # Cross-Site Scripting
                "owasp-a8": "CWE-311",  # Insecure Deserialization
                "owasp-a9": "CWE-327",  # Using Components with Known Vulnerabilities
                "owasp-a10": "CWE-319", # Insufficient Logging & Monitoring
            },
            "cppcheck": {
                "bufferAccessOutOfBounds": "CWE-119",
                "arrayIndexOutOfBounds": "CWE-119",
                "nullPointer": "CWE-476",
                "uninitializedVariable": "CWE-457",
                "memoryLeak": "CWE-401",
                "resourceLeak": "CWE-404",
                "doubleFree": "CWE-415",
                "useAfterFree": "CWE-416",
                "insecureRandom": "CWE-330",
                "insecureTempFile": "CWE-377",
            },
            "spotbugs": {
                "SQL_INJECTION_JPA": "CWE-89",
                "SQL_INJECTION_JDO": "CWE-89",
                "SQL_INJECTION_HIBERNATE": "CWE-89",
                "XSS_REQUEST_PARAMETER_TO_SEND_ERROR": "CWE-79",
                "XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER": "CWE-79",
                "XSS_REQUEST_PARAMETER_TO_JSP_WRITER": "CWE-79",
                "HARD_CODE_PASSWORD": "CWE-259",
                "HARD_CODE_PASSWORD_KEYSTORE": "CWE-259",
                "DES_USAGE": "CWE-327",
                "MD5_USAGE": "CWE-327",
                "SHA1_USAGE": "CWE-327",
                "RSA_NO_PADDING": "CWE-327",
                "STATIC_IV": "CWE-329",
                "ECB_MODE": "CWE-329",
                "PADDING_ORACLE": "CWE-329",
                "PREDICTABLE_RANDOM": "CWE-330",
                "PATH_TRAVERSAL_IN": "CWE-22",
                "PATH_TRAVERSAL_OUT": "CWE-22",
                "COMMAND_INJECTION": "CWE-78",
                "XXE_XMLSTREAMREADER": "CWE-611",
                "XXE_XMLREADER": "CWE-611",
                "XXE_DOCUMENT": "CWE-611",
                "XXE_XPATH": "CWE-611",
                "XXE_DOCUMENTBUILDER": "CWE-611",
            }
        }
    
    def convert_bandit_output(self, file_path: str) -> Dict[str, Any]:
        """Convert Bandit JSON output to SARIF format"""
        with open(file_path, 'r') as f:
            bandit_data = json.load(f)
        
        results = []
        rules = {}
        
        for result in bandit_data.get('results', []):
            test_id = result.get('test_id', '')
            cwe = self.cwe_mappings.get('bandit', {}).get(test_id, 'CWE-unknown')
            
            # Create rule
            if test_id not in rules:
                rules[test_id] = {
                    "id": test_id,
                    "name": result.get('test_name', ''),
                    "shortDescription": {
                        "text": result.get('issue_confidence', '') + " - " + result.get('issue_severity', '')
                    },
                    "help": {
                        "text": result.get('issue_text', '')
                    },
                    "properties": {
                        "tags": ["security", "python"],
                        "precision": "high"
                    }
                }
            
            # Create result
            sarif_result = {
                "ruleId": test_id,
                "level": "error" if result.get('issue_severity') == 'HIGH' else "warning",
                "message": {
                    "text": result.get('issue_text', '')
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result.get('filename', '').replace('\\', '/')
                        },
                        "region": {
                            "startLine": result.get('line_number', 1),
                            "startColumn": 1,
                            "endLine": result.get('line_number', 1),
                            "endColumn": 1
                        }
                    }
                }],
                "properties": {
                    "cwe": cwe,
                    "confidence": result.get('issue_confidence', ''),
                    "severity": result.get('issue_severity', '')
                }
            }
            results.append(sarif_result)
        
        return {
            "tool": {
                "driver": {
                    "name": "Bandit",
                    "version": "1.7.5",
                    "informationUri": "https://bandit.readthedocs.io/",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }
    
    def convert_semgrep_output(self, file_path: str) -> Dict[str, Any]:
        """Convert Semgrep JSON output to SARIF format"""
        with open(file_path, 'r') as f:
            semgrep_data = json.load(f)
        
        results = []
        rules = {}
        
        for result in semgrep_data.get('results', []):
            rule_id = result.get('check_id', '')
            
            # Create rule
            if rule_id not in rules:
                cwe = self.cwe_mappings.get('semgrep', {}).get(rule_id, 'CWE-unknown')
                rules[rule_id] = {
                    "id": rule_id,
                    "name": result.get('check_id', ''),
                    "shortDescription": {
                        "text": result.get('message', '')
                    },
                    "help": {
                        "text": result.get('message', '')
                    },
                    "properties": {
                        "tags": ["security"],
                        "precision": "high"
                    }
                }
            
            # Create result
            sarif_result = {
                "ruleId": rule_id,
                "level": "error" if result.get('extra', {}).get('severity') == 'ERROR' else "warning",
                "message": {
                    "text": result.get('extra', {}).get('message', '')
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result.get('path', '').replace('\\', '/')
                        },
                        "region": {
                            "startLine": result.get('start', {}).get('line', 1),
                            "startColumn": result.get('start', {}).get('col', 1),
                            "endLine": result.get('end', {}).get('line', 1),
                            "endColumn": result.get('end', {}).get('col', 1)
                        }
                    }
                }],
                "properties": {
                    "cwe": self.cwe_mappings.get('semgrep', {}).get(rule_id, 'CWE-unknown'),
                    "severity": result.get('extra', {}).get('severity', ''),
                    "confidence": result.get('extra', {}).get('confidence', '')
                }
            }
            results.append(sarif_result)
        
        return {
            "tool": {
                "driver": {
                    "name": "Semgrep",
                    "version": "1.45.0",
                    "informationUri": "https://semgrep.dev/",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }
    
    def convert_cppcheck_output(self, file_path: str) -> Dict[str, Any]:
        """Convert Cppcheck XML output to SARIF format"""
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        results = []
        rules = {}
        
        for error in root.findall('.//error'):
            error_id = error.get('id', '')
            severity = error.get('severity', '')
            
            # Create rule
            if error_id not in rules:
                cwe = self.cwe_mappings.get('cppcheck', {}).get(error_id, 'CWE-unknown')
                rules[error_id] = {
                    "id": error_id,
                    "name": error.get('msg', ''),
                    "shortDescription": {
                        "text": error.get('msg', '')
                    },
                    "help": {
                        "text": error.get('verbose', '')
                    },
                    "properties": {
                        "tags": ["security", "c++"],
                        "precision": "high"
                    }
                }
            
            # Create result
            for location in error.findall('location'):
                sarif_result = {
                    "ruleId": error_id,
                    "level": "error" if severity == 'error' else "warning",
                    "message": {
                        "text": error.get('msg', '')
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": location.get('file', '').replace('\\', '/')
                            },
                            "region": {
                                "startLine": int(location.get('line', 1)),
                                "startColumn": 1,
                                "endLine": int(location.get('line', 1)),
                                "endColumn": 1
                            }
                        }
                    }],
                    "properties": {
                        "cwe": self.cwe_mappings.get('cppcheck', {}).get(error_id, 'CWE-unknown'),
                        "severity": severity,
                        "confidence": "high"
                    }
                }
                results.append(sarif_result)
        
        return {
            "tool": {
                "driver": {
                    "name": "Cppcheck",
                    "version": "2.10",
                    "informationUri": "http://cppcheck.sourceforge.net/",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }
    
    def convert_spotbugs_output(self, file_path: str) -> Dict[str, Any]:
        """Convert SpotBugs XML output to SARIF format"""
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        results = []
        rules = {}
        
        for bug in root.findall('.//BugInstance'):
            bug_type = bug.get('type', '')
            priority = bug.get('priority', '')
            
            # Create rule
            if bug_type not in rules:
                cwe = self.cwe_mappings.get('spotbugs', {}).get(bug_type, 'CWE-unknown')
                rules[bug_type] = {
                    "id": bug_type,
                    "name": bug.find('ShortMessage').text if bug.find('ShortMessage') is not None else bug_type,
                    "shortDescription": {
                        "text": bug.find('ShortMessage').text if bug.find('ShortMessage') is not None else ''
                    },
                    "help": {
                        "text": bug.find('LongMessage').text if bug.find('LongMessage') is not None else ''
                    },
                    "properties": {
                        "tags": ["security", "java"],
                        "precision": "high"
                    }
                }
            
            # Create result
            for source_line in bug.findall('.//SourceLine'):
                sarif_result = {
                    "ruleId": bug_type,
                    "level": "error" if priority == 'HIGH' else "warning",
                    "message": {
                        "text": bug.find('ShortMessage').text if bug.find('ShortMessage') is not None else ''
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": source_line.get('sourcepath', '').replace('\\', '/')
                            },
                            "region": {
                                "startLine": int(source_line.get('start', 1)),
                                "startColumn": 1,
                                "endLine": int(source_line.get('end', 1)),
                                "endColumn": 1
                            }
                        }
                    }],
                    "properties": {
                        "cwe": self.cwe_mappings.get('spotbugs', {}).get(bug_type, 'CWE-unknown'),
                        "priority": priority,
                        "confidence": "high"
                    }
                }
                results.append(sarif_result)
        
        return {
            "tool": {
                "driver": {
                    "name": "SpotBugs",
                    "version": "4.8.0",
                    "informationUri": "https://spotbugs.github.io/",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }
    
    def create_unified_sarif(self, tool_outputs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create unified SARIF file from multiple tool outputs"""
        unified_sarif = self.base_sarif.copy()
        
        for tool_output in tool_outputs:
            run = {
                "tool": tool_output["tool"],
                "results": tool_output["results"],
                "invocations": [{
                    "executionSuccessful": True,
                    "exitCode": 0
                }],
                "properties": {
                    "analysisTimestamp": datetime.now().isoformat(),
                    "toolVersion": tool_output["tool"]["driver"]["version"]
                }
            }
            unified_sarif["runs"].append(run)
        
        return unified_sarif
    
    def save_sarif(self, sarif_data: Dict[str, Any], filename: str = "unified-sarif.json") -> str:
        """Save SARIF data to file"""
        output_path = self.output_dir / filename
        
        with open(output_path, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        
        return str(output_path)

def main():
    parser = argparse.ArgumentParser(description="Convert SAST tool outputs to SARIF 2.1.0")
    parser.add_argument("--bandit", help="Path to Bandit JSON output")
    parser.add_argument("--semgrep", help="Path to Semgrep JSON output")
    parser.add_argument("--cppcheck", help="Path to Cppcheck XML output")
    parser.add_argument("--spotbugs", help="Path to SpotBugs XML output")
    parser.add_argument("--output", default="unified-sarif.json", help="Output SARIF filename")
    
    args = parser.parse_args()
    
    converter = SARIFConverter()
    tool_outputs = []
    
    # Convert each tool output if provided
    if args.bandit and os.path.exists(args.bandit):
        print(f"Converting Bandit output: {args.bandit}")
        tool_outputs.append(converter.convert_bandit_output(args.bandit))
    
    if args.semgrep and os.path.exists(args.semgrep):
        print(f"Converting Semgrep output: {args.semgrep}")
        tool_outputs.append(converter.convert_semgrep_output(args.semgrep))
    
    if args.cppcheck and os.path.exists(args.cppcheck):
        print(f"Converting Cppcheck output: {args.cppcheck}")
        tool_outputs.append(converter.convert_cppcheck_output(args.cppcheck))
    
    if args.spotbugs and os.path.exists(args.spotbugs):
        print(f"Converting SpotBugs output: {args.spotbugs}")
        tool_outputs.append(converter.convert_spotbugs_output(args.spotbugs))
    
    if not tool_outputs:
        print("No valid tool outputs provided!")
        return 1
    
    # Create unified SARIF
    unified_sarif = converter.create_unified_sarif(tool_outputs)
    output_path = converter.save_sarif(unified_sarif, args.output)
    
    print(f"Unified SARIF file created: {output_path}")
    print(f"Total runs: {len(unified_sarif['runs'])}")
    
    total_results = sum(len(run['results']) for run in unified_sarif['runs'])
    print(f"Total findings: {total_results}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
