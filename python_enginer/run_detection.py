#!/usr/bin/env python3
"""
Comprehensive Python Vulnerability Detection Runner
Integrates dataset generation, detection, and analysis
"""

import json
import time
import argparse
import os
import sys
from pathlib import Path
import csv
from typing import List, Dict, Any

# Import our modules
from enhanced_detector import PythonVulnerabilityDetector, process_code_snippet
from dataset_generator import create_sample_dataset

def run_comprehensive_analysis(input_file: str, output_dir: str = "results"):
    """Run comprehensive vulnerability analysis"""
    
    # Create output directory
    Path(output_dir).mkdir(exist_ok=True)
    
    print("Starting Comprehensive Python Vulnerability Detection")
    print("=" * 60)
    
    # Read input data
    snippets = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                snippets.append(json.loads(line.strip()))
    
    print(f"Processing {len(snippets)} code snippets...")
    
    # Process each snippet
    results = []
    total_start_time = time.time()
    
    for i, snippet in enumerate(snippets, 1):
        print(f"Processing snippet {i}/{len(snippets)}: {snippet.get('id', 'unknown')}")
        
        try:
            result = process_code_snippet(snippet)
            results.append(result)
            
            # Print quick summary
            vuln_count = result['detection_summary']['total_vulnerabilities']
            if vuln_count > 0:
                vuln_types = ', '.join(result['detection_summary']['vulnerability_types'])
                print(f"  Found {vuln_count} vulnerabilities: {vuln_types}")
            else:
                print(f"  No vulnerabilities detected")
                
        except Exception as e:
            print(f"  Error processing snippet: {e}")
            continue
    
    total_time = time.time() - total_start_time
    
    # Save detailed results
    detailed_output = os.path.join(output_dir, "detailed_results.jsonl")
    with open(detailed_output, 'w', encoding='utf-8') as f:
        for result in results:
            f.write(json.dumps(result, ensure_ascii=False) + '\n')
    
    # Generate summary CSV
    csv_output = os.path.join(output_dir, "summary.csv")
    generate_summary_csv(results, csv_output)
    
    # Generate vulnerability report
    report_output = os.path.join(output_dir, "vulnerability_report.json")
    generate_vulnerability_report(results, report_output)
    
    # Print comprehensive summary
    print_comprehensive_summary(results, total_time)
    
    return results

def generate_summary_csv(results: List[Dict], output_file: str):
    """Generate CSV summary of results"""
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow([
            'ID', 'Code_Length', 'Line_Count', 'Total_Vulnerabilities',
            'TP', 'FP', 'FN', 'Precision', 'Recall', 'F1_Score',
            'Total_Time', 'Detection_Time', 'Vulnerability_Types',
            'CWE_Categories', 'CVE_Count', 'Top_Vulnerability', 'Confidence_Avg'
        ])
        
        # Data rows
        for result in results:
            metrics = result['metrics']
            timing = result['timing']
            summary = result['detection_summary']
            vulnerabilities = result['vulnerabilities']
            
            # Calculate average confidence
            avg_confidence = 0
            if vulnerabilities:
                avg_confidence = sum(v['confidence'] for v in vulnerabilities) / len(vulnerabilities)
            
            # Get top vulnerability type
            top_vuln = "None"
            if vulnerabilities:
                vuln_types = [v['type'] for v in vulnerabilities]
                top_vuln = max(set(vuln_types), key=vuln_types.count)
            
            writer.writerow([
                result['id'],
                result['code_length'],
                result['line_count'],
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
                summary['cve_count'],
                top_vuln,
                f"{avg_confidence:.3f}"
            ])

def generate_vulnerability_report(results: List[Dict], output_file: str):
    """Generate detailed vulnerability report"""
    
    report = {
        "summary": {
            "total_snippets": len(results),
            "total_vulnerabilities": sum(r['detection_summary']['total_vulnerabilities'] for r in results),
            "snippets_with_vulnerabilities": len([r for r in results if r['detection_summary']['total_vulnerabilities'] > 0])
        },
        "vulnerability_distribution": {},
        "cwe_distribution": {},
        "cve_distribution": {},
        "timing_statistics": {},
        "performance_metrics": {}
    }
    
    # Vulnerability type distribution
    vuln_types = {}
    cwe_counts = {}
    cve_counts = {}
    all_times = []
    f1_scores = []
    
    for result in results:
        # Vulnerability types
        for vuln_type in result['detection_summary']['vulnerability_types']:
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # CWE distribution
        for cwe in result['detection_summary']['cwe_categories']:
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        # CVE distribution
        for vuln in result['vulnerabilities']:
            if vuln.get('cve'):
                cve_counts[vuln['cve']] = cve_counts.get(vuln['cve'], 0) + 1
        
        # Timing
        all_times.append(result['timing']['total'])
        
        # F1 scores
        if result['metrics']['f1'] is not None:
            f1_scores.append(result['metrics']['f1'])
    
    report["vulnerability_distribution"] = dict(sorted(vuln_types.items(), key=lambda x: x[1], reverse=True))
    report["cwe_distribution"] = dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True))
    report["cve_distribution"] = dict(sorted(cve_counts.items(), key=lambda x: x[1], reverse=True))
    
    # Timing statistics
    if all_times:
        report["timing_statistics"] = {
            "average_time": sum(all_times) / len(all_times),
            "min_time": min(all_times),
            "max_time": max(all_times),
            "total_time": sum(all_times)
        }
    
    # Performance metrics
    if f1_scores:
        report["performance_metrics"] = {
            "average_f1": sum(f1_scores) / len(f1_scores),
            "min_f1": min(f1_scores),
            "max_f1": max(f1_scores),
            "snippets_with_metrics": len(f1_scores)
        }
    
    # Save report
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

def print_comprehensive_summary(results: List[Dict], total_time: float):
    """Print comprehensive summary statistics"""
    
    print("\n" + "=" * 60)
    print("COMPREHENSIVE ANALYSIS SUMMARY")
    print("=" * 60)
    
    # Basic statistics
    total_snippets = len(results)
    total_vulns = sum(r['detection_summary']['total_vulnerabilities'] for r in results)
    snippets_with_vulns = len([r for r in results if r['detection_summary']['total_vulnerabilities'] > 0])
    
    print(f"Basic Statistics:")
    print(f"   Total snippets processed: {total_snippets}")
    print(f"   Total vulnerabilities found: {total_vulns}")
    print(f"   Snippets with vulnerabilities: {snippets_with_vulns}")
    print(f"   Average vulnerabilities per snippet: {total_vulns/total_snippets:.2f}")
    
    # Vulnerability type distribution
    vuln_types = {}
    for result in results:
        for vuln_type in result['detection_summary']['vulnerability_types']:
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    if vuln_types:
        print(f"\nVulnerability Type Distribution:")
        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            print(f"   {vuln_type}: {count}")
    
    # CWE distribution
    cwe_counts = {}
    for result in results:
        for cwe in result['detection_summary']['cwe_categories']:
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    
    if cwe_counts:
        print(f"\nCWE Category Distribution:")
        for cwe, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"   {cwe}: {count}")
    
    # CVE distribution
    cve_counts = {}
    for result in results:
        for vuln in result['vulnerabilities']:
            if vuln.get('cve'):
                cve_counts[vuln['cve']] = cve_counts.get(vuln['cve'], 0) + 1
    
    if cve_counts:
        print(f"\nCVE Distribution:")
        for cve, count in sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"   {cve}: {count}")
    
    # Performance metrics
    f1_scores = [r['metrics']['f1'] for r in results if r['metrics']['f1'] is not None]
    if f1_scores:
        print(f"\nPerformance Metrics:")
        print(f"   Average F1 Score: {sum(f1_scores)/len(f1_scores):.4f}")
        print(f"   Min F1 Score: {min(f1_scores):.4f}")
        print(f"   Max F1 Score: {max(f1_scores):.4f}")
        print(f"   Snippets with metrics: {len(f1_scores)}")
    
    # Timing statistics
    all_times = [r['timing']['total'] for r in results]
    if all_times:
        print(f"\nTiming Statistics:")
        print(f"   Total processing time: {total_time:.4f} seconds")
        print(f"   Average time per snippet: {sum(all_times)/len(all_times):.4f} seconds")
        print(f"   Min detection time: {min(all_times):.4f} seconds")
        print(f"   Max detection time: {max(all_times):.4f} seconds")
    
    print(f"\nOutput Files Generated:")
    print(f"   - detailed_results.jsonl (Detailed per-snippet results)")
    print(f"   - summary.csv (CSV summary)")
    print(f"   - vulnerability_report.json (Comprehensive report)")
    
    print("\nAnalysis completed successfully!")

def main():
    parser = argparse.ArgumentParser(description='Comprehensive Python Vulnerability Detection')
    parser.add_argument('--input', '-i', help='Input JSONL file (if not provided, will generate sample dataset)')
    parser.add_argument('--output-dir', '-o', default='results', help='Output directory for results')
    parser.add_argument('--generate-dataset', action='store_true', help='Generate sample dataset')
    parser.add_argument('--test-mode', action='store_true', help='Run in test mode with smaller dataset')
    
    args = parser.parse_args()
    
    # Generate dataset if requested or no input provided
    if args.generate_dataset or not args.input:
        print("Generating sample vulnerability dataset...")
        create_sample_dataset()
        
        if args.test_mode:
            input_file = "python_enginer/test_dataset.jsonl"
        else:
            input_file = "python_enginer/sample_vulnerability_dataset.jsonl"
    else:
        input_file = args.input
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Input file not found: {input_file}")
        print("Use --generate-dataset to create a sample dataset")
        return 1
    
    # Run analysis
    try:
        results = run_comprehensive_analysis(input_file, args.output_dir)
        return 0
    except Exception as e:
        print(f"Error during analysis: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
