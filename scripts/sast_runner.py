#!/usr/bin/env python3
"""
SAST Baseline Runner for NCIIPC Security Analysis
Executes all configured SAST tools and normalizes output to SARIF
"""

import os
import sys
import subprocess
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any
import logging
from datetime import datetime

# Import our SARIF converter
from sarif_converter import SARIFConverter

class SASTRunner:
    """Main SAST execution and orchestration class"""
    
    def __init__(self, source_dir: str = "/app/source-code", results_dir: str = "/app/results"):
        self.source_dir = Path(source_dir)
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(exist_ok=True)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/app/results/sast-run.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Tool configurations
        self.tool_configs = self._load_tool_configs()
        
    def _load_tool_configs(self) -> Dict[str, Dict[str, Any]]:
        """Load tool configurations"""
        return {
            "semgrep": {
                "command": "semgrep",
                "args": [
                    "--config=auto",
                    "--config=/app/rules/semgrep-custom.yml",
                    "--json",
                    "--output={output_file}",
                    "{source_dir}"
                ],
                "output_format": "json",
                "enabled": True
            },
            "bandit": {
                "command": "bandit",
                "args": [
                    "-r",
                    "-f", "json",
                    "-o", "{output_file}",
                    "{source_dir}"
                ],
                "output_format": "json",
                "enabled": True
            },
            "cppcheck": {
                "command": "cppcheck",
                "args": [
                    "--enable=all",
                    "--xml",
                    "--xml-version=2",
                    "--output-file={output_file}",
                    "{source_dir}"
                ],
                "output_format": "xml",
                "enabled": True
            },
            "spotbugs": {
                "command": "/opt/spotbugs/bin/spotbugs",
                "args": [
                    "-textui",
                    "-xml:output={output_file}",
                    "-auxclasspath", "/app/lib",
                    "{source_dir}"
                ],
                "output_format": "xml",
                "enabled": True
            },
            "flawfinder": {
                "command": "flawfinder",
                "args": [
                    "--csv",
                    "--dataonly",
                    "{source_dir}"
                ],
                "output_format": "csv",
                "enabled": True
            },
            "phpstan": {
                "command": "phpstan",
                "args": [
                    "analyse",
                    "--level=max",
                    "--error-format=json",
                    "--no-progress",
                    "{source_dir}"
                ],
                "output_format": "json",
                "enabled": True
            }
        }
    
    def run_tool(self, tool_name: str, source_path: str) -> Dict[str, Any]:
        """Run a specific SAST tool"""
        config = self.tool_configs.get(tool_name)
        if not config or not config.get("enabled"):
            self.logger.warning(f"Tool {tool_name} is not enabled or configured")
            return {"success": False, "error": "Tool not enabled"}
        
        # Prepare output file path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.results_dir / f"{tool_name}_{timestamp}.{config['output_format']}"
        
        # Build command
        args = []
        for arg in config["args"]:
            if "{output_file}" in arg:
                args.append(arg.format(output_file=str(output_file)))
            elif "{source_dir}" in arg:
                args.append(arg.format(source_dir=source_path))
            else:
                args.append(arg)
        
        command = [config["command"]] + args
        
        self.logger.info(f"Running {tool_name}: {' '.join(command)}")
        
        try:
            # Run the tool
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minute timeout
                cwd=str(self.source_dir)
            )
            
            if result.returncode == 0 or result.returncode == 1:  # Many tools return 1 for findings
                self.logger.info(f"{tool_name} completed successfully")
                return {
                    "success": True,
                    "output_file": str(output_file),
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode
                }
            else:
                self.logger.error(f"{tool_name} failed with return code {result.returncode}")
                self.logger.error(f"STDERR: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr,
                    "return_code": result.returncode
                }
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"{tool_name} timed out after 30 minutes")
            return {"success": False, "error": "Tool execution timed out"}
        except Exception as e:
            self.logger.error(f"Error running {tool_name}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def run_all_tools(self, source_path: str = None) -> Dict[str, Any]:
        """Run all enabled SAST tools"""
        if source_path is None:
            source_path = str(self.source_dir)
        
        if not os.path.exists(source_path):
            self.logger.error(f"Source directory does not exist: {source_path}")
            return {"success": False, "error": "Source directory not found"}
        
        self.logger.info(f"Starting SAST analysis on: {source_path}")
        results = {}
        
        for tool_name in self.tool_configs.keys():
            self.logger.info(f"Running {tool_name}...")
            result = self.run_tool(tool_name, source_path)
            results[tool_name] = result
            
            if result["success"]:
                self.logger.info(f"✓ {tool_name} completed")
            else:
                self.logger.warning(f"✗ {tool_name} failed: {result.get('error', 'Unknown error')}")
        
        return results
    
    def generate_unified_sarif(self, tool_results: Dict[str, Any]) -> str:
        """Generate unified SARIF from tool results"""
        converter = SARIFConverter()
        
        # Collect output files from successful runs
        sarif_args = {}
        
        for tool_name, result in tool_results.items():
            if result.get("success") and "output_file" in result:
                if tool_name == "bandit":
                    sarif_args["--bandit"] = result["output_file"]
                elif tool_name == "semgrep":
                    sarif_args["--semgrep"] = result["output_file"]
                elif tool_name == "cppcheck":
                    sarif_args["--cppcheck"] = result["output_file"]
                elif tool_name == "spotbugs":
                    sarif_args["--spotbugs"] = result["output_file"]
        
        if not sarif_args:
            self.logger.warning("No successful tool outputs to convert to SARIF")
            return None
        
        # Generate unified SARIF
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"unified-sarif-{timestamp}.json"
        
        # Create SARIF converter command
        cmd_args = []
        for arg, value in sarif_args.items():
            cmd_args.extend([arg, value])
        cmd_args.extend(["--output", output_file])
        
        try:
            # Import and run converter directly
            import sys
            sys.argv = ["sarif_converter.py"] + cmd_args
            from sarif_converter import main as converter_main
            
            converter_main()
            
            sarif_path = f"/app/sarif-output/{output_file}"
            self.logger.info(f"Unified SARIF created: {sarif_path}")
            return sarif_path
            
        except Exception as e:
            self.logger.error(f"Error creating unified SARIF: {str(e)}")
            return None
    
    def run_security_baseline(self, source_path: str = None) -> Dict[str, Any]:
        """Complete security baseline analysis"""
        self.logger.info("=" * 60)
        self.logger.info("NCIIPC Security Baseline Analysis")
        self.logger.info("=" * 60)
        
        # Run all SAST tools
        tool_results = self.run_all_tools(source_path)
        
        # Generate unified SARIF
        sarif_path = self.generate_unified_sarif(tool_results)
        
        # Summary
        successful_tools = [name for name, result in tool_results.items() if result.get("success")]
        failed_tools = [name for name, result in tool_results.items() if not result.get("success")]
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "source_path": source_path or str(self.source_dir),
            "successful_tools": successful_tools,
            "failed_tools": failed_tools,
            "sarif_output": sarif_path,
            "tool_results": tool_results
        }
        
        # Save summary
        summary_path = self.results_dir / f"analysis-summary-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info("=" * 60)
        self.logger.info("Analysis Summary:")
        self.logger.info(f"Successful tools: {len(successful_tools)} - {', '.join(successful_tools)}")
        self.logger.info(f"Failed tools: {len(failed_tools)} - {', '.join(failed_tools)}")
        self.logger.info(f"SARIF output: {sarif_path}")
        self.logger.info(f"Summary saved: {summary_path}")
        self.logger.info("=" * 60)
        
        return summary

def main():
    parser = argparse.ArgumentParser(description="Run SAST security baseline analysis")
    parser.add_argument("--source", default="/app/source-code", help="Source code directory to analyze")
    parser.add_argument("--tool", help="Run specific tool only (semgrep, bandit, cppcheck, spotbugs, flawfinder, phpstan)")
    parser.add_argument("--list-tools", action="store_true", help="List available tools")
    
    args = parser.parse_args()
    
    runner = SASTRunner()
    
    if args.list_tools:
        print("Available SAST tools:")
        for tool_name, config in runner.tool_configs.items():
            status = "enabled" if config.get("enabled") else "disabled"
            print(f"  {tool_name}: {status}")
        return 0
    
    if args.tool:
        if args.tool not in runner.tool_configs:
            print(f"Unknown tool: {args.tool}")
            return 1
        
        print(f"Running {args.tool} on {args.source}")
        result = runner.run_tool(args.tool, args.source)
        
        if result["success"]:
            print(f"✓ {args.tool} completed successfully")
            print(f"Output: {result.get('output_file', 'N/A')}")
        else:
            print(f"✗ {args.tool} failed: {result.get('error', 'Unknown error')}")
            return 1
    else:
        # Run complete baseline
        summary = runner.run_security_baseline(args.source)
        
        if summary["failed_tools"]:
            print(f"\nWarning: {len(summary['failed_tools'])} tools failed")
            return 1
        else:
            print("\n✓ All tools completed successfully")
            return 0

if __name__ == "__main__":
    sys.exit(main())
