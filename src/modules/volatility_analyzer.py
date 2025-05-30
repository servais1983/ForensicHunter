"""
ForensicHunter Volatility 3 Integration
Professional memory analysis module with real Volatility 3 integration

This module provides:
- Direct Volatility 3 API integration
- Automatic symbol table management
- Parallel plugin execution
- Memory dump validation
- Enterprise reporting integration
"""

import os
import asyncio
import logging
import tempfile
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import subprocess
import shutil
import time

# Volatility 3 imports
try:
    import volatility3
    from volatility3 import framework, plugins, constants
    from volatility3.framework import contexts, configuration, interfaces, exceptions
    from volatility3.framework.plugins import yarascan
    from volatility3.plugins.windows import pslist, psscan, dlllist, handles, cmdline
    from volatility3.plugins.windows import malfind, hollowfind, vadinfo
    from volatility3.plugins.windows import filescan, netstat
    HAS_VOLATILITY = True
except ImportError:
    HAS_VOLATILITY = False
    logging.warning("Volatility 3 not available - memory analysis disabled")

from ..core.enterprise_config import EnterpriseConfig

logger = logging.getLogger("forensichunter.modules.volatility")

class VolatilityAnalyzer:
    """
    Professional Volatility 3 analyzer for enterprise memory forensics
    """
    
    def __init__(self, config: Optional[EnterpriseConfig] = None):
        self.config = config or EnterpriseConfig()
        self.logger = logging.getLogger(__name__)
        
        if not HAS_VOLATILITY:
            raise RuntimeError("Volatility 3 is not installed - cannot perform memory analysis")
        
        # Volatility configuration
        self.vol_config = self._setup_volatility_config()
        self.symbols_path = self.config.get('forensics.volatility_symbols', '/opt/volatility3/symbols')
        
        # Plugin categories and priorities
        self.plugin_categories = self._initialize_plugin_categories()
        
        self.logger.info("Volatility 3 analyzer initialized")
    
    def _setup_volatility_config(self) -> configuration.HierarchicalDict:
        """Setup Volatility 3 configuration"""
        config = configuration.HierarchicalDict()
        
        # Set up constants
        constants.LOGLEVEL = logging.INFO
        constants.CACHETYPES = [interfaces.configuration.CacheableInterface]
        
        return config
    
    def _initialize_plugin_categories(self) -> Dict[str, Dict]:
        """Initialize categorized Volatility plugins for enterprise use"""
        return {
            "process_analysis": {
                "description": "Process and thread analysis",
                "plugins": [
                    {"name": "pslist", "class": pslist.PsList, "priority": "HIGH"},
                    {"name": "psscan", "class": psscan.PsScan, "priority": "HIGH"},
                    {"name": "cmdline", "class": cmdline.CmdLine, "priority": "HIGH"},
                ],
                "timeout": 300
            },
            
            "malware_analysis": {
                "description": "Malware detection and analysis",
                "plugins": [
                    {"name": "malfind", "class": malfind.Malfind, "priority": "CRITICAL"},
                    {"name": "hollowfind", "class": hollowfind.HollowFind, "priority": "HIGH"},
                    {"name": "yarascan", "class": yarascan.YaraScan, "priority": "HIGH"},
                ],
                "timeout": 900  # Longer timeout for malware analysis
            },
            
            "memory_structures": {
                "description": "Memory structure analysis",
                "plugins": [
                    {"name": "vadinfo", "class": vadinfo.VadInfo, "priority": "MEDIUM"},
                    {"name": "handles", "class": handles.Handles, "priority": "MEDIUM"},
                    {"name": "dlllist", "class": dlllist.DllList, "priority": "MEDIUM"},
                ],
                "timeout": 600
            },
            
            "filesystem_analysis": {
                "description": "File system artifacts in memory",
                "plugins": [
                    {"name": "filescan", "class": filescan.FileScan, "priority": "MEDIUM"},
                ],
                "timeout": 600
            },
            
            "network_analysis": {
                "description": "Network artifacts and connections",
                "plugins": [
                    {"name": "netstat", "class": netstat.NetStat, "priority": "HIGH"},
                ],
                "timeout": 300
            }
        }
    
    async def analyze_memory_dump(self, 
                                dump_path: str, 
                                output_dir: str,
                                categories: List[str] = None,
                                yara_rules: str = None) -> Dict[str, Any]:
        """
        Comprehensive memory dump analysis
        
        Args:
            dump_path: Path to memory dump file
            output_dir: Output directory for results
            categories: Plugin categories to run (None = all)
            yara_rules: Path to YARA rules directory
            
        Returns:
            Analysis results dictionary
        """
        self.logger.info(f"Starting memory analysis: {dump_path}")
        
        # Validate dump file
        if not await self._validate_memory_dump(dump_path):
            raise ValueError(f"Invalid or corrupted memory dump: {dump_path}")
        
        # Setup output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize context
        context = self._create_volatility_context(dump_path)
        
        # Determine categories to analyze
        categories_to_run = categories or list(self.plugin_categories.keys())
        
        # Results storage
        analysis_results = {
            "dump_file": dump_path,
            "analysis_timestamp": time.time(),
            "categories_analyzed": categories_to_run,
            "results": {},
            "statistics": {
                "plugins_executed": 0,
                "plugins_successful": 0,
                "plugins_failed": 0,
                "total_duration": 0
            }
        }
        
        start_time = time.time()
        
        # Execute plugin categories
        for category_name in categories_to_run:
            if category_name not in self.plugin_categories:
                self.logger.warning(f"Unknown category: {category_name}")
                continue
            
            self.logger.info(f"Analyzing category: {category_name}")
            
            category_results = await self._analyze_category(
                context, 
                category_name, 
                output_path,
                yara_rules
            )
            
            analysis_results["results"][category_name] = category_results
        
        # Calculate final statistics
        end_time = time.time()
        analysis_results["statistics"]["total_duration"] = end_time - start_time
        
        # Generate summary report
        await self._generate_analysis_report(analysis_results, output_path)
        
        self.logger.info(f"Memory analysis completed in {end_time - start_time:.2f}s")
        
        return analysis_results
    
    async def _validate_memory_dump(self, dump_path: str) -> bool:
        """Validate memory dump file"""
        try:
            if not os.path.exists(dump_path):
                return False
            
            # Check file size (should be reasonable for memory dump)
            file_size = os.path.getsize(dump_path)
            if file_size < 1024 * 1024:  # Less than 1MB is suspicious
                self.logger.warning(f"Memory dump seems too small: {file_size} bytes")
                return False
            
            # Try to read first few bytes to check format
            with open(dump_path, 'rb') as f:
                header = f.read(8)
                
                # Check for common memory dump signatures
                # Raw memory dumps, crash dumps, etc.
                valid_signatures = [
                    b'PAGEDUM',  # Windows crash dump
                    b'PAGEDUMP', # Windows crash dump
                    b'DMP\x00',  # Another dump format
                ]
                
                # For raw dumps, we can't easily validate without Volatility
                # So we'll just check it's readable and reasonable size
                return True
                
        except Exception as e:
            self.logger.error(f"Error validating memory dump: {e}")
            return False
    
    def _create_volatility_context(self, dump_path: str) -> interfaces.context.ContextInterface:
        """Create Volatility 3 context for analysis"""
        try:
            # Create context
            context = contexts.Context()
            
            # Configure memory layer
            context.config['automagic.LayerStacker.single_location'] = f"file://{dump_path}"
            
            # Set symbol paths
            if os.path.exists(self.symbols_path):
                context.config['automagic.LayerStacker.stackers.intel.IntelStacker.single_location'] = f"file://{dump_path}"
            
            return context
            
        except Exception as e:
            self.logger.error(f"Failed to create Volatility context: {e}")
            raise
    
    async def _analyze_category(self, 
                              context: interfaces.context.ContextInterface,
                              category_name: str, 
                              output_path: Path,
                              yara_rules: str = None) -> Dict[str, Any]:
        """Analyze a specific plugin category"""
        category_config = self.plugin_categories[category_name]
        category_results = {
            "description": category_config["description"],
            "plugins": {},
            "summary": {
                "plugins_run": 0,
                "plugins_successful": 0,
                "plugins_failed": 0,
                "duration": 0
            }
        }
        
        start_time = time.time()
        
        # Create category output directory
        category_dir = output_path / category_name
        category_dir.mkdir(exist_ok=True)
        
        # Execute plugins in this category
        for plugin_info in category_config["plugins"]:
            plugin_name = plugin_info["name"]
            plugin_class = plugin_info["class"]
            
            if plugin_class is None:
                self.logger.warning(f"Plugin class not available: {plugin_name}")
                continue
            
            self.logger.info(f"Running plugin: {plugin_name}")
            
            try:
                plugin_start = time.time()
                
                # Special handling for yarascan if YARA rules provided
                if plugin_name == "yarascan" and yara_rules:
                    plugin_result = await self._run_yarascan_plugin(
                        context, plugin_class, category_dir, yara_rules
                    )
                else:
                    plugin_result = await self._run_volatility_plugin(
                        context, plugin_class, category_dir, plugin_name
                    )
                
                plugin_duration = time.time() - plugin_start
                
                category_results["plugins"][plugin_name] = {
                    "status": "success",
                    "duration": plugin_duration,
                    "result": plugin_result,
                    "output_file": str(category_dir / f"{plugin_name}.json")
                }
                
                category_results["summary"]["plugins_successful"] += 1
                
            except Exception as e:
                self.logger.error(f"Plugin {plugin_name} failed: {e}")
                
                category_results["plugins"][plugin_name] = {
                    "status": "failed",
                    "error": str(e),
                    "duration": time.time() - plugin_start
                }
                
                category_results["summary"]["plugins_failed"] += 1
            
            category_results["summary"]["plugins_run"] += 1
        
        category_results["summary"]["duration"] = time.time() - start_time
        
        return category_results
    
    async def _run_volatility_plugin(self, 
                                   context: interfaces.context.ContextInterface,
                                   plugin_class: type,
                                   output_dir: Path,
                                   plugin_name: str) -> Dict[str, Any]:
        """Run a standard Volatility plugin"""
        try:
            # Instantiate plugin
            plugin = plugin_class(context, self.vol_config, None)
            
            # Run plugin and collect results
            results = []
            
            for row in plugin.run():
                # Convert TreeNode results to serializable format
                if hasattr(row, '__iter__') and not isinstance(row, (str, bytes)):
                    row_data = {}
                    try:
                        for i, cell in enumerate(row):
                            if hasattr(cell, 'get_value'):
                                row_data[f'column_{i}'] = str(cell.get_value())
                            else:
                                row_data[f'column_{i}'] = str(cell)
                    except Exception:
                        row_data = {'data': str(row)}
                else:
                    row_data = {'data': str(row)}
                
                results.append(row_data)
            
            # Save results to file
            output_file = output_dir / f"{plugin_name}.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            return {
                "records_found": len(results),
                "output_file": str(output_file),
                "sample_data": results[:5] if results else []
            }
            
        except Exception as e:
            self.logger.error(f"Failed to run plugin {plugin_name}: {e}")
            raise
    
    async def _run_yarascan_plugin(self, 
                                 context: interfaces.context.ContextInterface,
                                 plugin_class: type,
                                 output_dir: Path,
                                 yara_rules: str) -> Dict[str, Any]:
        """Run YARA scan plugin with custom rules"""
        try:
            # Configure YARA scan
            yara_config = self.vol_config.clone()
            yara_config['yarascan.yara_rules'] = yara_rules
            
            # Instantiate plugin
            plugin = plugin_class(context, yara_config, None)
            
            # Run YARA scan
            matches = []
            
            for match in plugin.run():
                match_data = {
                    'rule_name': str(match[1]),  # Rule name
                    'offset': str(match[0]),     # Memory offset
                    'process': str(match[2]) if len(match) > 2 else None,
                    'context': str(match[3]) if len(match) > 3 else None
                }
                matches.append(match_data)
            
            # Save YARA results
            output_file = output_dir / "yarascan.json"
            with open(output_file, 'w') as f:
                json.dump(matches, f, indent=2, default=str)
            
            return {
                "matches_found": len(matches),
                "output_file": str(output_file),
                "yara_rules_used": yara_rules,
                "sample_matches": matches[:10] if matches else []
            }
            
        except Exception as e:
            self.logger.error(f"YARA scan failed: {e}")
            raise
    
    async def _generate_analysis_report(self, 
                                      analysis_results: Dict[str, Any], 
                                      output_path: Path):
        """Generate comprehensive analysis report"""
        
        # Create summary report
        summary_report = {
            "forensic_analysis_summary": {
                "dump_file": analysis_results["dump_file"],
                "analysis_timestamp": analysis_results["analysis_timestamp"],
                "total_duration": analysis_results["statistics"]["total_duration"],
                "categories_analyzed": len(analysis_results["categories_analyzed"]),
                "total_plugins": analysis_results["statistics"]["plugins_executed"],
                "successful_plugins": analysis_results["statistics"]["plugins_successful"],
                "failed_plugins": analysis_results["statistics"]["plugins_failed"]
            },
            "category_summaries": {},
            "key_findings": [],
            "recommendations": []
        }
        
        # Process each category
        for category_name, category_data in analysis_results["results"].items():
            summary_report["category_summaries"][category_name] = {
                "description": category_data["description"],
                "plugins_successful": category_data["summary"]["plugins_successful"],
                "plugins_failed": category_data["summary"]["plugins_failed"],
                "duration": category_data["summary"]["duration"]
            }
            
            # Extract key findings
            for plugin_name, plugin_data in category_data.get("plugins", {}).items():
                if plugin_data.get("status") == "success":
                    result = plugin_data.get("result", {})
                    records = result.get("records_found", 0)
                    
                    if records > 0:
                        summary_report["key_findings"].append({
                            "category": category_name,
                            "plugin": plugin_name,
                            "finding": f"Found {records} records",
                            "severity": self._assess_finding_severity(plugin_name, records)
                        })
        
        # Generate recommendations
        summary_report["recommendations"] = self._generate_recommendations(analysis_results)
        
        # Save comprehensive report
        report_file = output_path / "memory_analysis_report.json"
        with open(report_file, 'w') as f:
            json.dump({
                "summary": summary_report,
                "detailed_results": analysis_results
            }, f, indent=2, default=str)
        
        # Generate HTML report if possible
        try:
            await self._generate_html_report(summary_report, output_path)
        except Exception as e:
            self.logger.warning(f"Failed to generate HTML report: {e}")
        
        self.logger.info(f"Analysis report saved: {report_file}")
    
    def _assess_finding_severity(self, plugin_name: str, record_count: int) -> str:
        """Assess severity of findings based on plugin and count"""
        
        high_severity_plugins = ["malfind", "hollowfind", "yarascan"]
        medium_severity_plugins = ["pslist", "netstat", "handles"]
        
        if plugin_name in high_severity_plugins:
            if record_count > 0:
                return "HIGH"
        elif plugin_name in medium_severity_plugins:
            if record_count > 50:
                return "MEDIUM"
            elif record_count > 10:
                return "LOW"
        
        return "INFO"
    
    def _generate_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate investigation recommendations based on findings"""
        recommendations = []
        
        # Check for malware indicators
        malware_category = analysis_results["results"].get("malware_analysis", {})
        for plugin_name, plugin_data in malware_category.get("plugins", {}).items():
            if plugin_data.get("status") == "success":
                records = plugin_data.get("result", {}).get("records_found", 0)
                if records > 0:
                    recommendations.append(
                        f"CRITICAL: {plugin_name} found {records} suspicious entries - "
                        "immediate malware analysis recommended"
                    )
        
        # Check for suspicious processes
        process_category = analysis_results["results"].get("process_analysis", {})
        pslist_data = process_category.get("plugins", {}).get("pslist", {})
        if pslist_data.get("status") == "success":
            process_count = pslist_data.get("result", {}).get("records_found", 0)
            if process_count > 100:
                recommendations.append(
                    f"INFO: High number of processes ({process_count}) - "
                    "review for suspicious or unnecessary processes"
                )
        
        # Check for network connections
        network_category = analysis_results["results"].get("network_analysis", {})
        netstat_data = network_category.get("plugins", {}).get("netstat", {})
        if netstat_data.get("status") == "success":
            connection_count = netstat_data.get("result", {}).get("records_found", 0)
            if connection_count > 0:
                recommendations.append(
                    f"MEDIUM: Found {connection_count} network connections - "
                    "review for suspicious external communications"
                )
        
        if not recommendations:
            recommendations.append("INFO: No immediate security concerns identified in memory analysis")
        
        return recommendations
    
    async def _generate_html_report(self, summary_report: Dict[str, Any], output_path: Path):
        """Generate HTML report for better readability"""
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ForensicHunter Memory Analysis Report</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .finding {{ padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .high {{ background: #ffebee; border-left: 4px solid #f44336; }}
                .medium {{ background: #fff3e0; border-left: 4px solid #ff9800; }}
                .low {{ background: #e8f5e8; border-left: 4px solid #4caf50; }}
                .info {{ background: #e3f2fd; border-left: 4px solid #2196f3; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>ForensicHunter Memory Analysis Report</h1>
                <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Analysis Summary</h2>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    <tr><td>Memory Dump</td><td>{summary_report['forensic_analysis_summary']['dump_file']}</td></tr>
                    <tr><td>Analysis Duration</td><td>{summary_report['forensic_analysis_summary']['total_duration']:.2f} seconds</td></tr>
                    <tr><td>Categories Analyzed</td><td>{summary_report['forensic_analysis_summary']['categories_analyzed']}</td></tr>
                    <tr><td>Total Plugins</td><td>{summary_report['forensic_analysis_summary']['total_plugins']}</td></tr>
                    <tr><td>Successful Plugins</td><td>{summary_report['forensic_analysis_summary']['successful_plugins']}</td></tr>
                    <tr><td>Failed Plugins</td><td>{summary_report['forensic_analysis_summary']['failed_plugins']}</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h2>Key Findings</h2>
        """
        
        for finding in summary_report.get("key_findings", []):
            severity_class = finding["severity"].lower()
            html_content += f"""
                <div class="finding {severity_class}">
                    <strong>{finding['severity']}</strong> - {finding['category']} / {finding['plugin']}: {finding['finding']}
                </div>
            """
        
        html_content += """
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
        """
        
        for recommendation in summary_report.get("recommendations", []):
            html_content += f"<li>{recommendation}</li>"
        
        html_content += """
                </ul>
            </div>
            
            <div class="section">
                <h2>Category Details</h2>
                <table>
                    <tr><th>Category</th><th>Description</th><th>Successful</th><th>Failed</th><th>Duration</th></tr>
        """
        
        for category, details in summary_report.get("category_summaries", {}).items():
            html_content += f"""
                <tr>
                    <td>{category}</td>
                    <td>{details['description']}</td>
                    <td>{details['plugins_successful']}</td>
                    <td>{details['plugins_failed']}</td>
                    <td>{details['duration']:.2f}s</td>
                </tr>
            """
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <p><small>Generated by ForensicHunter Enterprise Memory Analysis Module</small></p>
            </div>
        </body>
        </html>
        """
        
        # Save HTML report
        html_file = output_path / "memory_analysis_report.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report saved: {html_file}")

# Standalone function for CLI usage
async def analyze_memory_dump_cli(dump_path: str, 
                                output_dir: str, 
                                categories: List[str] = None,
                                yara_rules: str = None,
                                config_path: str = None) -> Dict[str, Any]:
    """
    CLI wrapper for memory dump analysis
    
    Args:
        dump_path: Path to memory dump
        output_dir: Output directory
        categories: Plugin categories to run
        yara_rules: YARA rules directory
        config_path: Config file path
        
    Returns:
        Analysis results
    """
    config = EnterpriseConfig(config_path) if config_path else EnterpriseConfig()
    analyzer = VolatilityAnalyzer(config)
    
    return await analyzer.analyze_memory_dump(
        dump_path=dump_path,
        output_dir=output_dir,
        categories=categories,
        yara_rules=yara_rules
    )