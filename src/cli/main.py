#!/usr/bin/env python3
"""
ForensicHunter Enterprise CLI
Professional command-line interface inspired by KAPE but significantly enhanced

Usage examples:
    # KAPE-style target collection
    forensichunter collect --targets WindowsSystemFiles,BrowserArtifacts --dest /evidence/case001
    
    # Enhanced module execution  
    forensichunter modules --modules VolatilityMemoryAnalysis --evidence /evidence/case001
    
    # Full forensic workflow
    forensichunter investigate --targets all --modules all --dest /evidence/case001 --format json,html
    
    # Enterprise features
    forensichunter server --host 0.0.0.0 --port 8000  # Web interface
    forensichunter status --collection-id FH_20241130_12345678  # Monitor collection
"""

import asyncio
import sys
import os
import json
import time
from pathlib import Path
from typing import List, Optional, Dict, Any
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
import yaml

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.enterprise_config import EnterpriseConfig, ENTERPRISE_TARGETS, ENTERPRISE_MODULES
from src.core.enterprise_collector import EnterpriseCollector

console = Console()

@click.group()
@click.version_option(version="2.0.0-enterprise", prog_name="ForensicHunter Enterprise")
@click.option('--config', '-c', help='Configuration file path', default='config/enterprise.yaml')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def cli(ctx, config, verbose, quiet):
    """
    ForensicHunter Enterprise - Advanced Digital Forensics Platform
    
    Professional forensic collection and analysis tool inspired by KAPE
    but with enterprise-grade enhancements.
    """
    ctx.ensure_object(dict)
    ctx.obj['config'] = EnterpriseConfig(config)
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    
    if not quiet:
        console.print(Panel.fit(
            "[bold blue]ForensicHunter Enterprise v2.0.0[/bold blue]\n"
            "[italic]Advanced Digital Forensics Platform[/italic]",
            border_style="blue"
        ))

@cli.command()
@click.option('--targets', '-t', help='Comma-separated list of targets (or "all")', default='all')
@click.option('--dest', '-d', help='Destination directory', required=True)
@click.option('--source', '-s', help='Source drive/path', default='C:')
@click.option('--compress', is_flag=True, help='Compress collected files')
@click.option('--encrypt', is_flag=True, help='Encrypt collected files')
@click.option('--parallel', '-p', type=int, default=0, help='Number of parallel workers (0=auto)')
@click.option('--exclude', help='Comma-separated list of targets to exclude')
@click.option('--dry-run', is_flag=True, help='Show what would be collected without collecting')
@click.pass_context
def collect(ctx, targets, dest, source, compress, encrypt, parallel, exclude, dry_run):
    """
    Collect forensic artifacts (KAPE-style target collection enhanced)
    
    Examples:
        forensichunter collect --targets WindowsSystemFiles,BrowserArtifacts --dest /evidence/case001
        forensichunter collect --targets all --dest /evidence/case001 --compress --encrypt
        forensichunter collect --targets all --exclude StartupItems --dest /evidence/case001
    """
    config = ctx.obj['config']
    
    # Parse targets
    if targets.lower() == 'all':
        target_list = list(ENTERPRISE_TARGETS.keys())
    else:
        target_list = [t.strip() for t in targets.split(',')]
    
    # Apply exclusions
    if exclude:
        exclude_list = [e.strip() for e in exclude.split(',')]
        target_list = [t for t in target_list if t not in exclude_list]
    
    # Validate targets
    invalid_targets = [t for t in target_list if t not in ENTERPRISE_TARGETS]
    if invalid_targets:
        console.print(f"[red]Error: Invalid targets: {', '.join(invalid_targets)}[/red]")
        console.print(f"[yellow]Available targets: {', '.join(ENTERPRISE_TARGETS.keys())}[/yellow]")
        sys.exit(1)
    
    if dry_run:
        console.print("[yellow]DRY RUN - No files will be collected[/yellow]")
        table = Table(title="Collection Plan")
        table.add_column("Target", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Paths", style="yellow")
        
        for target_name in target_list:
            target_config = ENTERPRISE_TARGETS[target_name]
            paths_str = '\n'.join(target_config.get('paths', [])[:3])
            if len(target_config.get('paths', [])) > 3:
                paths_str += f"\n... and {len(target_config.get('paths', [])) - 3} more"
            
            table.add_row(
                target_name,
                target_config.get('description', ''),
                paths_str
            )
        
        console.print(table)
        return
    
    # Setup collector
    collector = EnterpriseCollector(config)
    
    # Progress tracking
    progress_data = {'current': 0, 'total': len(target_list), 'status': 'Initializing...'}
    
    def update_progress(current, total):
        progress_data['current'] = current
        progress_data['total'] = total
        progress_data['status'] = f'Processing target {current}/{total}'
    
    async def run_collection():
        try:
            console.print(f"[green]Starting collection of {len(target_list)} targets...[/green]")
            console.print(f"[blue]Destination: {dest}[/blue]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                
                task = progress.add_task("Collecting artifacts...", total=len(target_list))
                
                def progress_callback(current, total):
                    progress.update(task, advance=1)
                
                # Run collection
                result = await collector.collect_targets(
                    target_names=target_list,
                    output_path=dest,
                    progress_callback=progress_callback
                )
                
                progress.update(task, completed=len(target_list))
            
            # Display results
            console.print("\n[bold green]Collection completed successfully![/bold green]")
            
            # Results table
            results_table = Table(title="Collection Results")
            results_table.add_column("Metric", style="cyan")
            results_table.add_column("Value", style="green")
            
            stats = collector.stats
            duration = result.get('duration_seconds', 0)
            
            results_table.add_row("Targets Processed", str(stats['targets_processed']))
            results_table.add_row("Files Collected", str(stats['files_collected']))
            results_table.add_row("Data Collected", f"{stats['bytes_collected'] / (1024*1024):.1f} MB")
            results_table.add_row("Duplicates Skipped", str(stats['duplicates_skipped']))
            results_table.add_row("Errors", str(stats['errors']))
            results_table.add_row("Duration", f"{duration:.1f} seconds")
            results_table.add_row("Collection ID", result.get('collection_id', 'N/A'))
            
            console.print(results_table)
            
            # Save collection info
            collection_info = {
                'collection_id': result.get('collection_id'),
                'targets': target_list,
                'destination': dest,
                'timestamp': time.time(),
                'stats': stats,
                'duration': duration
            }
            
            info_file = Path(dest) / 'collection_info.json'
            with open(info_file, 'w') as f:
                json.dump(collection_info, f, indent=2)
            
            console.print(f"[blue]Collection info saved to: {info_file}[/blue]")
            
        except Exception as e:
            console.print(f"[red]Collection failed: {e}[/red]")
            if ctx.obj['verbose']:
                import traceback
                console.print(traceback.format_exc())
            sys.exit(1)
    
    # Run async collection
    asyncio.run(run_collection())

@cli.command()
@click.option('--modules', '-m', help='Comma-separated list of modules (or "all")', default='all')
@click.option('--evidence', '-e', help='Evidence directory path', required=True)
@click.option('--output', '-o', help='Module output directory')
@click.option('--timeout', '-t', type=int, default=1800, help='Timeout per module in seconds')
@click.option('--parallel', '-p', type=int, default=1, help='Number of parallel modules')
@click.pass_context
def modules(ctx, modules, evidence, output, timeout, parallel):
    """
    Execute forensic analysis modules (KAPE-style module processing enhanced)
    
    Examples:
        forensichunter modules --modules VolatilityMemoryAnalysis --evidence /evidence/case001
        forensichunter modules --modules all --evidence /evidence/case001 --parallel 4
    """
    config = ctx.obj['config']
    
    # Parse modules
    if modules.lower() == 'all':
        module_list = list(ENTERPRISE_MODULES.keys())
    else:
        module_list = [m.strip() for m in modules.split(',')]
    
    # Validate modules
    invalid_modules = [m for m in module_list if m not in ENTERPRISE_MODULES]
    if invalid_modules:
        console.print(f"[red]Error: Invalid modules: {', '.join(invalid_modules)}[/red]")
        console.print(f"[yellow]Available modules: {', '.join(ENTERPRISE_MODULES.keys())}[/yellow]")
        sys.exit(1)
    
    # Verify evidence directory
    evidence_path = Path(evidence)
    if not evidence_path.exists():
        console.print(f"[red]Error: Evidence directory does not exist: {evidence}[/red]")
        sys.exit(1)
    
    collector = EnterpriseCollector(config)
    
    async def run_modules():
        try:
            console.print(f"[green]Executing {len(module_list)} modules...[/green]")
            console.print(f"[blue]Evidence directory: {evidence}[/blue]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                
                task = progress.add_task("Executing modules...", total=len(module_list))
                
                results = await collector.execute_modules(
                    module_names=module_list,
                    evidence_path=evidence
                )
                
                progress.update(task, completed=len(module_list))
            
            # Display results
            console.print("\n[bold green]Module execution completed![/bold green]")
            
            results_table = Table(title="Module Execution Results")
            results_table.add_column("Module", style="cyan")
            results_table.add_column("Status", style="green")
            results_table.add_column("Duration", style="yellow")
            results_table.add_column("Output", style="blue")
            
            for module_name, result in results.items():
                if 'error' in result:
                    status = f"[red]Failed: {result['error']}[/red]"
                    duration = "N/A"
                    output = "N/A"
                else:
                    status = "[green]Success[/green]" if result.get('success') else "[red]Failed[/red]"
                    duration = f"{result.get('execution_time', 0):.1f}s"
                    output = "See module output directory"
                
                results_table.add_row(module_name, status, duration, output)
            
            console.print(results_table)
            
        except Exception as e:
            console.print(f"[red]Module execution failed: {e}[/red]")
            if ctx.obj['verbose']:
                import traceback
                console.print(traceback.format_exc())
            sys.exit(1)
    
    asyncio.run(run_modules())

@cli.command()
@click.option('--targets', '-t', help='Targets to collect (default: all)', default='all')
@click.option('--modules', '-m', help='Modules to execute (default: all)', default='all')
@click.option('--dest', '-d', help='Destination directory', required=True)
@click.option('--format', '-f', help='Report formats (json,html,pdf)', default='json,html')
@click.option('--memory-dump', help='Path to memory dump file for analysis')
@click.option('--case-name', help='Case name for documentation')
@click.option('--investigator', help='Investigator name')
@click.pass_context
def investigate(ctx, targets, modules, dest, format, memory_dump, case_name, investigator):
    """
    Complete forensic investigation workflow (Collection + Analysis + Reporting)
    
    This combines KAPE-style collection with enhanced analysis and reporting.
    
    Examples:
        forensichunter investigate --dest /evidence/case001 --case-name "Malware Investigation"
        forensichunter investigate --targets WindowsSystemFiles --modules VolatilityMemoryAnalysis --dest /evidence/case001
    """
    config = ctx.obj['config']
    
    async def run_investigation():
        try:
            console.print("[bold blue]Starting Complete Forensic Investigation[/bold blue]")
            
            # Phase 1: Collection
            console.print("\n[yellow]Phase 1: Artifact Collection[/yellow]")
            
            target_list = list(ENTERPRISE_TARGETS.keys()) if targets == 'all' else targets.split(',')
            
            collector = EnterpriseCollector(config)
            
            collection_result = await collector.collect_targets(
                target_names=target_list,
                output_path=dest
            )
            
            console.print(f"[green]✓ Collection completed - ID: {collection_result['collection_id']}[/green]")
            
            # Phase 2: Module Execution
            console.print("\n[yellow]Phase 2: Analysis Modules[/yellow]")
            
            module_list = list(ENTERPRISE_MODULES.keys()) if modules == 'all' else modules.split(',')
            
            module_results = await collector.execute_modules(
                module_names=module_list,
                evidence_path=dest
            )
            
            console.print("[green]✓ Analysis completed[/green]")
            
            # Phase 3: Memory Analysis (if provided)
            if memory_dump:
                console.print("\n[yellow]Phase 3: Memory Analysis[/yellow]")
                # TODO: Implement Volatility 3 integration
                console.print(f"[blue]Memory dump analysis: {memory_dump}[/blue]")
            
            # Phase 4: Reporting
            console.print("\n[yellow]Phase 4: Report Generation[/yellow]")
            
            # Generate investigation report
            report_data = {
                'case_name': case_name or f"Investigation_{collection_result['collection_id']}",
                'investigator': investigator or 'Unknown',
                'timestamp': time.time(),
                'collection_result': collection_result,
                'module_results': module_results,
                'summary': {
                    'files_collected': collector.stats['files_collected'],
                    'targets_processed': collector.stats['targets_processed'],
                    'modules_executed': collector.stats['modules_executed'],
                    'total_duration': collection_result.get('duration_seconds', 0)
                }
            }
            
            # Save report in requested formats
            report_formats = format.split(',')
            for fmt in report_formats:
                fmt = fmt.strip().lower()
                if fmt == 'json':
                    report_file = Path(dest) / 'investigation_report.json'
                    with open(report_file, 'w') as f:
                        json.dump(report_data, f, indent=2, default=str)
                    console.print(f"[green]✓ JSON report: {report_file}[/green]")
                
                elif fmt == 'html':
                    # TODO: Generate HTML report with templates
                    console.print("[yellow]HTML report generation pending[/yellow]")
                
                elif fmt == 'pdf':
                    # TODO: Generate PDF report
                    console.print("[yellow]PDF report generation pending[/yellow]")
            
            console.print(f"\n[bold green]Investigation completed successfully![/bold green]")
            console.print(f"[blue]Results saved to: {dest}[/blue]")
            
        except Exception as e:
            console.print(f"[red]Investigation failed: {e}[/red]")
            if ctx.obj['verbose']:
                import traceback
                console.print(traceback.format_exc())
            sys.exit(1)
    
    asyncio.run(run_investigation())

@cli.command()
@click.option('--list-targets', is_flag=True, help='List available targets')
@click.option('--list-modules', is_flag=True, help='List available modules')
@click.option('--target-info', help='Show detailed info about a target')
@click.option('--module-info', help='Show detailed info about a module')
def info(list_targets, list_modules, target_info, module_info):
    """
    Show information about available targets and modules
    """
    if list_targets:
        table = Table(title="Available Forensic Targets")
        table.add_column("Name", style="cyan")
        table.add_column("Category", style="green")
        table.add_column("Priority", style="yellow")
        table.add_column("Description", style="blue")
        
        for name, config in ENTERPRISE_TARGETS.items():
            table.add_row(
                name,
                config.get('category', 'N/A'),
                config.get('priority', 'N/A'),
                config.get('description', 'N/A')
            )
        
        console.print(table)
    
    if list_modules:
        table = Table(title="Available Analysis Modules")
        table.add_column("Name", style="cyan")
        table.add_column("Category", style="green")
        table.add_column("Priority", style="yellow")
        table.add_column("Description", style="blue")
        
        for name, config in ENTERPRISE_MODULES.items():
            table.add_row(
                name,
                config.get('category', 'N/A'),
                config.get('priority', 'N/A'),
                config.get('description', 'N/A')
            )
        
        console.print(table)
    
    if target_info:
        if target_info in ENTERPRISE_TARGETS:
            config = ENTERPRISE_TARGETS[target_info]
            console.print(Panel(
                f"[bold]Target: {target_info}[/bold]\n\n"
                f"Description: {config.get('description', 'N/A')}\n"
                f"Category: {config.get('category', 'N/A')}\n"
                f"Priority: {config.get('priority', 'N/A')}\n"
                f"Author: {config.get('author', 'N/A')}\n"
                f"Version: {config.get('version', 'N/A')}\n\n"
                f"[bold]Paths:[/bold]\n" + '\n'.join(f"  • {path}" for path in config.get('paths', [])),
                title=f"Target Information: {target_info}",
                border_style="blue"
            ))
        else:
            console.print(f"[red]Target not found: {target_info}[/red]")
    
    if module_info:
        if module_info in ENTERPRISE_MODULES:
            config = ENTERPRISE_MODULES[module_info]
            console.print(Panel(
                f"[bold]Module: {module_info}[/bold]\n\n"
                f"Description: {config.get('description', 'N/A')}\n"
                f"Category: {config.get('category', 'N/A')}\n"
                f"Priority: {config.get('priority', 'N/A')}\n"
                f"Author: {config.get('author', 'N/A')}\n"
                f"Version: {config.get('version', 'N/A')}\n"
                f"Executable: {config.get('executable', 'N/A')}\n"
                f"Timeout: {config.get('timeout', 'N/A')}s\n\n"
                f"[bold]Command:[/bold]\n{config.get('command_line', 'N/A')}",
                title=f"Module Information: {module_info}",
                border_style="green"
            ))
        else:
            console.print(f"[red]Module not found: {module_info}[/red]")

@cli.command()
@click.option('--collection-id', help='Collection ID to check status')
@click.option('--list-collections', is_flag=True, help='List recent collections')
@click.option('--monitor', is_flag=True, help='Monitor active collections')
def status(collection_id, list_collections, monitor):
    """
    Check status of collections and system health
    """
    if list_collections:
        # TODO: Implement collection history tracking
        console.print("[yellow]Collection history tracking not yet implemented[/yellow]")
    
    if collection_id:
        # TODO: Implement collection status checking
        console.print(f"[yellow]Status check for collection {collection_id} not yet implemented[/yellow]")
    
    if monitor:
        # TODO: Implement real-time monitoring
        console.print("[yellow]Real-time monitoring not yet implemented[/yellow]")
    
    # System status
    table = Table(title="System Status")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details", style="yellow")
    
    # Check Python version
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    table.add_row("Python", "[green]OK[/green]", f"Version {python_version}")
    
    # Check disk space
    try:
        import shutil
        total, used, free = shutil.disk_usage("/")
        free_gb = free // (1024**3)
        table.add_row("Disk Space", "[green]OK[/green]" if free_gb > 10 else "[red]Low[/red]", f"{free_gb} GB free")
    except:
        table.add_row("Disk Space", "[yellow]Unknown[/yellow]", "Unable to check")
    
    # Check dependencies
    dependencies = [
        ('volatility3', 'Memory Analysis'),
        ('yara', 'Malware Detection'), 
        ('psutil', 'System Monitoring'),
        ('fastapi', 'Web Interface')
    ]
    
    for dep, desc in dependencies:
        try:
            __import__(dep.replace('-', '_'))
            table.add_row(dep, "[green]Available[/green]", desc)
        except ImportError:
            table.add_row(dep, "[red]Missing[/red]", desc)
    
    console.print(table)

@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=8000, type=int, help='Port to bind to')
@click.option('--workers', default=4, type=int, help='Number of worker processes')
@click.option('--dev', is_flag=True, help='Development mode with hot reload')
@click.pass_context
def server(ctx, host, port, workers, dev):
    """
    Start ForensicHunter web interface server
    
    Provides a web-based interface for forensic investigations.
    """
    try:
        import uvicorn
        from src.api.main import app
        
        console.print(f"[green]Starting ForensicHunter Enterprise Server[/green]")
        console.print(f"[blue]Host: {host}:{port}[/blue]")
        console.print(f"[blue]Workers: {workers}[/blue]")
        
        if dev:
            console.print("[yellow]Development mode - Hot reload enabled[/yellow]")
            uvicorn.run(
                "src.api.main:app",
                host=host,
                port=port,
                reload=True,
                log_level="info"
            )
        else:
            uvicorn.run(
                app,
                host=host,
                port=port,
                workers=workers,
                log_level="info"
            )
            
    except ImportError:
        console.print("[red]Web server dependencies not installed[/red]")
        console.print("Install with: pip install 'forensichunter[server]'")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Failed to start server: {e}[/red]")
        sys.exit(1)

@cli.command()
@click.option('--format', type=click.Choice(['yaml', 'json']), default='yaml')
def config(format):
    """
    Generate default configuration file
    """
    config_obj = EnterpriseConfig()
    
    if format == 'yaml':
        config_content = yaml.dump(config_obj.config, default_flow_style=False)
        filename = 'forensichunter_config.yaml'
    else:
        config_content = json.dumps(config_obj.config, indent=2)
        filename = 'forensichunter_config.json'
    
    with open(filename, 'w') as f:
        f.write(config_content)
    
    console.print(f"[green]Configuration file generated: {filename}[/green]")
    console.print("[yellow]Please review and customize the configuration before use[/yellow]")

if __name__ == '__main__':
    cli()