#!/usr/bin/env python3
"""
Secure Code Analyzer (SCA) - Command Line Interface

Production-ready CLI for static code analysis of PHP and JavaScript security vulnerabilities.
"""


import multiprocessing as mp
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from .config import Config
from .engine.rule_engine import RuleEngine
from .parser.js_parser import JavaScriptParser
from .parser.php_parser import PHPParser
from .report.json_reporter import JSONReporter
from .report.sarif_reporter import SARIFReporter
from .taint.analyzer import TaintAnalyzer
from .utils.file_utils import find_files, get_git_diff_files
from .utils.logging import setup_logging

console = Console()


@dataclass
class ScanResult:
    """Results from a scan operation."""

    findings: List[Dict[str, Any]]
    summary: Dict[str, Any]
    duration: float
    files_scanned: int


class SCAScanner:
    """Main scanner class that orchestrates the analysis."""

    def __init__(self, config: Config):
        self.config = config
        self.rule_engine = RuleEngine(config)
        self.php_parser = PHPParser()
        self.js_parser = JavaScriptParser()
        self.taint_analyzer = TaintAnalyzer(config) if not config.no_taint else None

    def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan a single file for vulnerabilities."""
        try:
            if file_path.suffix.lower() in [".php"]:
                parser = self.php_parser
                language = "php"
            elif file_path.suffix.lower() in [".js", ".jsx", ".ts", ".tsx"]:
                parser = self.js_parser
                language = "javascript"
            else:
                return []

            # Parse the file
            with open(file_path, "rb") as f:
                content = f.read()

            tree = parser.parse(content)
            if not tree:
                return []

            # Run pattern-based rules
            findings = self.rule_engine.analyze_file(file_path, tree, language)

            # Run taint analysis if enabled
            if self.taint_analyzer and not self.config.no_taint:
                taint_findings = self.taint_analyzer.analyze_file(
                    file_path, tree, language
                )
                findings.extend(taint_findings)

            return findings

        except Exception as e:
            console.print(f"[red]Error scanning {file_path}: {e}")
            return []

    def scan_directory(self, path: Path, diff_base: Optional[str] = None) -> ScanResult:
        """Scan a directory or specific files."""
        start_time = time.time()

        # Get files to scan
        if diff_base:
            files = get_git_diff_files(path, diff_base)
            console.print(f"[blue]Scanning {len(files)} changed files vs {diff_base}")
        else:
            files = find_files(
                path, self.config.include_patterns, self.config.exclude_patterns
            )
            console.print(f"[blue]Scanning {len(files)} files in {path}")

        if not files:
            console.print("[yellow]No files found to scan")
            return ScanResult([], {}, 0, 0)

        # Filter files by size limit
        filtered_files = []
        for file_path in files:
            try:
                if file_path.stat().st_size <= self.config.max_file_size:
                    filtered_files.append(file_path)
                else:
                    console.print(
                        f"[yellow]Skipping {file_path} (too large: {file_path.stat().st_size} bytes)"
                    )
            except OSError:
                continue

        files = filtered_files
        all_findings = []

        # Scan files with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning files...", total=len(files))

            for file_path in files:
                findings = self.scan_file(file_path)
                all_findings.extend(findings)
                progress.advance(task)

        duration = time.time() - start_time

        # Create summary
        summary = self._create_summary(all_findings, len(files), duration)

        return ScanResult(all_findings, summary, duration, len(files))

    def _create_summary(
        self, findings: List[Dict[str, Any]], files_scanned: int, duration: float
    ) -> Dict[str, Any]:
        """Create summary statistics."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        rule_counts = {}

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

            rule_id = finding.get("rule_id", "unknown")
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

        return {
            "total_findings": len(findings),
            "files_scanned": files_scanned,
            "duration_seconds": round(duration, 2),
            "severity_counts": severity_counts,
            "rule_counts": rule_counts,
            "scan_timestamp": time.time(),
        }


@click.group()
@click.version_option(version="0.1.0")
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Path to configuration file"
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, config, verbose):
    """Secure Code Analyzer - Static security analysis for PHP and JavaScript."""
    ctx.ensure_object(dict)

    # Setup logging
    setup_logging(verbose)

    # Load configuration
    if config:
        ctx.obj["config"] = Config.from_file(Path(config))
    else:
        ctx.obj["config"] = Config()


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--json", "json_output", type=click.Path(), help="Output JSON report to file"
)
@click.option(
    "--sarif", "sarif_output", type=click.Path(), help="Output SARIF report to file"
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "none"]),
    default="high",
    help="Fail on findings of this severity or higher",
)
@click.option("--diff-base", help="Compare against git reference (e.g., origin/main)")
@click.option(
    "--baseline",
    type=click.Path(exists=True),
    help="SARIF baseline file to compare against",
)
@click.option(
    "--update-baseline", is_flag=True, help="Update baseline file with current findings"
)
@click.option(
    "--severity-filter",
    multiple=True,
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Only show findings of specified severity levels",
)
@click.option(
    "--max-workers",
    type=int,
    default=mp.cpu_count(),
    help="Maximum number of worker processes",
)
@click.option(
    "--timeout", type=int, default=300, help="Timeout in seconds for the entire scan"
)
@click.option("--no-taint", is_flag=True, help="Disable taint analysis")
@click.pass_context
def scan(
    ctx,
    path,
    json_output,
    sarif_output,
    fail_on,
    diff_base,
    baseline,
    update_baseline,
    severity_filter,
    max_workers,
    timeout,
    no_taint,
):
    """Scan PATH for security vulnerabilities."""

    config = ctx.obj["config"]
    config.no_taint = no_taint
    config.max_workers = max_workers
    config.timeout = timeout

    # Create scanner
    scanner = SCAScanner(config)

    try:
        # Perform scan
        result = scanner.scan_directory(path, diff_base)

        # Apply severity filter if specified
        if severity_filter:
            filtered_findings = [
                f
                for f in result.findings
                if f.get("severity", "info").lower() in severity_filter
            ]
            result.findings = filtered_findings

        # Display results
        display_results(result)

        # Generate reports
        if json_output:
            json_reporter = JSONReporter()
            json_reporter.generate_report(
                result.findings, result.summary, Path(json_output)
            )
            console.print(f"[green]JSON report written to {json_output}")

        if sarif_output:
            sarif_reporter = SARIFReporter()
            sarif_reporter.generate_report(
                result.findings, result.summary, Path(sarif_output)
            )
            console.print(f"[green]SARIF report written to {sarif_output}")

        # Check if we should fail based on severity
        should_fail = check_failure_condition(result.findings, fail_on)

        if should_fail:
            console.print(
                f"[red]Scan failed: Found {fail_on} or higher severity issues"
            )
            sys.exit(1)
        else:
            console.print("[green]Scan completed successfully")
            sys.exit(0)

    except Exception as e:
        console.print(f"[red]Scan failed with error: {e}")
        sys.exit(2)


@cli.group()
def rules():
    """Manage analysis rules."""
    pass


@rules.command("list")
@click.option(
    "--language", type=click.Choice(["php", "javascript"]), help="Filter by language"
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Filter by severity",
)
@click.pass_context
def list_rules(ctx, language, severity):
    """List available rules."""
    config = ctx.obj["config"]
    rule_engine = RuleEngine(config)

    rules = rule_engine.get_rules()

    # Apply filters
    if language:
        rules = [r for r in rules if language in r.get("languages", [])]
    if severity:
        rules = [r for r in rules if r.get("severity", "").lower() == severity.lower()]

    # Display rules in a table
    table = Table(title="Security Analysis Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="magenta")
    table.add_column("Languages", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("CWE", style="blue")

    for rule in rules:
        table.add_row(
            rule.get("id", ""),
            rule.get("title", ""),
            ", ".join(rule.get("languages", [])),
            rule.get("severity", ""),
            rule.get("cwe", ""),
        )

    console.print(table)


@rules.command("show")
@click.argument("rule_id")
@click.pass_context
def show_rule(ctx, rule_id):
    """Show detailed information about a specific rule."""
    config = ctx.obj["config"]
    rule_engine = RuleEngine(config)

    rule = rule_engine.get_rule(rule_id)
    if not rule:
        console.print(f"[red]Rule {rule_id} not found")
        sys.exit(1)

    # Display rule details
    panel_content = f"""
**Title:** {rule.get('title', 'N/A')}
**ID:** {rule.get('id', 'N/A')}  
**Languages:** {', '.join(rule.get('languages', []))}
**Severity:** {rule.get('severity', 'N/A')}
**Confidence:** {rule.get('confidence', 'N/A')}
**CWE:** {rule.get('cwe', 'N/A')}
**OWASP:** {rule.get('owasp', 'N/A')}

**Description:**
{rule.get('message', 'N/A')}

**Remediation:**
{rule.get('remediation', 'N/A')}
"""

    console.print(Panel(panel_content, title=f"Rule: {rule_id}"))


@cli.command()
def version():
    """Show version information."""
    console.print("Secure Code Analyzer v0.1.0")
    console.print("Licensed under MIT License")


def display_results(result: ScanResult):
    """Display scan results in a formatted table."""
    summary = result.summary

    # Summary panel
    summary_text = f"""
**Files Scanned:** {summary['files_scanned']}
**Total Findings:** {summary['total_findings']}
**Scan Duration:** {summary['duration_seconds']}s

**Severity Breakdown:**
• Critical: {summary['severity_counts']['critical']}
• High: {summary['severity_counts']['high']}  
• Medium: {summary['severity_counts']['medium']}
• Low: {summary['severity_counts']['low']}
• Info: {summary['severity_counts']['info']}
"""

    console.print(Panel(summary_text, title="Scan Summary"))

    # Findings table
    if result.findings:
        table = Table(title="Security Findings")
        table.add_column("File", style="cyan", max_width=40)
        table.add_column("Line", style="green", justify="right")
        table.add_column("Rule", style="magenta")
        table.add_column("Severity", style="yellow")
        table.add_column("Message", style="white", max_width=60)

        for finding in result.findings[:50]:  # Limit display to first 50
            table.add_row(
                str(finding.get("file", "")),
                str(finding.get("line", "")),
                finding.get("rule_id", ""),
                finding.get("severity", ""),
                finding.get("message", "")[:100]
                + ("..." if len(finding.get("message", "")) > 100 else ""),
            )

        console.print(table)

        if len(result.findings) > 50:
            console.print(f"[yellow]... and {len(result.findings) - 50} more findings")


def check_failure_condition(findings, fail_on):
    # If user specified “none”, never fail
    if fail_on.lower() == "none":
        return False

    severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    threshold = severity_levels.get(fail_on.lower(), 0)
    for f in findings:
        if severity_levels.get(f.get("severity", "info").lower(), 0) >= threshold:
            return True
    return False


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
