"""Taint analysis engine for tracking data flow."""

import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class TaintAnalyzer:
    """Performs taint analysis on parsed code."""

    def __init__(self, config):
        self.config = config
        self.sources = config.taint_sources
        self.sinks = config.taint_sinks

    def analyze_file(
        self, file_path: Path, tree, language: str
    ) -> List[Dict[str, Any]]:
        """Perform taint analysis on a file."""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Simple taint analysis - would be more sophisticated in full implementation
            tainted_vars = self._find_taint_sources(content, language)
            sink_usage = self._find_taint_sinks(content, language)

            # Check for potential taint flows
            for source_var in tainted_vars:
                for sink in sink_usage:
                    if self._potential_flow(source_var, sink, content):
                        finding = {
                            "rule_id": f"taint-{language}-flow",
                            "title": "Potential Taint Flow",
                            "message": f"Untrusted data from {source_var} may reach dangerous sink {sink}",
                            "severity": "high",
                            "confidence": "medium",
                            "cwe": "CWE-20",
                            "owasp": "A03:2021 - Injection",
                            "file": str(file_path),
                            "line": 1,  # Would be actual line number
                            "column": 1,
                            "remediation": "Validate and sanitize input before using in sensitive operations",
                        }
                        findings.append(finding)

        except Exception as e:
            logger.error(f"Error in taint analysis for {file_path}: {e}")

        return findings

    def _find_taint_sources(self, content: str, language: str) -> List[str]:
        """Find taint sources in code."""
        sources = []
        for source in self.sources:
            if source in content:
                sources.append(source)
        return sources

    def _find_taint_sinks(self, content: str, language: str) -> List[str]:
        """Find taint sinks in code."""
        sinks = []
        for sink in self.sinks:
            if sink in content:
                sinks.append(sink)
        return sinks

    def _potential_flow(self, source: str, sink: str, content: str) -> bool:
        """Check if there's a potential flow from source to sink."""
        # Simple heuristic - would be proper data-flow analysis in full implementation
        source_pos = content.find(source)
        sink_pos = content.find(sink)
        return source_pos >= 0 and sink_pos >= 0 and source_pos < sink_pos
