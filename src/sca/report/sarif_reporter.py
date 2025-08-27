"""SARIF report generator."""

import json
import time
from pathlib import Path
from typing import Any, Dict, List


class SARIFReporter:
    """Generates SARIF 2.1.0 compliant reports."""

    def generate_report(
        self, findings: List[Dict[str, Any]], summary: Dict[str, Any], output_path: Path
    ):
        """Generate a SARIF report."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Secure Code Analyzer",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/company/secure-code-analyzer",
                            "rules": [],
                        }
                    },
                    "results": [],
                }
            ],
        }

        # Convert findings to SARIF format
        for finding in findings:
            result = {
                "ruleId": finding.get("rule_id"),
                "message": {"text": finding.get("message")},
                "level": self._severity_to_level(finding.get("severity")),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.get("file")},
                            "region": {
                                "startLine": finding.get("line", 1),
                                "startColumn": finding.get("column", 1),
                            },
                        }
                    }
                ],
            }
            sarif["runs"][0]["results"].append(result)

        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2)

    def _severity_to_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        return mapping.get(severity.lower(), "warning")
