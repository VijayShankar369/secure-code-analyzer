"""JSON report generator."""

import json
import time
from pathlib import Path
from typing import Any, Dict, List


class JSONReporter:
    """Generates JSON security reports."""

    def generate_report(
        self, findings: List[Dict[str, Any]], summary: Dict[str, Any], output_path: Path
    ):
        """Generate a JSON report."""
        report = {
            "version": "0.1.0",
            "scan_info": {
                "timestamp": time.time(),
                "tool": "Secure Code Analyzer",
                "version": "0.1.0",
            },
            "summary": summary,
            "findings": findings,
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
