"""Integration tests for scanning functionality."""

import tempfile
from pathlib import Path

import pytest

from sca.cli import SCAScanner
from sca.config import Config


def test_php_vulnerability_detection():
    """Test PHP vulnerability detection."""
    config = Config()
    scanner = SCAScanner(config)

    # Create temporary PHP file with vulnerability
    with tempfile.NamedTemporaryFile(mode="w", suffix=".php", delete=False) as f:
        f.write('<?php echo $_GET["name"]; ?>')
        temp_file = Path(f.name)

    try:
        findings = scanner.scan_file(temp_file)
        # Should detect XSS vulnerability
        assert len(findings) > 0
        assert any("xss" in finding.get("rule_id", "").lower() for finding in findings)
    finally:
        temp_file.unlink()


def test_javascript_vulnerability_detection():
    """Test JavaScript vulnerability detection."""
    config = Config()
    scanner = SCAScanner(config)

    # Create temporary JS file with vulnerability
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write("eval(userInput);")
        temp_file = Path(f.name)

    try:
        findings = scanner.scan_file(temp_file)
        # Should detect code injection vulnerability
        assert len(findings) > 0
        assert any("eval" in finding.get("rule_id", "").lower() for finding in findings)
    finally:
        temp_file.unlink()
