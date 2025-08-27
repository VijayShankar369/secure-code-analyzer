"""Unit tests for CLI module."""

from unittest.mock import Mock, patch

import pytest

from sca.cli import SCAScanner
from sca.config import Config


def test_sca_scanner_initialization():
    """Test SCAScanner initialization."""
    config = Config()
    scanner = SCAScanner(config)
    assert scanner.config == config
    assert scanner.rule_engine is not None
    assert scanner.php_parser is not None
    assert scanner.js_parser is not None


def test_config_loading():
    """Test configuration loading."""
    config = Config()
    assert config.max_workers == 4
    assert config.timeout == 300
    assert "php" in str(config.include_patterns)
