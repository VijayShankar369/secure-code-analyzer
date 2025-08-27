"""
Secure Code Analyzer (SCA) - Main Module

A production-ready static code analyzer for PHP and JavaScript that detects
security vulnerabilities, performs taint analysis, and generates SARIF/JSON reports.

License: MIT
"""

__version__ = "0.1.0"
__author__ = "Security Team"
__email__ = "security@company.com"

from .cli import main
from .config import Config
from .engine.rule_engine import RuleEngine
from .parser.js_parser import JavaScriptParser
from .parser.php_parser import PHPParser
from .report.json_reporter import JSONReporter
from .report.sarif_reporter import SARIFReporter
from .taint.analyzer import TaintAnalyzer

__all__ = [
    "__version__",
    "main",
    "Config",
    "RuleEngine",
    "PHPParser",
    "JavaScriptParser",
    "TaintAnalyzer",
    "JSONReporter",
    "SARIFReporter",
]
