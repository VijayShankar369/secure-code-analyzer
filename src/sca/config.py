"""
Configuration management for Secure Code Analyzer.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class Config:
    """Configuration settings for the analyzer."""

    # Rule configuration
    rules_directory: Path = field(
        default_factory=lambda: Path(__file__).parent.parent.parent / "rules"
    )
    enabled_rules: List[str] = field(default_factory=list)
    disabled_rules: List[str] = field(default_factory=list)

    # Severity and filtering
    min_severity: str = "info"
    fail_on_severity: str = "high"

    # File scanning options
    include_patterns: List[str] = field(
        default_factory=lambda: [
            "**/*.php",
            "**/*.js",
            "**/*.jsx",
            "**/*.ts",
            "**/*.tsx",
        ]
    )
    exclude_patterns: List[str] = field(
        default_factory=lambda: [
            "**/node_modules/**",
            "**/vendor/**",
            "**/build/**",
            "**/dist/**",
            "**/.git/**",
            "**/tests/**",
            "**/test/**",
        ]
    )
    max_file_size: int = 1024 * 1024  # 1MB

    # Performance options
    max_workers: int = 4
    timeout: int = 300

    # Taint analysis options
    no_taint: bool = False
    taint_sources: List[str] = field(
        default_factory=lambda: [
            "_GET",
            "_POST",
            "_REQUEST",
            "_COOKIE",
            "_SERVER",
            "_FILES",
            "process.argv",
            "process.env",
            "window.location",
            "document.cookie",
        ]
    )
    taint_sinks: List[str] = field(
        default_factory=lambda: [
            "eval",
            "exec",
            "system",
            "shell_exec",
            "mysql_query",
            "document.write",
            "innerHTML",
            "outerHTML",
        ]
    )

    # Baseline and diff options
    baseline_file: Optional[Path] = None
    diff_base: Optional[str] = None

    # Output options
    json_output: Optional[Path] = None
    sarif_output: Optional[Path] = None
    verbose: bool = False

    @classmethod
    def from_file(cls, config_path: Path) -> "Config":
        """Load configuration from YAML file."""
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create configuration from dictionary."""
        config = cls()

        # Update fields from dictionary
        for key, value in data.items():
            if hasattr(config, key):
                if key.endswith("_directory") or key.endswith("_file"):
                    setattr(config, key, Path(value) if value else None)
                else:
                    setattr(config, key, value)

        return config

    def save_to_file(self, config_path: Path) -> None:
        """Save configuration to YAML file."""
        data = {}
        for key, value in self.__dict__.items():
            if isinstance(value, Path):
                data[key] = str(value)
            else:
                data[key] = value

        with open(config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, indent=2)

    def get_default_config_content(self) -> str:
        """Get default sca.yaml configuration file content."""
        return """# Secure Code Analyzer Configuration

# Rule Management
rules:
  # Directory containing rule files
  directory: "./rules"
  
  # Enable/disable specific rules
  enabled: []  # Empty list means all rules enabled
  disabled: []
  
# Severity Configuration  
severity:
  # Minimum severity to report (info, low, medium, high, critical)
  min_level: "info"
  
  # Fail scan on this severity or higher
  fail_on: "high"

# File Scanning
files:
  # File patterns to include
  include:
    - "**/*.php"
    - "**/*.js"
    - "**/*.jsx" 
    - "**/*.ts"
    - "**/*.tsx"
    
  # File patterns to exclude
  exclude:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/build/**"
    - "**/dist/**"
    - "**/.git/**"
    - "**/tests/**"
    - "**/test/**"
    
  # Maximum file size to scan (bytes)
  max_size: 1048576  # 1MB

# Performance
performance:
  # Number of worker processes
  max_workers: 4
  
  # Timeout for entire scan (seconds)
  timeout_seconds: 300

# Taint Analysis
taint:
  # Enable/disable taint analysis
  enabled: true
  
  # Taint sources (where untrusted data comes from)
  sources:
    - "_GET"
    - "_POST" 
    - "_REQUEST"
    - "_COOKIE"
    - "_SERVER"
    - "_FILES"
    - "process.argv"
    - "process.env"
    - "window.location"
    - "document.cookie"
    
  # Taint sinks (dangerous operations)
  sinks:
    - "eval"
    - "exec"
    - "system"
    - "shell_exec"
    - "mysql_query"
    - "document.write"
    - "innerHTML"
    - "outerHTML"

# Baseline and Differential Scanning
baseline:
  # Path to baseline SARIF file
  file: null
  
  # Update baseline after scan
  update: false

# Git Diff Options
diff:
  # Git reference to compare against
  base: null  # e.g., "origin/main"

# Output Configuration
output:
  # JSON report output path
  json: null
  
  # SARIF report output path  
  sarif: null
  
  # Verbose output
  verbose: false

# Custom rule directories (in addition to default ./rules)
custom_rule_paths: []
"""
