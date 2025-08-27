"""Rule engine for loading and executing security rules."""

import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml

logger = logging.getLogger(__name__)


class RuleEngine:
    """Loads and executes security analysis rules."""

    def __init__(self, config):
        self.config = config
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        """Load rules from YAML files."""
        rules_dir = self.config.rules_directory
        for rule_file in rules_dir.glob("**/*.yaml"):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    content = yaml.safe_load(f)
                    if content and "rules" in content:
                        for rule in content["rules"]:
                            if rule:
                                self.rules.append(rule)
            except Exception as e:
                logger.error(f"Error loading rule file {rule_file}: {e}")

    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all loaded rules."""
        return self.rules

    def get_rule(self, rule_id: str) -> Dict[str, Any]:
        """Get a specific rule by ID."""
        for rule in self.rules:
            if rule.get("id") == rule_id:
                return rule
        return None

    def analyze_file(
        self, file_path: Path, tree, language: str
    ) -> List[Dict[str, Any]]:
        """Analyze a file with loaded rules."""
        findings = []

        for rule in self.rules:
            if language in rule.get("languages", []):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # Simple pattern matching
                    if self._check_rule_patterns(rule, content):
                        finding = {
                            "rule_id": rule.get("id"),
                            "title": rule.get("title"),
                            "message": rule.get("message"),
                            "severity": rule.get("severity", "medium"),
                            "confidence": rule.get("confidence", "medium"),
                            "cwe": rule.get("cwe"),
                            "owasp": rule.get("owasp"),
                            "file": str(file_path),
                            "line": 1,
                            "column": 1,
                            "remediation": rule.get("remediation"),
                        }
                        findings.append(finding)
                except Exception as e:
                    logger.error(
                        f"Error analyzing {file_path} with rule {rule.get('id')}: {e}"
                    )

        return findings

    def _check_rule_patterns(self, rule, content: str) -> bool:
        """Simple pattern checking."""
        patterns = rule.get("pattern", [])

        for pattern in patterns:
            if isinstance(pattern, dict) and "contains" in pattern:
                if pattern["contains"] in content:
                    return True

        return False
