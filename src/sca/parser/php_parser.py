"""
Simplified PHP parser that works without complex tree-sitter queries.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class PHPParser:
    """Simplified PHP parser for basic pattern matching."""

    def __init__(self):
        self.language_name = "PHP"
        logger.info(f"Initialized simplified {self.language_name} parser")

    def parse(self, source_code: bytes):
        """Parse source code – simplified version."""

        class MockTree:
            def __init__(self, content):
                self.content = content
                self.root_node = self

            @property
            def text(self):
                return self.content

        return MockTree(source_code)

    def parse_file(self, file_path: Path):
        """Parse a source code file."""
        try:
            with open(file_path, "rb") as f:
                source_code = f.read()
            return self.parse(source_code)
        except Exception as e:
            logger.error(f"Failed to read/parse file {file_path}: {e}")
            return None

    def is_supported_file(self, file_path: Path) -> bool:
        """Check if file is a PHP file."""
        return file_path.suffix.lower() in [".php", ".phtml", ".inc"]
