"""
Base parser interface and common functionality for all language parsers.
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

import tree_sitter
from tree_sitter import Language, Parser, Tree

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """Abstract base class for language-specific parsers."""

    def __init__(self, language_name: str):
        self.language_name = language_name
        self._parser = None
        self._language = None
        self._initialize_parser()

    @abstractmethod
    def _get_language(self) -> Language:
        """Get the tree-sitter language object for this parser."""
        pass

    def _initialize_parser(self) -> None:
        """Initialize the tree-sitter parser."""
        try:
            self._language = self._get_language()
            self._parser = Parser(self._language)
            logger.info(f"Initialized {self.language_name} parser")
        except Exception as e:
            logger.error(f"Failed to initialize {self.language_name} parser: {e}")
            raise

    def parse(self, source_code: bytes) -> Optional[Tree]:
        """Parse source code and return the syntax tree."""
        if not self._parser:
            logger.error(f"{self.language_name} parser not initialized")
            return None

        try:
            tree = self._parser.parse(source_code)
            if tree.root_node.has_error:
                logger.warning(f"Parse errors found in {self.language_name} code")
            return tree
        except Exception as e:
            logger.error(f"Failed to parse {self.language_name} code: {e}")
            return None

    def parse_file(self, file_path: Path) -> Optional[Tree]:
        """Parse a source code file."""
        try:
            with open(file_path, "rb") as f:
                source_code = f.read()
            return self.parse(source_code)
        except Exception as e:
            logger.error(f"Failed to read/parse file {file_path}: {e}")
            return None

    def query(self, tree: Tree, query_string: str) -> List[Dict[str, Any]]:
        """Execute a tree-sitter query on the syntax tree."""
        if not self._language or not tree:
            return []

        try:
            query = self._language.query(query_string)
            captures = query.captures(tree.root_node)

            results = []
            for capture_name, nodes in captures.items():
                for node in nodes:
                    results.append(
                        {
                            "capture": capture_name,
                            "node": node,
                            "text": node.text.decode("utf-8", errors="ignore"),
                            "start_point": node.start_point,
                            "end_point": node.end_point,
                            "start_byte": node.start_byte,
                            "end_byte": node.end_byte,
                        }
                    )
            return results
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            return []

    def get_function_definitions(self, tree: Tree) -> List[Dict[str, Any]]:
        """Extract function definitions from the syntax tree."""
        # This is a default implementation that should be overridden by subclasses
        return []

    def get_variable_declarations(self, tree: Tree) -> List[Dict[str, Any]]:
        """Extract variable declarations from the syntax tree."""
        # This is a default implementation that should be overridden by subclasses
        return []

    def get_function_calls(self, tree: Tree) -> List[Dict[str, Any]]:
        """Extract function calls from the syntax tree."""
        # This is a default implementation that should be overridden by subclasses
        return []

    def is_supported_file(self, file_path: Path) -> bool:
        """Check if the file is supported by this parser."""
        # This should be overridden by subclasses
        return False

    def get_node_by_position(self, tree: Tree, line: int, column: int) -> Optional[Any]:
        """Get the AST node at a specific line and column position."""

        def find_node_at_position(node, target_line, target_column):
            start_line, start_column = node.start_point
            end_line, end_column = node.end_point

            # Check if position is within this node
            if (
                start_line <= target_line <= end_line
                and (start_line < target_line or start_column <= target_column)
                and (target_line < end_line or target_column <= end_column)
            ):

                # Check children for more specific match
                for child in node.children:
                    child_result = find_node_at_position(
                        child, target_line, target_column
                    )
                    if child_result:
                        return child_result

                # Return this node if no more specific child found
                return node

            return None

        if not tree:
            return None

        return find_node_at_position(tree.root_node, line, column)

    def extract_strings(self, tree: Tree) -> List[Dict[str, Any]]:
        """Extract string literals from the syntax tree."""
        if not tree:
            return []

        strings = []

        def visit_node(node):
            if "string" in node.type.lower():
                strings.append(
                    {
                        "text": node.text.decode("utf-8", errors="ignore"),
                        "start_point": node.start_point,
                        "end_point": node.end_point,
                        "node_type": node.type,
                    }
                )

            for child in node.children:
                visit_node(child)

        visit_node(tree.root_node)
        return strings

    def get_imports(self, tree: Tree) -> List[Dict[str, Any]]:
        """Extract import/include statements from the syntax tree."""
        # Default implementation - should be overridden by subclasses
        return []
