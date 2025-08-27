"""File utility functions."""

import fnmatch
import logging
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


def find_files(
    root_path: Path, include_patterns: List[str], exclude_patterns: List[str]
) -> List[Path]:
    """Find files matching include patterns but not exclude patterns."""
    files = []

    for pattern in include_patterns:
        for file_path in root_path.rglob(pattern.replace("**/", "")):
            if file_path.is_file() and not _is_excluded(file_path, exclude_patterns):
                files.append(file_path)

    return sorted(list(set(files)))  # Remove duplicates and sort


def _is_excluded(file_path: Path, exclude_patterns: List[str]) -> bool:
    """Check if file matches any exclude pattern."""
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(str(file_path), pattern):
            return True
    return False


def get_git_diff_files(repo_path: Path, base_ref: str) -> List[Path]:
    """Get list of changed files compared to base reference."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", base_ref, "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            files = []
            for file_name in result.stdout.strip().split("\n"):
                if file_name:
                    file_path = repo_path / file_name
                    if file_path.exists() and file_path.is_file():
                        files.append(file_path)
            return files
        else:
            logger.warning(f"Git diff failed: {result.stderr}")
            return []

    except Exception as e:
        logger.error(f"Error getting git diff: {e}")
        return []
