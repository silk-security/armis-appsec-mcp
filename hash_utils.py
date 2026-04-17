"""Shared hash utilities for the AppSec MCP plugin.

Used by both server.py and hooks/pre_commit_scan.py to compute
the staged diff hash for the .scan-pass commit gate.
"""

import hashlib
import subprocess

_MAX_DIFF_BYTES = 50 * 1024 * 1024  # 50 MB — safety limit for hashing


def compute_staged_hash() -> str:
    """Compute SHA-256 hash of the current staged diff."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 or not result.stdout:
            return ""
        if len(result.stdout) > _MAX_DIFF_BYTES:
            return ""  # Too large to hash safely
        return hashlib.sha256(result.stdout.encode()).hexdigest()
    except (subprocess.TimeoutExpired, OSError):
        return ""
