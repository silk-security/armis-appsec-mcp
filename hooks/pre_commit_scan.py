#!/usr/bin/env python3
"""
Claude Code PreToolUse Hook -- Security gate for shipping commands.

Fires before every Bash tool execution. Inspects the command and blocks
git commit, git push, and gh pr create until code has been scanned.

Uses "exit 2 + stderr JSON" to deny the command and inject a systemMessage
telling Claude to scan first, then retry the original command.

After a clean scan, the MCP server writes a .scan-pass file containing the
SHA-256 hash of the staged diff. For commit commands, the hook computes the
current staged hash and compares — same hash means these exact changes were
scanned. For push/PR commands, file existence suffices (commit already
enforced the scan).
"""

import json
import os
import re
import sys

# Add plugin root to path so we can import hash_utils
_plugin_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _plugin_root_dir not in sys.path:
    sys.path.insert(0, _plugin_root_dir)

from hash_utils import compute_staged_hash

# Shipping command patterns — preceded by start-of-command context
GIT_SHIPPING_PATTERNS = [
    re.compile(r"(?:^|&&|\|\||;)\s*git\s+commit\b"),
    re.compile(r"(?:^|&&|\|\||;)\s*git\s+push\b"),
    re.compile(r"(?:^|&&|\|\||;)\s*gh\s+pr\s+create\b"),
]

_PUSH_PR_PATTERNS = [
    re.compile(r"(?:^|&&|\|\||;)\s*git\s+push\b"),
    re.compile(r"(?:^|&&|\|\||;)\s*gh\s+pr\s+create\b"),
]

_COMMIT_ALL_FLAG = re.compile(r"\bgit\s+commit\b.*(?:\s-a\b|\s--all\b)")

_SCAN_PASS_WRITE_PATTERN = re.compile(
    r"[>|][^;&|]*(?:^|/)\.scan-pass\b" r"|(?:tee|cp|mv)\s+[^;&|]*(?:^|/)\.scan-pass\b"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_shipping_command(cmd):
    """Check if the command matches any git shipping pattern."""
    return any(p.search(cmd) for p in GIT_SHIPPING_PATTERNS)


def _is_push_or_pr(cmd):
    """Check if the command is a git push or gh pr create."""
    return any(p.search(cmd) for p in _PUSH_PR_PATTERNS)


def _has_all_flag(cmd):
    """Check if git commit has -a or --all flag."""
    return bool(_COMMIT_ALL_FLAG.search(cmd))


def _plugin_root():
    """Return the plugin root directory.

    Validates CLAUDE_PLUGIN_ROOT to prevent path traversal attacks (CWE-73).
    The env var must resolve to a path within a git repository, preventing
    attackers from pointing to arbitrary filesystem locations with forged
    .scan-pass files.
    """
    fallback = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    raw = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if raw:
        resolved = os.path.realpath(raw)
        # CWE-73 mitigation: Only accept paths within a git repository.
        # This prevents pointing to arbitrary directories outside version control.
        if os.path.isdir(resolved):
            try:
                # Check if resolved path is within any git repository
                git_root = _find_git_root(resolved)
                if git_root:
                    # Verify resolved path is within this git repo
                    resolved_abs = os.path.abspath(resolved)
                    git_root_abs = os.path.abspath(git_root)
                    # Check if resolved starts with git_root (is a subpath)
                    if (
                        resolved_abs.startswith(git_root_abs + os.sep)
                        or resolved_abs == git_root_abs
                    ):
                        return resolved
            except (OSError, ValueError):
                pass  # Fall through to return fallback
    return fallback


def _find_git_root(start_path):
    """Walk up from start_path to find .git directory.

    Returns the git repository root path, or None if not found.
    """
    current = os.path.abspath(start_path)
    # Limit traversal to prevent infinite loops (max 50 levels up)
    for _ in range(50):
        if os.path.isdir(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:  # Reached filesystem root
            break
        current = parent
    return None


def _has_matching_scan_pass() -> bool:
    """Check if .scan-pass hash matches current staged changes."""
    scan_pass_path = os.path.join(_plugin_root(), ".scan-pass")
    try:
        if not os.path.isfile(scan_pass_path):
            return False
        with open(scan_pass_path) as f:
            stored_hash = f.read().strip()
        if not stored_hash:
            return False
        current_hash = compute_staged_hash()
        if not current_hash:
            return False  # fail-closed: can't compute hash -> require scan
        return stored_hash == current_hash
    except OSError:
        return False


def _has_scan_pass_for_push() -> bool:
    """For push/PR: check that a .scan-pass file exists (commit already enforced scan)."""
    scan_pass_path = os.path.join(_plugin_root(), ".scan-pass")
    try:
        return os.path.isfile(scan_pass_path)
    except OSError:
        return False


def _build_system_message(cmd):
    """Build the scan instruction based on command type."""
    if _is_push_or_pr(cmd):
        scan_instruction = "scan_diff(ref='origin/HEAD')"
    elif _has_all_flag(cmd):
        scan_instruction = "scan_diff()"
    else:
        scan_instruction = "scan_diff(staged=True)"

    return (
        f"Security scan required before shipping. "
        f"Call {scan_instruction} to scan your changes. "
        f"After scanning:\n"
        f"- If clean (no HIGH/CRITICAL findings): retry the original command.\n"
        f"- If HIGH/CRITICAL findings: fix what you can (move secrets to env vars, "
        f"mask tokens, set debug=False), re-stage, and re-scan.\n"
        f"- If HIGH/CRITICAL findings remain after remediation: present them to the "
        f"user and ask whether to proceed. Do NOT call approve_findings on your own "
        f"- wait for the user to explicitly say to proceed. If the user approves, "
        f"call approve_findings(reason='<quote the user stated reason>') then retry "
        f"the original command.\n"
        f"MEDIUM/LOW/INFO findings can be ignored."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
_MAX_STDIN_BYTES = 1_048_576  # 1MB — hook input is small JSON


def main():
    try:
        raw = sys.stdin.buffer.read(_MAX_STDIN_BYTES).decode("utf-8", errors="replace")
        hook_input = json.loads(raw) if raw.strip() else {}
        # CWE-20: validate structure immediately after parsing.
        # Fail-open on malformed input is intentional — this is a developer-local
        # hook; the CI scanner is the fail-closed second line of defense.
        if not isinstance(hook_input, dict):
            hook_input = {}
    except Exception:
        hook_input = {}

    # Fail-open: wrap all logic so our bugs never block the developer.
    # Design doc: "Must fail open — plugin bugs should never block the developer."
    # The CI scanner runs fail-closed as the second line of defense.
    try:
        tool_input = hook_input.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}

        cmd = tool_input.get("command", "")
        if not isinstance(cmd, str) or not cmd.strip():
            # Not a Bash command or empty — allow
            print(json.dumps({}))
            sys.exit(0)

        # Block Bash writes to .scan-pass (prevent forgery bypass)
        if _SCAN_PASS_WRITE_PATTERN.search(cmd):
            sys.stderr.write(
                json.dumps(
                    {
                        "hookSpecificOutput": {"permissionDecision": "deny"},
                        "systemMessage": (
                            "BLOCKED: Direct writes to .scan-pass are not allowed. "
                            "The scan-pass file is managed by the security scanner. "
                            "Run scan_diff() to scan your code instead."
                        ),
                    }
                )
            )
            sys.exit(2)

        # Check if this is a shipping command
        if not _is_shipping_command(cmd):
            print(json.dumps({}))
            sys.exit(0)

        # For commit: check content hash match. For push/PR: check file exists.
        if _is_push_or_pr(cmd):
            if _has_scan_pass_for_push():
                print(json.dumps({}))
                sys.exit(0)
        elif _has_matching_scan_pass():
            print(json.dumps({}))
            sys.exit(0)

        # Block the command — deny with scan instructions
        system_message = _build_system_message(cmd)

        sys.stderr.write(
            json.dumps(
                {
                    "hookSpecificOutput": {"permissionDecision": "deny"},
                    "systemMessage": system_message,
                }
            )
        )
        sys.exit(2)

    except Exception:
        # Fail open: never block due to our own bugs.
        # CWE-215: use generic message — no exception type or message
        # to avoid leaking internal implementation details.
        print(
            "appsec-hook: fail-open on internal error",
            file=sys.stderr,
        )
        print(json.dumps({}))
        sys.exit(0)


if __name__ == "__main__":
    main()
