#!/usr/bin/env python3
"""
Claude Code PreToolUse Hook -- Protect .scan-pass from forgery.

Fires before Write and Edit tool executions. Denies any attempt to
write or edit a file whose basename is '.scan-pass', preventing
prompt-injection attacks from forging the scan-pass file to bypass
the security gate.
"""

import json
import os
import sys

_MAX_STDIN_BYTES = 1_048_576  # 1MB — hook input is small JSON


def main():
    try:
        raw = sys.stdin.buffer.read(_MAX_STDIN_BYTES).decode("utf-8", errors="replace")
        hook_input = json.loads(raw) if raw.strip() else {}
        if not isinstance(hook_input, dict):
            hook_input = {}
    except Exception:
        hook_input = {}

    # Fail-open: wrap all logic so our bugs never block the developer.
    try:

        tool_input = hook_input.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}

        file_path = tool_input.get("file_path", "")
        if not isinstance(file_path, str) or not file_path.strip():
            print(json.dumps({}))
            sys.exit(0)

        if os.path.basename(file_path) == ".scan-pass":
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

        print(json.dumps({}))
        sys.exit(0)

    except Exception:
        # Fail open: never block due to our own bugs.
        print(
            "appsec-hook: fail-open on internal error",
            file=sys.stderr,
        )
        print(json.dumps({}))
        sys.exit(0)


if __name__ == "__main__":
    main()
