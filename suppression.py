"""
.armisignore file parser and finding suppression logic.

Reads suppression directives from {git_root}/.armisignore and applies them
to scan findings. Fail-open: any parse/IO error leaves findings active.
"""

import fnmatch
import logging
import os
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger("appsec-mcp")

_MAX_ARMISIGNORE_LINES = 1000


@dataclass
class ArmisIgnoreConfig:
    file_patterns: list[str] = field(default_factory=list)
    cwes: list[int] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)


def find_git_root(from_path: str | None = None) -> str | None:
    """Return the git repository root, or None if not in a git repo.

    Re-resolved on every call to handle long-running server processes
    where the user may switch between repositories.
    """
    cwd = os.path.dirname(from_path) if from_path and os.path.isabs(from_path) else None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=cwd,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def load_armisignore(git_root: str | None) -> ArmisIgnoreConfig:
    """Read and parse .armisignore from git root. Returns empty config on failure."""
    if not git_root:
        return ArmisIgnoreConfig()
    path = os.path.join(git_root, ".armisignore")
    try:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return ArmisIgnoreConfig()
    return _parse_armisignore_lines(lines)


def _parse_armisignore_lines(lines: list[str]) -> ArmisIgnoreConfig:
    """Parse .armisignore lines into config. Pure logic, no I/O."""
    if len(lines) > _MAX_ARMISIGNORE_LINES:
        logger.warning(
            ".armisignore has %d lines, truncating to %d",
            len(lines),
            _MAX_ARMISIGNORE_LINES,
        )
        lines = lines[:_MAX_ARMISIGNORE_LINES]

    config = ArmisIgnoreConfig()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Strip inline reason: "cwe:798 -- hardcoded creds"
        if " -- " in line:
            line = line.split(" -- ", 1)[0].strip()

        if line.startswith("cwe:"):
            value = line[4:]
            try:
                config.cwes.append(int(value))
            except ValueError:
                logger.warning(".armisignore: invalid cwe directive: %r", line)
        elif line.startswith("severity:"):
            config.severities.append(line[9:].strip().upper())
        elif line.startswith("category:"):
            config.categories.append(line[9:].strip().lower())
        elif line.startswith("rule:"):
            config.rule_ids.append(line[5:].strip())
        else:
            if line in ("*", "**", "**/*"):
                logger.warning(
                    ".armisignore: broad pattern %r may exclude all files from scanning",
                    line,
                )
            config.file_patterns.append(line)

    return config


def is_path_excluded(file_path: str, config: ArmisIgnoreConfig, git_root: str) -> bool:
    """Check if a file path matches any exclusion pattern in the config.

    Trailing-slash patterns (e.g. "vendor/") match any path starting with that prefix.
    Other patterns use fnmatch against the path relative to git root.
    """
    if not config.file_patterns:
        return False

    rel_path = os.path.relpath(file_path, git_root)
    # Normalize to forward slashes for consistent matching
    rel_path = rel_path.replace(os.sep, "/")

    for pattern in config.file_patterns:
        if pattern.endswith("/"):
            # Directory prefix match
            prefix = pattern  # e.g. "vendor/"
            if rel_path.startswith(prefix) or rel_path == prefix.rstrip("/"):
                return True
        elif "/" in pattern:
            # Pattern contains path separator — match against full relative path
            if fnmatch.fnmatch(rel_path, pattern):
                return True
        else:
            # No path separator — match against basename (like .gitignore)
            if fnmatch.fnmatch(os.path.basename(rel_path), pattern):
                return True

    return False


def _derive_category(finding: dict) -> str:
    """Derive category from finding fields: has_secret=True → "secrets", else "sast"."""
    return "secrets" if finding.get("has_secret") else "sast"


def _finding_matches_config(finding: dict, config: ArmisIgnoreConfig) -> str | None:
    """Check if a finding matches any directive in config (OR logic).

    Returns the matching directive string, or None if no match.
    rule: directives are silently skipped (fast-scan model has no rule ID).
    """
    # CWE match
    finding_cwe = finding.get("cwe")
    if finding_cwe and finding_cwe in config.cwes:
        return f"cwe:{finding_cwe}"

    # Severity match
    finding_severity = (finding.get("severity") or "").upper()
    if finding_severity and finding_severity in config.severities:
        return f"severity:{finding_severity}"

    # Category match
    finding_category = _derive_category(finding)
    if finding_category in config.categories:
        return f"category:{finding_category}"

    return None


def apply_suppressions(
    findings: list[dict], config: ArmisIgnoreConfig
) -> tuple[list[dict], list[dict], dict]:
    """Apply .armisignore directives to findings.

    Returns:
        (active, suppressed, summary) where summary is:
        {"total": N, "active": X, "suppressed": Y, "by_directive": {"cwe:798": 2, ...}}
    """
    if not findings or _is_empty_config(config):
        return (
            findings,
            [],
            {"total": len(findings), "active": len(findings), "suppressed": 0, "by_directive": {}},
        )

    active = []
    suppressed = []
    by_directive: dict[str, int] = {}

    for finding in findings:
        directive = _finding_matches_config(finding, config)
        if directive:
            suppressed.append(finding)
            by_directive[directive] = by_directive.get(directive, 0) + 1
        else:
            active.append(finding)

    summary = {
        "total": len(findings),
        "active": len(active),
        "suppressed": len(suppressed),
        "by_directive": by_directive,
    }
    return active, suppressed, summary


def _is_empty_config(config: ArmisIgnoreConfig) -> bool:
    """Check if config has no finding-level directives (file_patterns/rule_ids irrelevant)."""
    return not (config.cwes or config.severities or config.categories)
