"""Unit tests for suppression.py — .armisignore parser and directive matcher."""

import os
import sys
from unittest.mock import patch

import pytest

_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from suppression import (
    ArmisIgnoreConfig,
    _derive_category,
    _finding_matches_config,
    _parse_armisignore_lines,
    apply_suppressions,
    find_git_root,
    is_path_excluded,
    load_armisignore,
)


# ---------------------------------------------------------------------------
# Category A: Parse correctness
# ---------------------------------------------------------------------------
class TestParseArmisignoreLines:
    def test_empty_file(self):
        config = _parse_armisignore_lines([])
        assert config == ArmisIgnoreConfig()

    def test_comments_ignored(self):
        lines = ["# this is a comment\n", "  # indented comment\n", "\n"]
        config = _parse_armisignore_lines(lines)
        assert config == ArmisIgnoreConfig()

    def test_cwe_directive(self):
        config = _parse_armisignore_lines(["cwe:798\n", "cwe:89\n"])
        assert config.cwes == [798, 89]

    def test_severity_directive(self):
        config = _parse_armisignore_lines(["severity:LOW\n", "severity:info\n"])
        assert config.severities == ["LOW", "INFO"]

    def test_category_directive(self):
        config = _parse_armisignore_lines(["category:secrets\n", "category:SAST\n"])
        assert config.categories == ["secrets", "sast"]

    def test_rule_directive(self):
        config = _parse_armisignore_lines(["rule:ARMIS-001\n"])
        assert config.rule_ids == ["ARMIS-001"]

    def test_file_pattern(self):
        config = _parse_armisignore_lines(["vendor/\n", "*.test.js\n"])
        assert config.file_patterns == ["vendor/", "*.test.js"]

    def test_reason_suffix_stripped(self):
        config = _parse_armisignore_lines(["cwe:798 -- hardcoded credentials\n"])
        assert config.cwes == [798]

    def test_whitespace_handling(self):
        config = _parse_armisignore_lines(["  cwe:79  \n", "  \n"])
        assert config.cwes == [79]

    def test_invalid_cwe_warns_and_skips(self):
        with patch("suppression.logger") as mock_logger:
            config = _parse_armisignore_lines(["cwe:abc\n", "cwe:89\n"])
        assert config.cwes == [89]
        mock_logger.warning.assert_called_once()

    def test_utf8_bom_handled(self):
        # BOM is handled by utf-8-sig in load_armisignore; here test that
        # a BOM-prefixed line still works if it leaks through
        config = _parse_armisignore_lines(["﻿cwe:798\n"])
        # The BOM character makes it not match "cwe:" prefix, so it becomes a pattern
        # This is fine — the real BOM handling is in load_armisignore using utf-8-sig
        assert config.cwes == [] or config.file_patterns

    def test_truncation_at_1000_lines(self):
        lines = [f"cwe:{i}\n" for i in range(1, 1100)]
        with patch("suppression.logger") as mock_logger:
            config = _parse_armisignore_lines(lines)
        assert len(config.cwes) == 1000
        mock_logger.warning.assert_called_once()

    def test_mixed_directives(self):
        lines = [
            "# Suppress secrets\n",
            "cwe:798\n",
            "severity:LOW\n",
            "category:secrets\n",
            "vendor/\n",
            "rule:SKIP-001\n",
        ]
        config = _parse_armisignore_lines(lines)
        assert config.cwes == [798]
        assert config.severities == ["LOW"]
        assert config.categories == ["secrets"]
        assert config.file_patterns == ["vendor/"]
        assert config.rule_ids == ["SKIP-001"]


# ---------------------------------------------------------------------------
# Category B: Directive matching
# ---------------------------------------------------------------------------
class TestFindingMatchesConfig:
    def test_cwe_match(self):
        config = ArmisIgnoreConfig(cwes=[798])
        finding = {"cwe": 798, "severity": "CRITICAL", "has_secret": True}
        assert _finding_matches_config(finding, config) == "cwe:798"

    def test_cwe_mismatch(self):
        config = ArmisIgnoreConfig(cwes=[798])
        finding = {"cwe": 89, "severity": "HIGH", "has_secret": False}
        assert _finding_matches_config(finding, config) is None

    def test_severity_match_case_insensitive(self):
        config = ArmisIgnoreConfig(severities=["LOW"])
        finding = {"cwe": 79, "severity": "low", "has_secret": False}
        assert _finding_matches_config(finding, config) == "severity:LOW"

    def test_category_secrets_match(self):
        config = ArmisIgnoreConfig(categories=["secrets"])
        finding = {"cwe": 798, "severity": "HIGH", "has_secret": True}
        assert _finding_matches_config(finding, config) == "category:secrets"

    def test_category_sast_match(self):
        config = ArmisIgnoreConfig(categories=["sast"])
        finding = {"cwe": 89, "severity": "HIGH", "has_secret": False}
        assert _finding_matches_config(finding, config) == "category:sast"

    def test_category_no_match(self):
        config = ArmisIgnoreConfig(categories=["secrets"])
        finding = {"cwe": 89, "severity": "HIGH", "has_secret": False}
        assert _finding_matches_config(finding, config) is None

    def test_rule_skipped(self):
        config = ArmisIgnoreConfig(rule_ids=["ARMIS-001"])
        finding = {"cwe": 89, "severity": "HIGH", "has_secret": False}
        assert _finding_matches_config(finding, config) is None

    def test_or_logic_first_match_wins(self):
        config = ArmisIgnoreConfig(cwes=[89], severities=["HIGH"])
        finding = {"cwe": 89, "severity": "HIGH", "has_secret": False}
        # CWE is checked first
        assert _finding_matches_config(finding, config) == "cwe:89"

    def test_empty_config_no_match(self):
        config = ArmisIgnoreConfig()
        finding = {"cwe": 89, "severity": "HIGH", "has_secret": False}
        assert _finding_matches_config(finding, config) is None


class TestDeriveCategory:
    def test_has_secret_true(self):
        assert _derive_category({"has_secret": True}) == "secrets"

    def test_has_secret_false(self):
        assert _derive_category({"has_secret": False}) == "sast"

    def test_has_secret_missing(self):
        assert _derive_category({}) == "sast"


# ---------------------------------------------------------------------------
# Category B: apply_suppressions
# ---------------------------------------------------------------------------
class TestApplySuppressions:
    def test_empty_findings(self):
        config = ArmisIgnoreConfig(cwes=[798])
        active, suppressed, summary = apply_suppressions([], config)
        assert active == []
        assert suppressed == []
        assert summary["suppressed"] == 0

    def test_empty_config(self):
        findings = [{"cwe": 89, "severity": "HIGH", "has_secret": False}]
        config = ArmisIgnoreConfig()
        active, suppressed, summary = apply_suppressions(findings, config)
        assert active == findings
        assert suppressed == []
        assert summary["active"] == 1

    def test_partial_suppression(self):
        findings = [
            {"cwe": 798, "severity": "CRITICAL", "has_secret": True},
            {"cwe": 89, "severity": "HIGH", "has_secret": False},
        ]
        config = ArmisIgnoreConfig(cwes=[798])
        active, suppressed, summary = apply_suppressions(findings, config)
        assert len(active) == 1
        assert active[0]["cwe"] == 89
        assert len(suppressed) == 1
        assert suppressed[0]["cwe"] == 798
        assert summary["by_directive"] == {"cwe:798": 1}

    def test_all_suppressed(self):
        findings = [
            {"cwe": 79, "severity": "LOW", "has_secret": False},
            {"cwe": 89, "severity": "LOW", "has_secret": False},
        ]
        config = ArmisIgnoreConfig(severities=["LOW"])
        active, suppressed, summary = apply_suppressions(findings, config)
        assert len(active) == 0
        assert len(suppressed) == 2
        assert summary["suppressed"] == 2
        assert summary["by_directive"] == {"severity:LOW": 2}

    def test_summary_counts(self):
        findings = [
            {"cwe": 798, "severity": "CRITICAL", "has_secret": True},
            {"cwe": 89, "severity": "HIGH", "has_secret": False},
            {"cwe": 79, "severity": "LOW", "has_secret": False},
        ]
        config = ArmisIgnoreConfig(cwes=[798], severities=["LOW"])
        active, suppressed, summary = apply_suppressions(findings, config)
        assert summary["total"] == 3
        assert summary["active"] == 1
        assert summary["suppressed"] == 2


# ---------------------------------------------------------------------------
# Category D: Edge cases — path exclusion
# ---------------------------------------------------------------------------
class TestIsPathExcluded:
    def test_trailing_slash_directory_match(self, tmp_path):
        config = ArmisIgnoreConfig(file_patterns=["vendor/"])
        git_root = str(tmp_path)
        file_path = str(tmp_path / "vendor" / "lib.js")
        assert is_path_excluded(file_path, config, git_root) is True

    def test_trailing_slash_no_match(self, tmp_path):
        config = ArmisIgnoreConfig(file_patterns=["vendor/"])
        git_root = str(tmp_path)
        file_path = str(tmp_path / "src" / "app.js")
        assert is_path_excluded(file_path, config, git_root) is False

    def test_fnmatch_pattern(self, tmp_path):
        config = ArmisIgnoreConfig(file_patterns=["*.test.js"])
        git_root = str(tmp_path)
        file_path = str(tmp_path / "app.test.js")
        assert is_path_excluded(file_path, config, git_root) is True

    def test_fnmatch_no_match(self, tmp_path):
        config = ArmisIgnoreConfig(file_patterns=["*.test.js"])
        git_root = str(tmp_path)
        file_path = str(tmp_path / "app.js")
        assert is_path_excluded(file_path, config, git_root) is False

    def test_empty_patterns(self, tmp_path):
        config = ArmisIgnoreConfig(file_patterns=[])
        git_root = str(tmp_path)
        file_path = str(tmp_path / "anything.py")
        assert is_path_excluded(file_path, config, git_root) is False

    def test_directory_exact_match(self, tmp_path):
        config = ArmisIgnoreConfig(file_patterns=["vendor/"])
        git_root = str(tmp_path)
        # The directory itself (without trailing file)
        file_path = str(tmp_path / "vendor")
        assert is_path_excluded(file_path, config, git_root) is True

    def test_nested_directory_match(self, tmp_path):
        config = ArmisIgnoreConfig(file_patterns=["vendor/"])
        git_root = str(tmp_path)
        file_path = str(tmp_path / "vendor" / "sub" / "deep.js")
        assert is_path_excluded(file_path, config, git_root) is True

    def test_basename_pattern_matches_at_any_depth(self, tmp_path):
        config = ArmisIgnoreConfig(file_patterns=["*.test.js"])
        git_root = str(tmp_path)
        file_path = str(tmp_path / "src" / "utils" / "helper.test.js")
        assert is_path_excluded(file_path, config, git_root) is True

    def test_pattern_with_slash_matches_relative_path(self, tmp_path):
        config = ArmisIgnoreConfig(file_patterns=["src/*.js"])
        git_root = str(tmp_path)
        # Matches files under src/
        assert is_path_excluded(str(tmp_path / "src" / "app.js"), config, git_root) is True
        # Also matches deeper (Python fnmatch * crosses / unlike shell glob)
        assert is_path_excluded(str(tmp_path / "src" / "sub" / "app.js"), config, git_root) is True
        # Does NOT match files outside src/
        assert is_path_excluded(str(tmp_path / "lib" / "app.js"), config, git_root) is False


# ---------------------------------------------------------------------------
# Category D: Edge cases — git root and load
# ---------------------------------------------------------------------------
class TestFindGitRoot:
    def test_returns_none_outside_git(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("suppression.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 128
            mock_run.return_value.stdout = ""
            result = find_git_root()
        assert result is None

    def test_resolves_from_file_path(self, tmp_path):
        with patch("suppression.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "/some/repo\n"
            result = find_git_root(from_path=str(tmp_path / "src" / "app.py"))
        assert result == "/some/repo"
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["cwd"] == str(tmp_path / "src")

    def test_no_from_path_uses_process_cwd(self):
        with patch("suppression.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "/cwd/repo\n"
            result = find_git_root()
        assert result == "/cwd/repo"
        assert mock_run.call_args[1]["cwd"] is None


class TestLoadArmisignore:
    def test_missing_file_returns_empty(self, tmp_path):
        config = load_armisignore(str(tmp_path))
        assert config == ArmisIgnoreConfig()

    def test_none_git_root_returns_empty(self):
        config = load_armisignore(None)
        assert config == ArmisIgnoreConfig()

    def test_valid_file_parsed(self, tmp_path):
        armisignore = tmp_path / ".armisignore"
        armisignore.write_text("cwe:798\nseverity:LOW\nvendor/\n")
        config = load_armisignore(str(tmp_path))
        assert config.cwes == [798]
        assert config.severities == ["LOW"]
        assert config.file_patterns == ["vendor/"]

    def test_utf8_bom_file(self, tmp_path):
        armisignore = tmp_path / ".armisignore"
        armisignore.write_bytes(b"\xef\xbb\xbfcwe:798\n")
        config = load_armisignore(str(tmp_path))
        assert config.cwes == [798]
