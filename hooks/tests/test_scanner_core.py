"""Tests for scanner_core.py — parse_findings, format_findings, URL validation, API call."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add plugin dir to path so we can import scanner_core
_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from scanner_core import format_findings, parse_findings


# ---------------------------------------------------------------------------
# parse_findings
# ---------------------------------------------------------------------------
class TestParseFindings:
    def test_valid_json_block(self):
        raw = '```json\n[{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQL injection"}]\n```'
        result = parse_findings(raw)
        assert len(result) == 1
        assert result[0]["cwe"] == 89
        assert result[0]["severity"] == "HIGH"

    def test_multiple_findings(self):
        raw = '```json\n[{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQLi"}, {"cwe": 79, "severity": "MEDIUM", "line": 20, "explanation": "XSS"}]\n```'
        result = parse_findings(raw)
        assert len(result) == 2

    def test_no_json_block(self):
        raw = "No vulnerabilities found in this code."
        result = parse_findings(raw)
        assert result == []

    def test_malformed_json(self):
        raw = "```json\n{broken json\n```"
        result = parse_findings(raw)
        assert result == []

    def test_empty_findings_list(self):
        raw = "```json\n[]\n```"
        result = parse_findings(raw)
        assert result == []

    def test_filters_cwe_zero(self):
        raw = '```json\n[{"cwe": 0, "severity": "INFO", "line": 1, "explanation": "no issue"}, {"cwe": 89, "severity": "HIGH", "line": 5, "explanation": "real"}]\n```'
        result = parse_findings(raw)
        assert len(result) == 1
        assert result[0]["cwe"] == 89

    def test_filters_cwe_none(self):
        raw = '```json\n[{"cwe": null, "severity": "INFO", "line": 1, "explanation": "no cwe"}]\n```'
        result = parse_findings(raw)
        assert result == []

    def test_surrounding_text(self):
        raw = 'Here is the analysis:\n\n```json\n[{"cwe": 79, "severity": "HIGH", "line": 3, "explanation": "XSS"}]\n```\n\nPlease fix these issues.'
        result = parse_findings(raw)
        assert len(result) == 1
        assert result[0]["cwe"] == 79


# ---------------------------------------------------------------------------
# format_findings
# ---------------------------------------------------------------------------
class TestFormatFindings:
    def test_no_findings(self):
        result = format_findings([], "app.py")
        assert result == "SCAN app.py: clean, no findings."

    def test_single_finding(self):
        findings = [
            {"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQL injection"}
        ]
        result = format_findings(findings, "app.py")
        assert "SCAN app.py: 1 finding(s)" in result
        assert "HIGH CWE-89 L10: SQL injection" in result

    def test_severity_sorting(self):
        findings = [
            {"cwe": 79, "severity": "LOW", "line": 20, "explanation": "minor"},
            {"cwe": 89, "severity": "CRITICAL", "line": 10, "explanation": "critical"},
            {"cwe": 22, "severity": "HIGH", "line": 15, "explanation": "important"},
        ]
        result = format_findings(findings, "app.py")
        lines = result.split("\n")
        # CRITICAL should come before HIGH, which comes before LOW
        assert "CRITICAL" in lines[1]
        assert "HIGH" in lines[2]
        assert "LOW" in lines[3]

    def test_has_secret_flag(self):
        findings = [
            {
                "cwe": 798,
                "severity": "CRITICAL",
                "line": 5,
                "explanation": "hardcoded secret",
                "has_secret": True,
            }
        ]
        result = format_findings(findings, "secrets.py")
        assert "[SECRET]" in result

    def test_tainted_references(self):
        findings = [
            {
                "cwe": 89,
                "severity": "HIGH",
                "line": 10,
                "explanation": "SQLi",
                "tainted_function_references": ["get_user_input", "build_query"],
            }
        ]
        result = format_findings(findings, "db.py")
        assert "tainted: get_user_input, build_query" in result

    def test_no_tainted_references(self):
        findings = [
            {
                "cwe": 89,
                "severity": "HIGH",
                "line": 10,
                "explanation": "SQLi",
                "tainted_function_references": [],
            }
        ]
        result = format_findings(findings, "db.py")
        assert "tainted" not in result

    def test_missing_fields_use_defaults(self):
        findings = [{"cwe": 89}]
        result = format_findings(findings, "app.py")
        assert "UNKNOWN CWE-89 L?" in result


# ---------------------------------------------------------------------------
# URL validation (call_appsec_api checks)
# ---------------------------------------------------------------------------
class TestURLValidation:
    def test_http_non_localhost_raises(self):
        """Non-HTTPS, non-localhost URL raises RuntimeError."""
        import scanner_core

        original_url = scanner_core.APPSEC_API_URL
        try:
            scanner_core.APPSEC_API_URL = "http://evil.com/api/v1"
            with patch("scanner_core.get_auth_header", return_value="Bearer fake"):
                with pytest.raises(RuntimeError, match="HTTPS"):
                    scanner_core.call_appsec_api("code")
        finally:
            scanner_core.APPSEC_API_URL = original_url

    def test_http_localhost_allowed(self):
        """HTTP with localhost hostname does not raise HTTPS error.

        It will fail on connection since there's no server, but it should
        NOT raise the HTTPS validation error.
        """
        import scanner_core

        original_url = scanner_core.APPSEC_API_URL
        try:
            scanner_core.APPSEC_API_URL = "http://localhost:8001/api/v1"
            with patch("scanner_core.get_auth_header", return_value="Bearer fake"):
                # Should raise a connection error, NOT a RuntimeError about HTTPS
                with pytest.raises(Exception) as exc_info:
                    scanner_core.call_appsec_api("code")
                assert "HTTPS" not in str(exc_info.value)
        finally:
            scanner_core.APPSEC_API_URL = original_url

    def test_http_evil_localhost_rejected(self):
        """S-4: http://evil-localhost.com is NOT treated as localhost."""
        import scanner_core

        original_url = scanner_core.APPSEC_API_URL
        try:
            scanner_core.APPSEC_API_URL = "http://evil-localhost.com/api/v1"
            with patch("scanner_core.get_auth_header", return_value="Bearer fake"):
                with pytest.raises(RuntimeError, match="HTTPS"):
                    scanner_core.call_appsec_api("code")
        finally:
            scanner_core.APPSEC_API_URL = original_url


# ---------------------------------------------------------------------------
# call_appsec_api happy path
# ---------------------------------------------------------------------------
class TestCallAppsecApiHappyPath:
    def test_sends_correct_payload_and_returns_raw_response(self):
        """Verify: URL, auth header, timeout, payload, and return value."""
        import scanner_core

        original_url = scanner_core.APPSEC_API_URL
        try:
            scanner_core.APPSEC_API_URL = "https://moose.armis.com/api/v1"

            mock_response = MagicMock()
            mock_response.json.return_value = {"raw_response": "```json\n[]\n```"}
            mock_response.raise_for_status = MagicMock()

            with patch(
                "scanner_core.get_auth_header", return_value="Bearer test-token"
            ):
                with patch(
                    "scanner_core.httpx.post", return_value=mock_response
                ) as mock_post:
                    result = scanner_core.call_appsec_api("print('hello')")

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args.kwargs["json"] == {
                "code": "print('hello')",
                "mode": "fast",
            }
            assert call_args.kwargs["headers"] == {"Authorization": "Bearer test-token"}
            assert call_args.kwargs["timeout"] == 120.0
            assert "scan/fast" in call_args.args[0]
            assert result == "```json\n[]\n```"
        finally:
            scanner_core.APPSEC_API_URL = original_url
