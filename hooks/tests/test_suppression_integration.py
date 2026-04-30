"""Integration tests for suppression wiring in server.py and scanner_core.py."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

# MCP mock setup (same pattern as test_server_helpers.py)
if "mcp.server.fastmcp" not in sys.modules:

    class _ToolError(Exception):
        pass

    _mock_exceptions = MagicMock()
    _mock_exceptions.ToolError = _ToolError
    _mock_fastmcp = MagicMock()
    _mock_fastmcp.exceptions = _mock_exceptions
    _mock_fastmcp.Context = MagicMock()
    sys.modules["mcp"] = MagicMock()
    sys.modules["mcp.server"] = MagicMock()
    sys.modules["mcp.server.fastmcp"] = _mock_fastmcp
    sys.modules["mcp.server.fastmcp.exceptions"] = _mock_exceptions

_ToolError = sys.modules["mcp.server.fastmcp.exceptions"].ToolError

import importlib

if "server" in sys.modules:
    importlib.reload(sys.modules["server"])
import server
from scanner_core import format_findings
from suppression import ArmisIgnoreConfig


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset server state between tests."""
    server._ALLOWED_ROOTS.clear()
    server._last_scan.update(
        {
            "report": "",
            "findings": [],
            "suppressed": [],
            "suppression_summary": {},
            "filename": "",
            "timestamp": None,
            "is_staged_scan": False,
            "scan_hash": "",
        }
    )
    yield
    server._ALLOWED_ROOTS.clear()


# ---------------------------------------------------------------------------
# Category E: _run_scan with suppression
# ---------------------------------------------------------------------------
class TestRunScanSuppression:
    @pytest.mark.asyncio
    async def test_suppresses_matching_findings(self):
        """_run_scan with config suppresses matching CWE findings."""
        raw_response = (
            '```json\n[{"cwe": 798, "severity": "HIGH", "line": 5, '
            '"explanation": "hardcoded secret", "has_secret": true}, '
            '{"cwe": 89, "severity": "HIGH", "line": 10, '
            '"explanation": "SQL injection", "has_secret": false}]\n```'
        )
        config = ArmisIgnoreConfig(cwes=[798])

        with patch("server.call_appsec_api", return_value=raw_response):
            report = await server._run_scan(
                "code", "app.py", config=config
            )

        assert "SQL injection" in report
        assert "hardcoded secret" not in report
        assert "1 suppressed" in report

    @pytest.mark.asyncio
    async def test_no_config_loads_from_git(self):
        """_run_scan with config=None loads .armisignore from git root."""
        raw_response = '```json\n[{"cwe": 89, "severity": "HIGH", "line": 1, "explanation": "SQLi", "has_secret": false}]\n```'

        with patch("server.call_appsec_api", return_value=raw_response):
            with patch("server.find_git_root", return_value=None):
                with patch("server.load_armisignore", return_value=ArmisIgnoreConfig()):
                    report = await server._run_scan("code", "app.py")

        assert "SQLi" in report

    @pytest.mark.asyncio
    async def test_critical_suppression_warning(self):
        """Suppressed CRITICAL emits a warning via logger."""
        raw_response = (
            '```json\n[{"cwe": 798, "severity": "CRITICAL", "line": 5, '
            '"explanation": "hardcoded key", "has_secret": true}]\n```'
        )
        config = ArmisIgnoreConfig(cwes=[798])

        with patch("server.call_appsec_api", return_value=raw_response):
            with patch("server.logger") as mock_logger:
                report = await server._run_scan(
                    "code", "app.py", config=config
                )

        mock_logger.warning.assert_called_once()
        assert "CRITICAL" in mock_logger.warning.call_args[0][0]


# ---------------------------------------------------------------------------
# Category E: scan_file path exclusion
# ---------------------------------------------------------------------------
class TestScanFilePathExclusion:
    def test_is_path_excluded_integration(self, tmp_path):
        """Path exclusion check works end-to-end with parsed .armisignore."""
        armisignore = tmp_path / ".armisignore"
        armisignore.write_text("vendor/\n*.generated.js\n")

        from suppression import is_path_excluded, load_armisignore

        config = load_armisignore(str(tmp_path))

        # vendor/ path excluded
        assert is_path_excluded(str(tmp_path / "vendor" / "lib.py"), config, str(tmp_path))
        # src/ path not excluded
        assert not is_path_excluded(str(tmp_path / "src" / "app.py"), config, str(tmp_path))
        # Generated file excluded
        assert is_path_excluded(str(tmp_path / "bundle.generated.js"), config, str(tmp_path))
        # Normal JS file not excluded
        assert not is_path_excluded(str(tmp_path / "app.js"), config, str(tmp_path))


# ---------------------------------------------------------------------------
# Category E: _cache_scan with suppression data
# ---------------------------------------------------------------------------
class TestCacheScanSuppression:
    def test_stores_suppressed_findings(self, tmp_path, monkeypatch):
        """_cache_scan stores suppressed findings in _last_scan."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        suppressed = [{"cwe": 798, "severity": "HIGH"}]
        summary = {"total": 2, "active": 1, "suppressed": 1, "by_directive": {"cwe:798": 1}}

        server._cache_scan(
            report="1 finding",
            findings=[{"cwe": 89, "severity": "HIGH"}],
            filename="app.py",
            suppressed=suppressed,
            suppression_summary=summary,
        )

        assert server._last_scan["suppressed"] == suppressed
        assert server._last_scan["suppression_summary"] == summary

    def test_suppressed_critical_blocks_scan_pass(self, tmp_path, monkeypatch):
        """Suppressed CRITICAL findings prevent .scan-pass from being written."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        suppressed = [{"cwe": 798, "severity": "CRITICAL"}]

        server._cache_scan(
            report="0 active findings",
            findings=[],
            filename="staged changes",
            is_staged_scan=True,
            scan_hash="abc123",
            suppressed=suppressed,
            suppression_summary={"total": 1, "active": 0, "suppressed": 1, "by_directive": {}},
        )

        scan_pass = tmp_path / ".scan-pass"
        assert not scan_pass.exists()

    def test_suppressed_high_does_not_block_scan_pass(self, tmp_path, monkeypatch):
        """Suppressed HIGH findings do NOT block .scan-pass (only CRITICAL)."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        suppressed = [{"cwe": 89, "severity": "HIGH"}]

        server._cache_scan(
            report="0 active findings",
            findings=[],
            filename="staged changes",
            is_staged_scan=True,
            scan_hash="abc123",
            suppressed=suppressed,
            suppression_summary={"total": 1, "active": 0, "suppressed": 1, "by_directive": {}},
        )

        scan_pass = tmp_path / ".scan-pass"
        assert scan_pass.exists()
        assert scan_pass.read_text() == "abc123"


# ---------------------------------------------------------------------------
# Category E: approve_findings with suppressed CRITICAL
# ---------------------------------------------------------------------------
class TestApproveFindingsSuppressedCritical:
    def test_suppressed_critical_requires_approval(self, tmp_path, monkeypatch):
        """Suppressed CRITICAL findings still require approve_findings."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        server._last_scan.update(
            {
                "findings": [],
                "suppressed": [{"cwe": 798, "severity": "CRITICAL"}],
                "is_staged_scan": True,
                "scan_hash": "hash123",
            }
        )
        with patch("server.compute_staged_hash", return_value="hash123"):
            result = server.do_approve_findings("user accepts risk")

        assert "Approved" in result
        assert (tmp_path / ".scan-pass").exists()

    def test_no_findings_no_suppressed_critical_errors(self):
        """No active HIGH/CRITICAL + no suppressed CRITICAL → error."""
        server._last_scan.update(
            {
                "findings": [],
                "suppressed": [{"cwe": 79, "severity": "LOW"}],
                "is_staged_scan": True,
                "scan_hash": "hash123",
            }
        )
        result = server.do_approve_findings("reason")
        assert "ERROR" in result


# ---------------------------------------------------------------------------
# Category E: format_findings with suppression summary
# ---------------------------------------------------------------------------
class TestFormatFindingsWithSuppression:
    def test_shows_suppression_counts_in_header(self):
        findings = [{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQLi"}]
        summary = {"total": 2, "active": 1, "suppressed": 1, "by_directive": {"cwe:798": 1}}
        result = format_findings(findings, "app.py", suppression_summary=summary)
        assert "1 active, 1 suppressed" in result
        assert "1 by cwe:798" in result

    def test_all_suppressed_shows_zero_active(self):
        summary = {"total": 2, "active": 0, "suppressed": 2, "by_directive": {"severity:LOW": 2}}
        result = format_findings([], "app.py", suppression_summary=summary)
        assert "0 finding(s) (2 suppressed by .armisignore)" in result

    def test_no_suppression_backward_compatible(self):
        findings = [{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQLi"}]
        result = format_findings(findings, "app.py")
        assert "SCAN app.py: 1 finding(s)" in result
        assert "suppressed" not in result

    def test_no_findings_no_suppression(self):
        result = format_findings([], "app.py")
        assert result == "SCAN app.py: clean, no findings."
