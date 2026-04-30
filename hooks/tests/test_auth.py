"""Tests for auth.py — JWT authentication provider."""

import base64
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# Add plugin dir to path so we can import auth
_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

import auth
from auth import JWTAuth, get_auth_header, get_auth_status, init_auth


def _make_jwt(exp: float = None, extra_claims: dict = None) -> str:
    """Build a fake JWT with the given exp claim (no real signature)."""
    if exp is None:
        exp = time.time() + 3600  # 1 hour from now
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=")
    claims = {"exp": exp, "sub": "test"}
    if extra_claims:
        claims.update(extra_claims)
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
    signature = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.{signature.decode()}"


# ---------------------------------------------------------------------------
# init_auth
# ---------------------------------------------------------------------------
class TestInitAuth:
    def setup_method(self):
        """Reset module singleton before each test."""
        auth._auth = None

    def test_success_with_both_credentials(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "test-id")
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "test-secret")
        init_auth("https://example.com/api/v1")
        assert auth._auth is not None

    def test_error_when_nothing_set(self, monkeypatch):
        monkeypatch.delenv("ARMIS_CLIENT_ID", raising=False)
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)
        with pytest.raises(RuntimeError, match="No auth credentials"):
            init_auth("https://example.com/api/v1")

    def test_error_when_only_client_id(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "test-id")
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)
        with pytest.raises(RuntimeError, match="ARMIS_CLIENT_SECRET is not set"):
            init_auth("https://example.com/api/v1")

    def test_error_when_only_client_secret(self, monkeypatch):
        monkeypatch.delenv("ARMIS_CLIENT_ID", raising=False)
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "test-secret")
        with pytest.raises(RuntimeError, match="ARMIS_CLIENT_ID is not set"):
            init_auth("https://example.com/api/v1")


# ---------------------------------------------------------------------------
# JWTAuth.exchange
# ---------------------------------------------------------------------------
class TestJWTAuthExchange:
    @pytest.fixture(autouse=True)
    def _set_secret(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret")

    def test_success(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        fake_token = _make_jwt(exp=time.time() + 3600)
        mock_response = MagicMock()
        mock_response.json.return_value = {"token": fake_token, "region": "us1"}
        mock_response.raise_for_status = MagicMock()

        with patch("auth.httpx.post", return_value=mock_response) as mock_post:
            jwt_auth.exchange()

        assert jwt_auth._token == fake_token
        assert jwt_auth._expires_at > time.time()
        mock_post.assert_called_once()

    def test_401_raises_clear_error(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        mock_response = MagicMock()
        mock_response.status_code = 401
        error = __import__("httpx").HTTPStatusError(
            "Unauthorized", request=MagicMock(), response=mock_response
        )
        mock_response.raise_for_status.side_effect = error

        with patch("auth.httpx.post", return_value=mock_response):
            with pytest.raises(RuntimeError, match="invalid client_id/client_secret"):
                jwt_auth.exchange()

    def test_timeout_raises_clear_error(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        with patch(
            "auth.httpx.post",
            side_effect=__import__("httpx").TimeoutException("timed out"),
        ):
            with pytest.raises(RuntimeError, match="connection timeout"):
                jwt_auth.exchange()

    def test_missing_token_key_raises(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        mock_response = MagicMock()
        mock_response.json.return_value = {"region": "us1"}  # no "token" key
        mock_response.raise_for_status = MagicMock()

        with patch("auth.httpx.post", return_value=mock_response):
            with pytest.raises(RuntimeError, match="missing token"):
                jwt_auth.exchange()

    def test_https_enforcement_rejects_http(self):
        jwt_auth = JWTAuth("http://evil.com/api/v1", "id")
        with pytest.raises(RuntimeError, match="HTTPS"):
            jwt_auth.exchange()

    def test_https_allows_localhost(self):
        jwt_auth = JWTAuth("http://localhost:8001/api/v1", "id")
        fake_token = _make_jwt()
        mock_response = MagicMock()
        mock_response.json.return_value = {"token": fake_token, "region": "us1"}
        mock_response.raise_for_status = MagicMock()

        with patch("auth.httpx.post", return_value=mock_response):
            jwt_auth.exchange()
        assert jwt_auth._token == fake_token

    def test_missing_env_secret_raises(self, monkeypatch):
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        with pytest.raises(RuntimeError, match="ARMIS_CLIENT_SECRET is not set"):
            jwt_auth.exchange()


# ---------------------------------------------------------------------------
# JWTAuth.get_header
# ---------------------------------------------------------------------------
class TestJWTAuthGetHeader:
    @pytest.fixture(autouse=True)
    def _set_secret(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret")

    def test_first_call_triggers_exchange(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        fake_token = _make_jwt(exp=time.time() + 3600)
        mock_response = MagicMock()
        mock_response.json.return_value = {"token": fake_token, "region": "us1"}
        mock_response.raise_for_status = MagicMock()

        with patch("auth.httpx.post", return_value=mock_response) as mock_post:
            header = jwt_auth.get_header()

        assert header == f"Bearer {fake_token}"
        mock_post.assert_called_once()

    def test_cached_token_no_second_exchange(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        fake_token = _make_jwt(exp=time.time() + 3600)
        jwt_auth._token = fake_token
        jwt_auth._expires_at = time.time() + 3600

        with patch("auth.httpx.post") as mock_post:
            header = jwt_auth.get_header()

        assert header == f"Bearer {fake_token}"
        mock_post.assert_not_called()

    def test_expired_token_triggers_reexchange(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        jwt_auth._token = "old-token"
        jwt_auth._expires_at = time.time() - 100  # already expired

        new_token = _make_jwt(exp=time.time() + 3600)
        mock_response = MagicMock()
        mock_response.json.return_value = {"token": new_token, "region": "us1"}
        mock_response.raise_for_status = MagicMock()

        with patch("auth.httpx.post", return_value=mock_response) as mock_post:
            header = jwt_auth.get_header()

        assert header == f"Bearer {new_token}"
        mock_post.assert_called_once()


# ---------------------------------------------------------------------------
# JWTAuth._parse_jwt_exp
# ---------------------------------------------------------------------------
class TestParseJWTExp:
    def test_valid_jwt(self):
        exp = time.time() + 7200
        token = _make_jwt(exp=exp)
        result = JWTAuth._parse_jwt_exp(token)
        assert abs(result - exp) < 1  # floating point tolerance

    def test_malformed_jwt_not_3_parts(self):
        with pytest.raises(ValueError, match="3 dot-separated"):
            JWTAuth._parse_jwt_exp("only.two")

    def test_invalid_base64(self):
        with pytest.raises(Exception):
            JWTAuth._parse_jwt_exp("header.!!!invalid!!!.sig")

    def test_missing_exp_claim(self):
        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=")
        payload = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=")
        sig = base64.urlsafe_b64encode(b"sig").rstrip(b"=")
        token = f"{header.decode()}.{payload.decode()}.{sig.decode()}"
        with pytest.raises(KeyError):
            JWTAuth._parse_jwt_exp(token)

    def test_exp_in_past_raises(self):
        token = _make_jwt(exp=time.time() - 100)
        with pytest.raises(ValueError, match="in the past"):
            JWTAuth._parse_jwt_exp(token)

    def test_exp_too_far_future_raises(self):
        token = _make_jwt(exp=time.time() + 100_000)
        with pytest.raises(ValueError, match="more than 24h"):
            JWTAuth._parse_jwt_exp(token)


# ---------------------------------------------------------------------------
# Module-level functions
# ---------------------------------------------------------------------------
class TestModuleFunctions:
    def setup_method(self):
        auth._auth = None

    def test_get_auth_header_before_init_raises(self):
        with pytest.raises(RuntimeError, match="not initialized"):
            get_auth_header()

    def test_get_auth_status_before_init(self):
        assert get_auth_status() == "not initialized"

    def test_get_auth_status_after_init(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "test-id")
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "test-secret")
        init_auth("https://example.com/api/v1")
        assert get_auth_status() == "not yet exchanged"


# ---------------------------------------------------------------------------
# JWTAuth.status()
# ---------------------------------------------------------------------------
class TestJWTAuthStatus:
    def test_status_not_yet_exchanged(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        assert jwt_auth.status() == "not yet exchanged"

    def test_status_expired(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        jwt_auth._token = "old-token"
        jwt_auth._expires_at = time.time() - 100
        assert jwt_auth.status() == "expired"

    def test_status_valid_with_remaining_time(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        jwt_auth._token = _make_jwt(exp=time.time() + 1800)
        jwt_auth._expires_at = time.time() + 1800  # 30 minutes
        status = jwt_auth.status()
        assert "valid" in status
        assert "30m" in status or "29m" in status


# ---------------------------------------------------------------------------
# JWTAuth.exchange — non-JSON response
# ---------------------------------------------------------------------------
class TestExchangeNonJsonResponse:
    @pytest.fixture(autouse=True)
    def _set_secret(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret")

    def test_non_json_200_raises_clear_error(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.side_effect = __import__("json").JSONDecodeError(
            "Expecting value", "<html>", 0
        )

        with patch("auth.httpx.post", return_value=mock_response):
            with pytest.raises(RuntimeError, match="invalid response"):
                jwt_auth.exchange()
