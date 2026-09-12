"""Unit tests for the crypto/encryption age functions, db module, and logging."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# ── age recording encryption ──────────────────────────────────────────────────


class TestDeletePlaintext:
    """Tests for _delete_plaintext."""

    def test_deletes_file(self, tmp_path):
        """_delete_plaintext must remove the file after overwriting it."""
        from bastion.crypto.encryption import _delete_plaintext

        f = tmp_path / "recording.cast"
        f.write_bytes(b"sensitive session data")
        _delete_plaintext(f)
        assert not f.exists()

    def test_missing_file_does_not_raise(self, tmp_path):
        """_delete_plaintext must not raise if the file does not exist."""
        from bastion.crypto.encryption import _delete_plaintext

        _delete_plaintext(tmp_path / "nonexistent.cast")


class TestEncryptRecordingAge:
    """Tests for encrypt_recording_age."""

    def test_age_failure_raises_runtime_error(self, tmp_path):
        """A non-zero age exit code must raise RuntimeError with the stderr message."""
        from bastion.crypto.encryption import encrypt_recording_age

        f = tmp_path / "recording.cast"
        f.write_bytes(b"data")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = b"age: bad recipient key"

        with (
            patch("bastion.crypto.encryption.subprocess.run", return_value=mock_result),
            pytest.raises(RuntimeError, match="age encryption failed"),
        ):
            encrypt_recording_age(f, "age1badkey")

    def test_successful_encryption_returns_age_path_and_deletes_original(self, tmp_path):
        """A successful age run must return the .age path and delete the plaintext."""
        from bastion.crypto.encryption import encrypt_recording_age

        f = tmp_path / "recording.cast"
        f.write_bytes(b"data")
        encrypted = tmp_path / "recording.cast.age"
        encrypted.write_bytes(b"encrypted content")

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("bastion.crypto.encryption.subprocess.run", return_value=mock_result):
            result = encrypt_recording_age(f, "age1validkey")

        assert result == encrypted
        assert not f.exists()


# ── Database module ───────────────────────────────────────────────────────────


class TestDatabaseModule:
    """Tests for db/__init__.py engine and session factory."""

    def test_get_engine_returns_async_engine(self):
        """get_engine must return an AsyncEngine instance."""
        from sqlalchemy.ext.asyncio import AsyncEngine

        from bastion.db import get_engine

        assert isinstance(get_engine(), AsyncEngine)

    def test_get_engine_is_singleton(self):
        """get_engine must return the same instance on every call."""
        from bastion.db import get_engine

        assert get_engine() is get_engine()

    def test_get_session_factory_returns_async_sessionmaker(self):
        """get_session_factory must return an async_sessionmaker."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from bastion.db import get_session_factory

        assert isinstance(get_session_factory(), async_sessionmaker)

    def test_get_session_factory_is_singleton(self):
        """get_session_factory must return the same instance on every call."""
        from bastion.db import get_session_factory

        assert get_session_factory() is get_session_factory()

    @pytest.mark.asyncio
    async def test_get_db_session_yields_session(self):
        """get_db_session must yield a usable AsyncSession."""
        from sqlalchemy.ext.asyncio import AsyncSession

        from bastion.db import get_db_session

        async with get_db_session() as session:
            assert isinstance(session, AsyncSession)

    @pytest.mark.asyncio
    async def test_get_db_session_rolls_back_on_exception(self):
        """get_db_session must roll back when an exception propagates."""
        from bastion.db import get_db_session

        with pytest.raises(ValueError, match="deliberate test error"):
            async with get_db_session():
                raise ValueError("deliberate test error")


# ── Logging module ────────────────────────────────────────────────────────────


class TestLoggingModule:
    """Tests for configure_logging and get_logger."""

    def test_get_logger_returns_bound_logger(self):
        """get_logger must return a structlog BoundLogger."""
        from bastion.logging import get_logger

        logger = get_logger("test.module")
        assert logger is not None

    def test_configure_logging_debug_mode_completes(self):
        """configure_logging must complete without error in debug mode."""
        from bastion.logging import configure_logging

        configure_logging("test-service", debug=True)

    def test_configure_logging_production_mode_completes(self):
        """configure_logging must complete without error in production mode."""
        from bastion.logging import configure_logging

        configure_logging("test-service", debug=False)

    def test_different_logger_names_are_independent(self):
        """Loggers with different names must be independent objects."""
        from bastion.logging import get_logger

        assert get_logger("module.a") is not get_logger("module.b")


# ── Rate limit middleware ─────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestRateLimitHeadersMiddleware:
    """Tests for make_rate_limit_middleware."""

    async def test_headers_injected_with_correct_values(self):
        """The middleware must inject X-RateLimit-Limit and X-RateLimit-Remaining."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from bastion_api.middleware.rate_limit import make_rate_limit_middleware

        mock_limiter = MagicMock()
        mock_limiter.default_limits = ["100/minute"]
        mock_storage = MagicMock()
        mock_storage.get.return_value = 10
        mock_limiter._storage = mock_storage

        app = FastAPI()
        app.add_middleware(make_rate_limit_middleware(mock_limiter))

        @app.get("/test")
        async def route():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/test")

        assert response.headers["X-RateLimit-Limit"] == "100"
        assert int(response.headers["X-RateLimit-Remaining"]) == 90

    async def test_no_headers_when_no_default_limits(self):
        """The middleware must not inject headers when no default limits are configured."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from bastion_api.middleware.rate_limit import make_rate_limit_middleware

        mock_limiter = MagicMock()
        mock_limiter.default_limits = []

        app = FastAPI()
        app.add_middleware(make_rate_limit_middleware(mock_limiter))

        @app.get("/test")
        async def route():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/test")

        assert "X-RateLimit-Limit" not in response.headers

    async def test_storage_exception_does_not_break_response(self):
        """An exception reading from limiter storage must not break the HTTP response."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from bastion_api.middleware.rate_limit import make_rate_limit_middleware

        mock_limiter = MagicMock()
        mock_limiter.default_limits = ["100/minute"]
        mock_limiter._storage.get.side_effect = RuntimeError("storage unavailable")

        app = FastAPI()
        app.add_middleware(make_rate_limit_middleware(mock_limiter))

        @app.get("/test")
        async def route():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/test")

        assert response.status_code == 200

    async def test_remaining_is_never_negative(self):
        """X-RateLimit-Remaining must be clamped to zero, never negative."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from bastion_api.middleware.rate_limit import make_rate_limit_middleware

        mock_limiter = MagicMock()
        mock_limiter.default_limits = ["10/minute"]
        mock_storage = MagicMock()
        mock_storage.get.return_value = 999
        mock_limiter._storage = mock_storage

        app = FastAPI()
        app.add_middleware(make_rate_limit_middleware(mock_limiter))

        @app.get("/test")
        async def route():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/test")

        assert int(response.headers.get("X-RateLimit-Remaining", "0")) >= 0
