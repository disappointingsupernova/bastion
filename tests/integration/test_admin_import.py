"""Integration tests for the admin bulk user import endpoints."""

from __future__ import annotations

import io

import pytest
from httpx import AsyncClient


def _csv_bytes(rows: list[dict]) -> bytes:
    """Build CSV bytes from a list of row dicts."""
    import csv

    buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return buf.getvalue().encode()


@pytest.mark.asyncio
class TestCsvUserImport:
    """Tests for POST /import/users/csv."""

    async def test_valid_csv_creates_users(self, admin_client: AsyncClient, admin_token: str):
        """A valid CSV must create all listed users and report the count."""
        csv_data = _csv_bytes(
            [
                {"username": "import_alice", "email": "import_alice@example.com"},
                {"username": "import_bob", "email": "import_bob@example.com"},
            ]
        )
        response = await admin_client.post(
            "/import/users/csv",
            files={"file": ("users.csv", io.BytesIO(csv_data), "text/csv")},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["created"] == 2
        assert data["skipped"] == 0
        assert data["errors"] == []

    async def test_row_missing_username_is_skipped(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """A row with no username must be skipped and reported in errors."""
        csv_data = _csv_bytes([{"username": "", "email": "noname@example.com"}])
        response = await admin_client.post(
            "/import/users/csv",
            files={"file": ("users.csv", io.BytesIO(csv_data), "text/csv")},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["skipped"] == 1
        assert len(data["errors"]) == 1

    async def test_reserved_username_is_skipped(self, admin_client: AsyncClient, admin_token: str):
        """A row with a reserved username (e.g. root) must be skipped."""
        csv_data = _csv_bytes([{"username": "root", "email": "root@example.com"}])
        response = await admin_client.post(
            "/import/users/csv",
            files={"file": ("users.csv", io.BytesIO(csv_data), "text/csv")},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json()["skipped"] == 1

    async def test_duplicate_username_is_skipped(
        self,
        admin_client: AsyncClient,
        admin_token: str,
        regular_user,
    ):
        """A row whose username already exists must be skipped silently."""
        csv_data = _csv_bytes([{"username": "testuser", "email": "other@example.com"}])
        response = await admin_client.post(
            "/import/users/csv",
            files={"file": ("users.csv", io.BytesIO(csv_data), "text/csv")},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json()["skipped"] == 1

    async def test_invalid_role_falls_back_to_user(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """A row with an unrecognised role must fall back to 'user' and still be created."""
        csv_data = _csv_bytes(
            [
                {"username": "roletest", "email": "roletest@example.com", "role": "superadmin"},
            ]
        )
        response = await admin_client.post(
            "/import/users/csv",
            files={"file": ("users.csv", io.BytesIO(csv_data), "text/csv")},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json()["created"] == 1

    async def test_non_admin_cannot_import(self, admin_client: AsyncClient, user_token: str):
        """A non-admin must receive 403 when attempting a CSV import."""
        csv_data = b"username,email\nalice,alice@example.com\n"
        response = await admin_client.post(
            "/import/users/csv",
            files={"file": ("users.csv", io.BytesIO(csv_data), "text/csv")},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestLdapSync:
    """Tests for POST /import/users/ldap-sync."""

    async def test_ldap_sync_returns_501_when_not_configured(
        self, admin_client: AsyncClient, admin_token: str
    ):
        """LDAP sync must return 501 when LDAP_URL is not configured."""
        response = await admin_client.post(
            "/import/users/ldap-sync",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 501

    async def test_non_admin_cannot_trigger_ldap_sync(
        self, admin_client: AsyncClient, user_token: str
    ):
        """A non-admin must receive 403 when attempting an LDAP sync."""
        response = await admin_client.post(
            "/import/users/ldap-sync",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
