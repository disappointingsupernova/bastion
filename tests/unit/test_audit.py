"""Unit tests for the audit logging module."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from bastion.audit import audit
from bastion.models import AuditLog


@pytest.mark.asyncio
class TestAuditLog:
    """Tests for the audit() function."""

    async def test_creates_audit_log_entry(self, db_session):
        """audit() must persist an AuditLog record to the database."""
        entry = await audit(db_session, "test.action", success=True)
        assert entry.id is not None
        assert entry.action == "test.action"
        assert entry.success is True

    async def test_entry_is_queryable(self, db_session):
        """The persisted audit entry must be retrievable by action."""
        await audit(db_session, "user.login", success=True, ip_address="1.2.3.4")

        result = await db_session.execute(
            select(AuditLog).where(AuditLog.action == "user.login")
        )
        rows = result.scalars().all()
        assert len(rows) == 1
        assert rows[0].ip_address == "1.2.3.4"

    async def test_detail_serialised_as_json(self, db_session):
        """The detail dict must be stored as a JSON string."""
        detail = {"hostname": "srv.example.com", "reason": "test"}
        entry = await audit(db_session, "server.connect", success=True, detail=detail)
        assert entry.detail is not None
        assert json.loads(entry.detail) == detail

    async def test_null_detail_stored_as_none(self, db_session):
        """Omitting detail must store None, not the string 'null'."""
        entry = await audit(db_session, "test.action", success=False)
        assert entry.detail is None

    async def test_all_optional_fields_stored(self, db_session):
        """All optional fields must be persisted correctly."""
        entry = await audit(
            db_session,
            action="admin.user.create",
            success=True,
            user_id="user-abc",
            resource_type="user",
            resource_id="user-xyz",
            detail={"username": "alice"},
            ip_address="10.0.0.1",
            node_id="node-1",
        )
        assert entry.user_id == "user-abc"
        assert entry.resource_type == "user"
        assert entry.resource_id == "user-xyz"
        assert entry.ip_address == "10.0.0.1"
        assert entry.node_id == "node-1"

    async def test_failure_recorded_correctly(self, db_session):
        """A failed action must be stored with success=False."""
        entry = await audit(db_session, "auth.login", success=False)
        assert entry.success is False

    async def test_multiple_entries_independent(self, db_session):
        """Multiple audit calls must produce independent records."""
        await audit(db_session, "action.one", success=True)
        await audit(db_session, "action.two", success=False)

        result = await db_session.execute(select(AuditLog))
        rows = result.scalars().all()
        assert len(rows) == 2
        actions = {r.action for r in rows}
        assert actions == {"action.one", "action.two"}
