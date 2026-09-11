"""Unit tests for audit log integrity chain — HMAC signing and chain verification."""

from __future__ import annotations

import pytest

from bastion.audit import (
    _compute_integrity_hash,
    _sanitise_detail,
    audit,
    verify_audit_chain,
)
from bastion.models import AuditLog


class TestSanitiseDetail:
    """Tests for _sanitise_detail."""

    def test_string_values_preserved(self):
        """Short string values must pass through unchanged."""
        result = _sanitise_detail({"key": "value"})
        assert result == {"key": "value"}

    def test_long_string_truncated(self):
        """String values exceeding 512 chars must be truncated."""
        long_val = "x" * 600
        result = _sanitise_detail({"key": long_val})
        assert len(result["key"]) == 512

    def test_numeric_values_preserved(self):
        """Integer, float, and bool values must pass through unchanged."""
        result = _sanitise_detail({"i": 42, "f": 3.14, "b": True, "n": None})
        assert result == {"i": 42, "f": 3.14, "b": True, "n": None}

    def test_nested_dict_serialised(self):
        """Nested dicts must be serialised and truncated if needed."""
        result = _sanitise_detail({"nested": {"a": 1}})
        assert result["nested"] == {"a": 1}

    def test_non_serialisable_replaced(self):
        """Non-JSON-serialisable values must be replaced with a placeholder."""
        result = _sanitise_detail({"obj": object()})
        assert result["obj"] == "<non-serialisable>"

    def test_oversized_payload_truncated(self):
        """A detail dict whose JSON exceeds 4096 bytes must be replaced with a truncation marker."""
        big = {f"key_{i}": "x" * 100 for i in range(50)}
        result = _sanitise_detail(big)
        assert result.get("_truncated") is True
        assert "_original_keys" in result


class TestComputeIntegrityHash:
    """Tests for _compute_integrity_hash."""

    def _make_entry(self, **kwargs) -> AuditLog:
        defaults = {
            "id": "test-id-1",
            "action": "test.action",
            "user_id": None,
            "resource_type": None,
            "resource_id": None,
            "detail": None,
            "ip_address": None,
            "success": True,
            "node_id": None,
        }
        defaults.update(kwargs)
        return AuditLog(**defaults)

    def test_genesis_entry_produces_hash(self):
        """The first entry (no previous hash) must produce a non-empty hash."""
        entry = self._make_entry()
        h = _compute_integrity_hash(entry, "secret", None)
        assert len(h) == 64  # SHA-256 hex digest

    def test_different_previous_hash_changes_output(self):
        """Changing the previous hash must change the computed hash."""
        entry = self._make_entry()
        h1 = _compute_integrity_hash(entry, "secret", "prev-hash-a")
        h2 = _compute_integrity_hash(entry, "secret", "prev-hash-b")
        assert h1 != h2

    def test_different_secret_changes_output(self):
        """Changing the secret key must change the computed hash."""
        entry = self._make_entry()
        h1 = _compute_integrity_hash(entry, "secret-a", None)
        h2 = _compute_integrity_hash(entry, "secret-b", None)
        assert h1 != h2

    def test_same_inputs_deterministic(self):
        """The same inputs must always produce the same hash."""
        entry = self._make_entry()
        h1 = _compute_integrity_hash(entry, "secret", "prev")
        h2 = _compute_integrity_hash(entry, "secret", "prev")
        assert h1 == h2

    def test_changed_action_changes_hash(self):
        """Modifying the action field must change the hash."""
        e1 = self._make_entry(action="action.a")
        e2 = self._make_entry(action="action.b")
        h1 = _compute_integrity_hash(e1, "secret", None)
        h2 = _compute_integrity_hash(e2, "secret", None)
        assert h1 != h2


@pytest.mark.asyncio
class TestAuditIntegrityChain:
    """Integration tests for the full audit chain via the audit() function."""

    async def test_single_entry_has_integrity_hash(self, db_session):
        """A single audit entry must have a non-null integrity_hash."""
        entry = await audit(db_session, "test.action", success=True)
        assert entry.integrity_hash is not None
        assert len(entry.integrity_hash) == 64

    async def test_chain_of_two_entries_valid(self, db_session):
        """Two sequential entries must form a valid chain."""
        await audit(db_session, "action.one", success=True)
        await audit(db_session, "action.two", success=False)

        valid, count, broken_id = await verify_audit_chain(db_session)
        assert valid is True
        assert count == 2
        assert broken_id is None

    async def test_chain_of_ten_entries_valid(self, db_session):
        """Ten sequential entries must all verify correctly."""
        for i in range(10):
            await audit(db_session, f"action.{i}", success=True)

        valid, count, broken_id = await verify_audit_chain(db_session)
        assert valid is True
        assert count == 10

    async def test_tampered_entry_breaks_chain(self, db_session):
        """Modifying an entry's action after writing must break the chain."""
        await audit(db_session, "action.one", success=True)
        entry2 = await audit(db_session, "action.two", success=True)
        await audit(db_session, "action.three", success=True)

        # Tamper with the middle entry
        entry2.action = "tampered.action"
        await db_session.flush()

        valid, count, broken_id = await verify_audit_chain(db_session)
        assert valid is False
        assert broken_id == entry2.id

    async def test_empty_chain_is_valid(self, db_session):
        """An empty audit log must report as valid with zero entries checked."""
        valid, count, broken_id = await verify_audit_chain(db_session)
        assert valid is True
        assert count == 0
        assert broken_id is None

    async def test_second_entry_chains_to_first(self, db_session):
        """The second entry's hash must depend on the first entry's hash."""
        e1 = await audit(db_session, "action.one", success=True)
        e2 = await audit(db_session, "action.two", success=True)

        # The second hash must differ from the first
        assert e1.integrity_hash != e2.integrity_hash

    async def test_detail_included_in_hash(self, db_session):
        """Two entries identical except for detail must have different hashes."""
        e1 = await audit(db_session, "action", success=True, detail={"x": 1})
        e2 = await audit(db_session, "action", success=True, detail={"x": 2})
        assert e1.integrity_hash != e2.integrity_hash
