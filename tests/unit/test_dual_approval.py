"""Unit tests for session_kill channel naming and dual_approval service."""

from __future__ import annotations

import pytest

from bastion.session_kill import _kill_channel


class TestKillChannel:
    """Tests for _kill_channel."""

    def test_returns_prefixed_name(self):
        """_kill_channel must return the correct prefixed channel name."""
        assert _kill_channel("abc-123") == "bastion:session:kill:abc-123"

    def test_different_ids_produce_different_channels(self):
        """Different session IDs must produce different channel names."""
        assert _kill_channel("id-1") != _kill_channel("id-2")

    def test_empty_id(self):
        """An empty session ID must still produce a valid channel name."""
        assert _kill_channel("") == "bastion:session:kill:"


@pytest.mark.asyncio
class TestDualApprovalService:
    """Tests for the dual_approval service functions."""

    async def test_create_request_persisted(self, db_session, admin_user):
        """create_dual_approval_request must persist a DualApprovalRequest."""
        from sqlalchemy import select

        from bastion.dual_approval import create_dual_approval_request
        from bastion.models import DualApprovalRequest, DualApprovalStatus

        req = await create_dual_approval_request(
            db_session,
            initiated_by=admin_user,
            action_type="admin.user.delete",
            action_description="Delete user alice",
            action_payload={"user_id": "abc"},
        )

        result = await db_session.execute(
            select(DualApprovalRequest).where(DualApprovalRequest.id == req.id)
        )
        stored = result.scalar_one()
        assert stored.status == DualApprovalStatus.PENDING
        assert stored.action_type == "admin.user.delete"
        assert stored.initiated_by_user_id == admin_user.id

    async def test_is_dual_approval_required_false_when_disabled(self, db_session):
        """is_dual_approval_required must return False when setting is disabled."""
        from bastion.dual_approval import is_dual_approval_required

        result = await is_dual_approval_required(db_session)
        assert result is False

    async def test_approve_request_changes_status(self, db_session, admin_user):
        """approve_dual_approval_request must set status to APPROVED."""
        from bastion.auth import hash_password
        from bastion.dual_approval import (
            approve_dual_approval_request,
            create_dual_approval_request,
        )
        from bastion.models import DualApprovalStatus, User, UserRole, UserStatus

        # Create a second admin to approve
        second_admin = User(
            username="second_admin",
            email="second@example.com",
            hashed_password=hash_password("pw"),
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        db_session.add(second_admin)
        await db_session.flush()

        req = await create_dual_approval_request(
            db_session,
            initiated_by=admin_user,
            action_type="test.action",
            action_description="Test",
            action_payload={},
        )

        approved = await approve_dual_approval_request(db_session, req.id, second_admin)
        assert approved.status == DualApprovalStatus.APPROVED
        assert approved.reviewed_by_user_id == second_admin.id

    async def test_self_approval_raises_permission_error(self, db_session, admin_user):
        """The initiating admin must not be able to approve their own request."""
        from bastion.dual_approval import (
            approve_dual_approval_request,
            create_dual_approval_request,
        )

        req = await create_dual_approval_request(
            db_session,
            initiated_by=admin_user,
            action_type="test.action",
            action_description="Test",
            action_payload={},
        )

        with pytest.raises(PermissionError, match="cannot approve their own"):
            await approve_dual_approval_request(db_session, req.id, admin_user)

    async def test_approve_nonexistent_request_raises(self, db_session, admin_user):
        """Approving a non-existent request must raise ValueError."""
        from bastion.dual_approval import approve_dual_approval_request

        with pytest.raises(ValueError, match="not found"):
            await approve_dual_approval_request(db_session, "nonexistent-id", admin_user)

    async def test_reject_request_changes_status(self, db_session, admin_user):
        """reject_dual_approval_request must set status to REJECTED."""
        from bastion.auth import hash_password
        from bastion.dual_approval import (
            create_dual_approval_request,
            reject_dual_approval_request,
        )
        from bastion.models import DualApprovalStatus, User, UserRole, UserStatus

        second_admin = User(
            username="rejector",
            email="rejector@example.com",
            hashed_password=hash_password("pw"),
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        db_session.add(second_admin)
        await db_session.flush()

        req = await create_dual_approval_request(
            db_session,
            initiated_by=admin_user,
            action_type="test.action",
            action_description="Test",
            action_payload={},
        )

        rejected = await reject_dual_approval_request(
            db_session, req.id, second_admin, note="Not approved"
        )
        assert rejected.status == DualApprovalStatus.REJECTED
        assert rejected.review_note == "Not approved"
