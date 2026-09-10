"""Shared pytest fixtures for the Bastion test suite."""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Set test environment before any application imports
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-use-only-32chars")
os.environ.setdefault("DB_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("ENVIRONMENT", "development")

from bastion.db import Base, get_db
from bastion_admin.main import app as admin_app
from bastion_api.main import app as api_app

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """Create an in-memory SQLite engine for each test function."""
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine) -> AsyncSession:
    """Provide a transactional test database session that rolls back after each test."""
    factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(scope="function")
async def api_client(db_session: AsyncSession) -> AsyncClient:
    """Return an AsyncClient for the user-facing API with the test DB injected."""
    api_app.dependency_overrides[get_db] = lambda: db_session
    async with AsyncClient(
        transport=ASGITransport(app=api_app),
        base_url="http://test",
    ) as client:
        yield client
    api_app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def admin_client(db_session: AsyncSession) -> AsyncClient:
    """Return an AsyncClient for the admin API with the test DB injected."""
    admin_app.dependency_overrides[get_db] = lambda: db_session
    async with AsyncClient(
        transport=ASGITransport(app=admin_app),
        base_url="http://test",
    ) as client:
        yield client
    admin_app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession):
    """Create and return a test admin user."""
    from bastion.auth import hash_password
    from bastion.models import User, UserRole, UserStatus

    user = User(
        username="testadmin",
        email="testadmin@example.com",
        hashed_password=hash_password("test-password-123"),
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def regular_user(db_session: AsyncSession):
    """Create and return a test regular user."""
    from bastion.auth import hash_password
    from bastion.models import User, UserRole, UserStatus

    user = User(
        username="testuser",
        email="testuser@example.com",
        hashed_password=hash_password("test-password-123"),
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def auditor_user(db_session: AsyncSession):
    """Create and return a test auditor user."""
    from bastion.auth import hash_password
    from bastion.models import User, UserRole, UserStatus

    user = User(
        username="testauditor",
        email="testauditor@example.com",
        hashed_password=hash_password("test-password-123"),
        role=UserRole.AUDITOR,
        status=UserStatus.ACTIVE,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def read_only_user(db_session: AsyncSession):
    """Create and return a test read-only user."""
    from bastion.auth import hash_password
    from bastion.models import User, UserRole, UserStatus

    user = User(
        username="testreadonly",
        email="testreadonly@example.com",
        hashed_password=hash_password("test-password-123"),
        role=UserRole.READ_ONLY,
        status=UserStatus.ACTIVE,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def test_server(db_session: AsyncSession):
    """Create and return a test server."""
    from bastion.models import OsFamily, Server, ServerStatus

    server = Server(
        hostname="test.example.com",
        display_name="Test Server",
        ssh_port=22,
        os_family=OsFamily.DEBIAN,
        status=ServerStatus.ACTIVE,
    )
    db_session.add(server)
    await db_session.flush()
    return server


@pytest_asyncio.fixture
async def server_access(db_session: AsyncSession, regular_user, test_server):
    """Grant regular_user access to test_server."""
    from bastion.models import ServerAccess

    access = ServerAccess(
        user_id=regular_user.id,
        server_id=test_server.id,
        allow_sudo=False,
        remote_username="testuser",
    )
    db_session.add(access)
    await db_session.flush()
    return access


@pytest.fixture
def admin_token(admin_user) -> str:
    """Return a valid JWT access token for the test admin user."""
    from bastion.auth import create_access_token

    return create_access_token(admin_user.id, admin_user.username, admin_user.role.value)


@pytest.fixture
def user_token(regular_user) -> str:
    """Return a valid JWT access token for the test regular user."""
    from bastion.auth import create_access_token

    return create_access_token(regular_user.id, regular_user.username, regular_user.role.value)


@pytest.fixture
def auditor_token(auditor_user) -> str:
    """Return a valid JWT access token for the test auditor user."""
    from bastion.auth import create_access_token

    return create_access_token(
        auditor_user.id, auditor_user.username, auditor_user.role.value
    )


@pytest.fixture
def read_only_token(read_only_user) -> str:
    """Return a valid JWT access token for the test read-only user."""
    from bastion.auth import create_access_token

    return create_access_token(
        read_only_user.id, read_only_user.username, read_only_user.role.value
    )
