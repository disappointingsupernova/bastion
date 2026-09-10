# Agents

This file describes the conventions, constraints, and context that AI coding agents must follow when working on this project.

---

## Project Overview

Bastion is a self-hosted SSH bastion/jumphost service written in Python. It runs on Ubuntu and provides:

- SSH certificate authority with short-lived cert issuance and KRL-based revocation
- Two FastAPI services (`bastion-api`, `bastion-admin`) communicating over Unix sockets only
- Celery + Redis background workers
- Session recording in asciinema v2 format, encrypted with `age`
- Remote server provisioning over SSH
- Heuristic anomaly detection and multi-channel alerting
- SQLAlchemy ORM with SQLite (default) or PostgreSQL (HA mode)

See [README.md](README.md) for the full overview and [docs/](docs/) for detailed documentation.

---

## Language

All code, comments, docstrings, log messages, commit messages, and documentation must use **British English** spelling.

- `authorise` not `authorize`
- `serialise` not `serialize`
- `colour` not `color`
- `behaviour` not `behavior`
- `initialise` not `initialize`

---

## Repository Layout

```
bastion/          Shared library — models, db, crypto, audit, auth, anomaly, alerting, proxy, provisioning
bastion_api/      User-facing FastAPI service (Unix socket: /opt/bastion/run/bastion-api.sock)
bastion_admin/    Admin FastAPI service (Unix socket: /opt/bastion/run/bastion-admin.sock)
cli/              bastion and bastion-admin CLI tools
workers/          Celery tasks
migrations/       Alembic database migrations
scripts/          install.sh, update.sh
docs/             Detailed documentation
tests/            pytest test suite
  unit/           Unit tests (no I/O, no DB)
  integration/    Integration tests (in-memory SQLite, ASGI test client)
```

---

## Code Standards

### Style
- Follow PEP 8. Maximum line length: 100 characters.
- Use `ruff` for linting and formatting. Run `ruff check . --fix` and `ruff format .` before committing.
- Use `mypy` for type checking. Run `mypy bastion bastion_api bastion_admin cli workers --ignore-missing-imports`. Zero errors required.
- Every function and method must have a docstring.
- No bare `except:` clauses — catch specific exceptions.
- No unused imports. No commented-out code.

### Types
- Use `X | None` not `Optional[X]` (Python 3.10+ union syntax).
- Use `StrEnum` not `(str, Enum)`.
- Use `datetime.UTC` not `timezone.utc`.
- Annotate all function parameters and return types.

### Logging
- Use `structlog` throughout — never `print()` or the stdlib `logging` module directly.
- Import loggers with `from bastion.logging import get_logger; log = get_logger(__name__)`.
- Log at appropriate levels: DEBUG for internal state, INFO for normal operations, WARNING for recoverable issues, ERROR for failures.
- Never log secrets, tokens, passwords, or private keys at any level.
- All log messages must be full English sentences with relevant context fields.

### Database
- SQLAlchemy ORM only — no raw SQL strings.
- All schema changes via Alembic migrations in `migrations/versions/`.
- Every model must have `created_at` and `updated_at` timestamps via `TimestampMixin`.
- Soft-delete pattern for users and servers — never hard-delete.
- Use distinct variable names for successive query results in the same scope to avoid mypy type confusion.

---

## Security — Non-Negotiable

- Every API endpoint must require authentication. The only unauthenticated route is `/health`.
- All audit log entries must be written before the action is performed, and again after with the result.
- SSH certificates must never be written to disk unencrypted — return via API response only.
- Passwords must be hashed with bcrypt at cost factor ≥ 12.
- All secrets stored in the database must be encrypted with Fernet before storage.
- Input validation on every endpoint via Pydantic models.
- Rate limiting on all authentication endpoints.
- Never log secrets, keys, passwords, or tokens.

---

## Commits

- Every commit must be atomic — one logical change per commit.
- Commit messages must be in the imperative mood, British English, concise.
- Never commit `.env` files, secrets, keys, or the `.amazonq/` directory.
- The `.amazonq/` directory is gitignored and must never be committed.

Good examples:
```
Add rate limiting to the certificate issuance endpoint
Fix mypy: handle asyncssh bytes|str|None stdout type in provisioning
Remove unused Optional import from audit module
```

Bad examples:
```
fixed stuff
WIP
updates
```

---

## Testing

- Tests live in `tests/unit/` (pure logic, no I/O) and `tests/integration/` (ASGI client, in-memory SQLite).
- Run with `pytest tests/ -v`.
- All tests must pass before committing.
- Do not add tests unless explicitly requested — but do not remove existing tests.
- Integration tests use the fixtures in `tests/conftest.py` — use `api_client`, `admin_client`, `admin_user`, `regular_user`, `admin_token`, `user_token`.
- Unauthenticated requests to protected endpoints return `401`, not `403`. `403` is for authenticated-but-unauthorised.

---

## CI

Three GitHub Actions workflows run on every push and PR:

| Workflow | What it checks |
|---|---|
| `ci.yml` | ruff lint, ruff format, mypy, pytest (Python 3.11 + 3.12) |
| `security.yml` | pip-audit, CodeQL, Bandit SAST |
| `release.yml` | Triggered on `v*` tags — builds sdist and creates GitHub release |

All three must pass before merging to `main`.

---

## Dependencies

- Do not add new dependencies without good reason.
- `age` is a system binary called via `subprocess` — it is not a Python package.
- `asyncssh` is used for all SSH operations — `paramiko` is not used.
- `python-jose` lacks complete type stubs — use typed intermediate variables when calling `jwt.encode`/`jwt.decode` rather than `# type: ignore` on return statements.
- `pydantic-settings` reads required fields (e.g. `secret_key`) from the environment at runtime — `Settings()` calls without arguments are correct and should be suppressed with `# type: ignore[call-arg]` if mypy complains.

---
