# Contributing

Thank you for your interest in contributing to Bastion. This document covers how to set up a development environment, the standards we hold code to, and the process for submitting changes.

---

## Code of Conduct

Be respectful. Contributions of all kinds are welcome — bug reports, documentation improvements, feature suggestions, and code. Harassment of any kind will not be tolerated.

---

## Development Setup

### Prerequisites

- Python 3.11 or later
- Redis (for running workers locally)
- `age` (`brew install age` / `apt-get install age`)
- `openssh-client` (for `ssh-keygen`)
- Git

### Clone and install

```bash
git clone https://github.com/disappointingsupernova/bastion
cd bastion

python3.11 -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"
```

### Environment

Copy the example environment file and fill in the required values:

```bash
cp .env.example .env
# Edit .env — at minimum set SECRET_KEY
```

Generate a `SECRET_KEY`:

```bash
python3 -c "import secrets; print(secrets.token_hex(64))"
```

### Running the services locally

```bash
# Terminal 1 — user API
uvicorn bastion_api.main:app --uds /tmp/bastion-api.sock

# Terminal 2 — admin API
uvicorn bastion_admin.main:app --uds /tmp/bastion-admin.sock

# Terminal 3 — Celery worker
celery -A workers.celery_app worker --loglevel=debug

# Terminal 4 — Celery beat
celery -A workers.celery_app beat --loglevel=debug
```

---

## Code Standards

### Language

All code, comments, commit messages, log strings, and documentation must use **British English** spelling.

- `authorise` not `authorize`
- `serialise` not `serialize`
- `colour` not `color`
- `behaviour` not `behavior`

### Style

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Maximum line length: 100 characters
- All functions must have a docstring
- No bare `except:` clauses — catch specific exceptions
- No unused imports
- Use `structlog` for all logging — no `print()` statements

### Security

- Never log secrets, keys, passwords, or tokens — at any log level
- Every new API endpoint must require authentication
- Every action must write an audit log entry
- Input validation on every endpoint via Pydantic models
- No raw SQL — SQLAlchemy ORM only

### Commits

- One logical change per commit
- Commit messages in the imperative mood, British English
- Examples:
  - `Add rate limiting to the certificate issuance endpoint`
  - `Fix session recording path when hostname contains dots`
  - `Update anomaly scoring threshold documentation`

---

## Testing

```bash
pytest
```

Tests live in `tests/`. We use `pytest` with `pytest-asyncio` for async tests and `httpx` for API testing.

When adding a new feature, include tests for:
- The happy path
- Authentication/authorisation failures
- Input validation failures
- Any edge cases specific to the feature

---

## Pull Request Process

1. **Fork** the repository and create a branch from `main`
2. **Make your changes** — keep commits atomic
3. **Run the tests** — all tests must pass
4. **Update documentation** — if your change affects behaviour, update the relevant doc in `docs/`
5. **Open a pull request** against `main`

### PR checklist

- [ ] Tests pass
- [ ] New code has docstrings
- [ ] British English throughout
- [ ] Audit logging added for any new actions
- [ ] Documentation updated if behaviour changed
- [ ] No secrets or credentials in the diff
- [ ] Commit messages are clean and atomic

### Review

All PRs require at least one review from a maintainer before merging. We aim to review within 5 business days.

---

## Reporting Bugs

Open a [GitHub issue](https://github.com/disappointingsupernova/bastion/issues/new?template=bug_report.md) using the bug report template.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

---

## Suggesting Features

Open a [GitHub issue](https://github.com/disappointingsupernova/bastion/issues/new?template=feature_request.md) using the feature request template. Describe the use case, not just the implementation.
