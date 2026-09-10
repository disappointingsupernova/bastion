# Security Policy

## Supported Versions

Only the latest release on the `main` branch receives security fixes. We do not backport patches to older releases.

| Version | Supported |
|---|---|
| Latest (`main`) | ✅ |
| Older releases | ❌ |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub issues.**

If you discover a security vulnerability in Bastion, please report it privately so it can be addressed before public disclosure.

### How to report

Report vulnerabilities via **GitHub's private vulnerability reporting**:

1. Go to [https://github.com/disappointingsupernova/bastion/security/advisories/new](https://github.com/disappointingsupernova/bastion/security/advisories/new)
2. Fill in the details of the vulnerability
3. Submit — this creates a private advisory visible only to the maintainers

Alternatively, email the maintainer directly. Include as much detail as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any proof-of-concept code
- Your suggested fix, if you have one

### What to expect

- **Acknowledgement** within 48 hours
- **Initial assessment** within 5 business days
- **Fix and coordinated disclosure** within 90 days of the report, depending on severity and complexity

We follow [responsible disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We will credit you in the release notes unless you prefer to remain anonymous.

---

## Security Design

Bastion is designed with security as a first-class concern. Key properties:

- Both APIs are Unix socket only — no TCP ports are exposed
- SSH certificates expire after 8 hours and can be revoked instantly via KRL
- All secrets are encrypted at rest (Fernet / AES-128-CBC + HMAC-SHA256)
- Session recordings are encrypted with `age` (X25519 asymmetric encryption)
- Bcrypt cost factor 12 for all password hashes
- Full audit trail of every action in the database
- Heuristic anomaly detection with configurable alerting

See [docs/security.md](docs/security.md) for the full security model and threat mitigations.

---

## Scope

The following are **in scope** for vulnerability reports:

- Authentication and authorisation bypasses
- Privilege escalation (user → admin, user → root)
- Remote code execution
- SQL injection or ORM bypass
- Secrets exposure (CA keys, tokens, passwords)
- Session recording decryption without the private key
- Certificate forgery or KRL bypass
- Denial of service via the API

The following are **out of scope**:

- Vulnerabilities requiring physical access to the bastion host
- Vulnerabilities in third-party dependencies (report those upstream)
- Social engineering attacks
- Issues in documentation only
