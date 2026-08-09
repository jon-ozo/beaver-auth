# Security Policy

Beaver-Auth handles authentication — passwords, sessions, tokens, and MFA — for whoever installs it. If you find a vulnerability, how you report it matters as much as what you found. Please read this before opening anything publicly.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.** A public issue is a public disclosure — it gives anyone running an affected version a head start on exploiting it before a fix ships.

Instead, please report privately using one of these channels:

- **GitHub Security Advisories (preferred):** open a [private security advisory](../../security/advisories/new) on this repository. This lets us discuss the issue, prepare a fix, and coordinate disclosure timing directly with you, with GitHub's tooling handling the private communication.

### What to include

The more of this you can provide, the faster a fix can move:

- A clear description of the vulnerability and its impact (what can an attacker actually do?)
- Steps to reproduce, or a minimal proof-of-concept
- The affected version(s)
- Whether you believe it's already being exploited in the wild
- Your assessment of severity, if you have one (informal is fine)

### What to expect

- **Acknowledgment within 3 business days.** If you haven't heard back by then, please follow up — it's possible the report didn't reach us.
- We'll work with you to understand the issue, and let you know our assessment and rough timeline once we've confirmed it.
- We'll credit you in the advisory and release notes when the fix ships, unless you'd prefer to stay anonymous — just let us know your preference in the report.
- We ask for a **coordinated disclosure window** before any public writeup or talk about the vulnerability, so users have a chance to update. 90 days is a reasonable default unless we agree on something different together — we're not trying to sit on reports indefinitely, just to give people time to patch.

## Scope

In scope:

- The `packages/core` package itself — password hashing, session/token generation and validation, JWT handling, MFA (TOTP), OAuth (PKCE) flow, rate limiting, and the payload normalization/validation layer.
- The `createBeaverAuth()` factory and its dependency wiring.

Generally out of scope (but let us know anyway if you're unsure — we'd rather hear it than have you sit on it):

- Vulnerabilities in a specific adapter implementation you or someone else wrote against `AuthRepoAdapter`/`AuthSessionAdapter`, unless the interface itself makes a secure implementation impossible.
- Vulnerabilities that require an already-compromised database, server, or environment variables (e.g. "if you already have my DB, you can read password hashes" is expected — that's why they're hashed, not encrypted-and-reversible).
- Denial-of-service that requires resources far beyond what's realistic for an attacker (e.g. a purely theoretical complexity bound with no practical exploit).
- Missing rate limiting on a route the package doesn't own — Beaver-Auth ships an optional rate limiter (`RateLimiterEngine`/`checkAuthRateLimit`); whether it's actually wired into a given route is the consuming application's responsibility, documented as such.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## A note on this package's design

A few things worth knowing if you're evaluating beaver-auth's security model before reporting something:

- Built exclusively on Node's built-in `node:crypto` — no third-party cryptographic dependencies, by design.
- Registration, login, and password-reset responses are enumeration-safe: response shape and timing (via a configurable floor) are designed not to reveal whether an account exists.
- Sessions, refresh tokens, verification tokens, and MFA challenge tokens are stored **hashed**, never in plaintext.
- Refresh tokens rotate on use, with reuse detection that revokes the entire token family if a already-rotated token is replayed.
- `LocalTaskDispatcher` and the default `MemoryStore` rate limiter are explicitly single-instance/non-serverless-safe by design — this is documented, not a bug, but worth knowing before reporting it as one.

If something here doesn't hold up the way it's described, that's exactly the kind of report we want — please tell us.

Thank you for helping keep beaver-auth and the people who depend on it safe.
