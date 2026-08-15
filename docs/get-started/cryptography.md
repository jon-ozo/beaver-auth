# Cryptographic Design

This document describes precisely how beaver-auth uses cryptography: which primitives, which parameters, and why. It exists for anyone evaluating this package for production use — you shouldn't have to read source code to answer "is this actually safe."

Everything here is built on Node's built-in `node:crypto` module only. No third-party cryptographic dependencies.

If you're reporting a vulnerability rather than evaluating the design, see [SECURITY.md](../../SECURITY.md) instead — that's the file with the private disclosure process.

A note before the details: **publishing these parameters is not a risk.** Security should depend on the secrecy of keys and secrets, never on the secrecy of the algorithm or its configuration — this is [Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle), and it's the entire reason well-reviewed primitives like scrypt and HMAC-SHA256 are trustworthy at all. If knowing a cost parameter helped an attacker, that would mean the underlying primitive was broken, not that this document leaked something.

## Password hashing

**Algorithm:** scrypt (`node:crypto`'s built-in `scrypt`), a memory-hard key derivation function — deliberately expensive in both CPU and RAM, which is what makes brute-forcing a stolen hash database costly even with dedicated hardware (unlike a fast general-purpose hash, which GPUs/ASICs chew through quickly).

**Parameters:**

- Cost factor (N): `16384`
- Block size (r): `8`
- Parallelization (p): `1`
- Derived key length: `64` bytes
- Salt: `16` random bytes (`crypto.randomBytes(16)`), unique per password, generated at hash time

**Storage format:** hashes are stored self-describing —

```
scrypt$<cost>$<blockSize>$<parallelization>$<salt>$<derivedKeyHex>
```

Encoding the cost parameters into the stored hash (rather than assuming a fixed global config) means the cost factor can be raised in the future without invalidating every existing password hash — new hashes use the new cost, old ones keep verifying against the cost they were created with, and a migration path (re-hash on next successful login) becomes straightforward.

**Verification:** re-derives a key from the supplied password using the _stored_ record's parameters and salt, then compares the result against the stored derived key using `crypto.timingSafeEqual()` — never `===` or `Buffer.equals()`, which short-circuit on the first differing byte and are themselves a (smaller, but real) timing side-channel.

**Constant-time behavior for nonexistent users and malformed input:** if no user exists for the given email, or the stored hash is malformed, the verification path still performs a full scrypt computation against a static dummy hash before returning failure — so "no such user" and "wrong password" cost approximately the same amount of time. This is deliberately paired with a response-time floor at the endpoint level (see [Enumeration & timing protection](#enumeration--timing-protection) below), since dummy-hashing alone narrows but doesn't eliminate the timing gap.

## Token strategy: why passwords, sessions, and other tokens are hashed differently

Sessions, refresh tokens, verification tokens (email verification, password reset), and MFA challenge tokens are all:

1. Generated as high-entropy random values: `crypto.randomBytes(32)`, hex-encoded (256 bits of entropy).
2. Hashed with **SHA-256** (a fast, general-purpose hash) before being persisted.
3. Looked up by hash — the raw value is never stored, and never used as a database key.

This is a **different algorithm than password hashing, deliberately.** The reason isn't inconsistency — it's that these two things need to resist different attacks:

- A **password** is chosen by a human and often has far less entropy than it looks like (predictable patterns, reused across sites, dictionary-adjacent). A stolen password hash needs to resist _offline guessing_ — which is exactly what a slow, memory-hard KDF like scrypt is for.
- A **session/refresh/verification token** is 256 bits of output from a cryptographically secure random number generator. There is nothing to "guess" — brute-forcing a random 256-bit value is computationally infeasible regardless of hash speed. A fast hash here isn't a weakness; using scrypt for this would just add unnecessary latency with no corresponding security benefit.

The reason to hash these tokens _at all_ (rather than store them as plaintext) is different too: it's not about resisting guessing, it's about limiting blast radius if the database itself is ever compromised (a leaked backup, a misconfigured replica, an insider). A hashed token table gives an attacker with read access to the database nothing directly usable — they'd still need to find a preimage, which SHA-256 makes infeasible even though it's "fast" in the cryptographic sense.

**Single-use enforcement:** verification tokens (email verification, password reset) are deleted from storage _before_ their expiry/hash comparison is evaluated, not after — this closes a race condition where two concurrent requests with the same token could otherwise both succeed. The second concurrent request always sees a already-deleted record.

## JWT signing and verification

**Algorithm:** HMAC-SHA256 (`HS256`) exclusively. The algorithm is not negotiable per-token — `verifyJwtToken` checks the `alg` field in the token's **header** and rejects anything that isn't `HS256`, explicitly guarding against algorithm-confusion attacks (e.g. a token crafted with `alg: none`, or an attempt to have the verifier accept a different algorithm than the one the signer used).

**Secret requirements:** the signing secret must be at least 32 bytes (measured as UTF-8 byte length, not string length or hex-decoded length) — `createJwtToken` throws immediately at construction time if the supplied secret is shorter, rather than silently signing with a weak key.

**Signature verification:** uses `crypto.timingSafeEqual()` to compare the recomputed HMAC against the token's signature, after first checking the two buffers are equal length (an early-return length mismatch is not itself exploitable the way a value mismatch would be, since length is already public information encoded in the token's structure).

**Claims:** every token gets a `jti` (JWT ID, a fresh `randomBytes(32)` value) and standard `iat`/`exp` claims added automatically, regardless of what the caller's payload contains. `jti` exists specifically to support optional revocation (see below).

**Payload sanitization:** the payload is passed through the same [prototype-pollution and resource-limit protections](#input-normalization) used elsewhere in the package before being signed, with JWT-reserved claim names (`iat`, `exp`, `jti`, `nbf`, `iss`, `aud`) stripped from caller-supplied data first, so a caller can't accidentally (or an attacker can't deliberately) override them.

**Revocation:** JWTs are stateless by default — no database check on verification, which is the performance benefit of using JWTs at all. Revocation-before-natural-expiry is **optional**, via an injectable `isJwtRevoked(jti)` check; supplying one re-adds a database read per verified request in exchange for the ability to kill a token immediately (e.g. on logout or account compromise). Without it, the honest trade-off is: keep access token lifetimes short, and rely on refresh-token revocation (below) for anything that needs to actually stop working promptly.

## Refresh token rotation and reuse detection

Refresh tokens follow the same generation/hashing/single-use pattern as other tokens, with one addition: **rotation with theft detection.**

- Each refresh token belongs to a **family** (a random ID established at initial issuance).
- Using a refresh token doesn't delete it — it's marked `used`, and a new `active` token is issued in the same family.
- If a token already marked `used` is ever presented again, that's treated as unambiguous evidence of theft (a legitimate client never reuses a token it already exchanged) — the **entire family** is revoked immediately, including the currently-valid rotated token, forcing full re-authentication.

This means a stolen-and-replayed refresh token doesn't just fail — it triggers a detectable security event (reported through the package's error-reporting hook) and kills the whole session chain, not just the one stolen token.

## TOTP (MFA)

**Algorithm:** RFC 6238 TOTP over HMAC-SHA1, 6 digits, 30-second time step — this matches the standard used by Google Authenticator, Authy, and effectively every TOTP-compatible authenticator app. (SHA-1 here is not a weakness the way it would be for, say, certificate signing — TOTP's construction doesn't rely on SHA-1's collision resistance, only its properties as an HMAC, which remain sound.)

**Secret generation:** `crypto.randomBytes()`, one byte per output character, masked to 5 bits (`byte & 31`) against a 32-symbol base32 alphabet. This is bias-free (32 divides 256 evenly, so masking a uniform random byte produces a uniform 5-bit value) but less bit-efficient than packed base32 encoding — the default 32-character secret carries 160 bits of entropy from 32 bytes of randomness, versus the ~130 bits a tightly-packed encoding would extract from the same 32 bytes. In exchange, the encoding logic is simpler and more obviously correct. 160 bits is far beyond what's needed (typical TOTP implementations use 80–160 bits), so this trade-off costs nothing in practice.

**Clock drift tolerance:** codes are accepted within a ±1 time-step window (i.e. the previous, current, or next 30-second window), to tolerate reasonable clock skew between server and authenticator app. All window offsets are checked unconditionally on every verification attempt — the loop never short-circuits on an early match — specifically so that _which_ offset matched isn't observable via timing.

**Replay protection:** the _specific time-step that matched_ (not simply "the current time-step") is recorded per user after a successful verification, and any future code whose matched step is less than or equal to the last recorded step is rejected — even if it's cryptographically valid. This closes the window where a captured/shoulder-surfed code could otherwise be replayed for the remainder of its 30-second validity.

## Enumeration & timing protection

Registration, login, and password-reset endpoints are designed so that response **shape** and response **timing** are both independent of whether a given account exists. The full design (including the response-floor mechanism and its trade-offs) is written up in detail here: _[Why Your Login Response Time Is a Security Leak](https://dev.to/obie/why-your-login-response-time-is-a-security-leak-5fij)_ — rather than duplicate it, the short version: every branch of these flows converges to the same response shape, performs comparable real work, and is padded to a configurable minimum response time (`responseFloorMs`) before returning.

## Input normalization

All external input passed into cryptographically-relevant flows (registration, login, JWT payloads) is run through an internal normalization pass before use, which:

- Strips `__proto__`, `constructor`, and `prototype` keys at every nesting level, closing prototype-pollution injection paths.
- Enforces a maximum traversal depth and a maximum processed-node count, so a maliciously deep or wide payload can't consume unbounded CPU/memory during parsing (a class of resource-exhaustion attack that pure `JSON.parse` doesn't protect against on its own).
- Coerces non-finite numbers (`NaN`, `Infinity`) to `null`, so they can't silently propagate into logic that assumes a well-formed number.
- Detects and breaks reference cycles, so a circular payload can't cause infinite traversal.

## How to verify these claims yourself

Every property described above has a corresponding automated test — don't take this document's word for it. Rather than trust prose, read (or run) these directly:

| Claim                                                                                        | Test file                                                                                                       | What to look for                                                                                                                |
| -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Password hash format, salt uniqueness, correct/incorrect verification                        | `apps/test-app/crypto.test.ts`                                                                                  | `hashPassword / verifyPassword` describe block                                                                                  |
| Passwords aren't silently truncated at any length boundary                                   | `apps/test-app/crypto.test.ts`                                                                                  | The test explicitly marked `REGRESSION GUARD` for the 128-char boundary                                                         |
| Constant-time comparison, dummy-hash path for nonexistent users                              | `apps/test-app/login.test.ts`                                                                                   | "gives the SAME response shape for a nonexistent user and a wrong password"                                                     |
| Session/refresh/verification tokens are never stored or looked up by raw value, only by hash | `apps/test-app/session.test.ts`, `packages/core/test/token.test.ts`, `packages/core/test/refresh-token.test.ts` | Tests asserting the raw token is absent from the adapter's storage keys                                                         |
| Verification tokens are single-use, including under concurrent redemption                    | `apps/test-app/token.test.ts`                                                                                   | "single-use" test in the `create / consume` describe block                                                                      |
| JWT algorithm-confusion defense (rejects tampered/unsupported `alg`)                         | `apps/test-app/token.test.ts`                                                                                   | "rejects a token with an unsupported/tampered algorithm header"                                                                 |
| JWT secret length enforcement (32-byte UTF-8 minimum)                                        | `apps/test-app/token.test.ts`                                                                                   | "rejects a secret under 32 bytes"                                                                                               |
| Refresh token rotation and theft-triggered family revocation                                 | `apps/test-app/refresh-token.test.ts`, `apps/test-app/login.test.ts`                                            | "reusing an already-rotated token triggers reuse detection and revokes the WHOLE family"                                        |
| TOTP drift window (±1 step) and replay rejection of an already-used step                     | `apps/test-app/mfa.test.ts`, `apps/test-app/login.test.ts`                                                      | "accepts a code from one step in the past or future"; "rejects replaying the same TOTP code across two separate MFA challenges" |
| Enumeration-safe response shape and timing floor, registration and login                     | `apps/test-app/register.test.ts`, `apps/test-app/login.test.ts`                                                 | "enumeration protection" and "response floor" describe blocks                                                                   |
| Prototype-pollution stripping, depth/node resource limits, cycle detection                   | `apps/test-app/normalize-payload.test.ts`                                                                       | Full file — this is the input-normalization layer directly                                                                      |

To run the full suite yourself:

```bash
pnpm install
pnpm test
```

As of this writing, that's 238 tests, all run against real source (not mocked implementations of the package's own logic) — the only things mocked are the storage adapter and outbound network calls (OAuth token/profile endpoints), both of which are legitimately external to what's being tested.

## Known limitations

Being upfront about what this design does _not_ solve:

- **`LocalTaskDispatcher` and the default `MemoryStore` rate limiter are single-instance only.** Both use in-process state and are not safe for serverless deployments or any horizontally-scaled deployment with more than one running instance — in those environments, background email dispatch is not guaranteed to complete, and rate limits are effectively per-instance rather than global. Both accept pluggable, interface-compatible replacements (a queue-backed `TaskDispatcher`, a Redis-backed `RateLimitStore`) for anyone who needs correctness at scale; neither ships built-in, since the right backing service is deployment-specific.
- **JWT access tokens can't be revoked before expiry without opting into the `isJwtRevoked` check**, which trades away most of the "stateless" performance benefit of using JWTs in the first place. Short access-token lifetimes plus refresh-token-family revocation is the recommended default posture instead.
- **scrypt's cost parameters are a deliberate trade-off, not a universal constant.** The shipped defaults balance security and latency for a typical web server; anyone deploying under significant memory constraints (e.g. certain serverless tiers) should benchmark actual hash time under their real memory allocation, since a memory-starved scrypt call doesn't fail gracefully — it fails slowly.
- **A compromised adapter implementation compromises everything downstream of it.** beaver-auth's cryptographic design assumes the `AuthRepoAdapter`/`AuthSessionAdapter` implementation it's given faithfully stores and returns what it's asked to — nothing here can protect against, for example, an adapter that logs raw tokens on the way through, or a database connection that isn't encrypted in transit. Adapter implementations are outside this package's control and its threat model.

If any of this doesn't hold up the way it's described, or you find a gap this document doesn't mention, please [report it](../../SECURITY.md) — that's exactly the kind of finding this document exists to invite.
