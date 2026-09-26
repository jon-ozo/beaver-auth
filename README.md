# Beaver-Auth

**Authentication workflows for Node.js that are easy to get subtly wrong, with zero runtime dependencies.**

[![npm](https://img.shields.io/npm/v/@beaver-auth/core)](https://www.npmjs.com/package/@beaver-auth/core)
[![license](https://img.shields.io/npm/l/@beaver-auth/core)](./LICENSE)
[![runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](./package.json)
[![CI](https://github.com/jon-ozo/beaver-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/jon-ozo/beaver-auth/actions)

Beaver-Auth handles the parts of authentication that break quietly: token lifecycles, refresh-token theft, TOTP replay, account enumeration, timing leaks. You keep your framework, your database, and your infrastructure.

```ts
import { createAuth } from '@beaver-auth/core'
import { createMemoryAdapter } from '@beaver-auth/core/testing' // development only

const auth = createAuth({ adapter: createMemoryAdapter() })

await auth.registration.execute({
	email: 'alice@example.com',
	password: 'SecurePassword123',
	profile: { firstName: 'Alice', lastName: 'Johnson' },
})

const login = await auth.login.executePasswordStage(
	{ email: 'alice@example.com', password: 'SecurePassword123' },
	'', // JWT signing secret. Only used when sessionType is 'jwt'.
	undefined, // request context (userAgent, ipAddress)
	{ sessionType: 'session' },
)

console.log(login.status) // 'success-session'
```

That runs as-is. **[Get a real server running in five minutes →](./docs/get-started/quick-start.md)** (Express and Hono, cookie sessions and JWTs.)

## Why Beaver-Auth

**Zero runtime dependencies.** Cryptography and everything else is built on Node.js built-ins. There is no dependency tree between your login endpoint and someone else's compromised package. Check it yourself: `npm view @beaver-auth/core dependencies` prints nothing.

**Attack-resistant by construction.** These behaviors are part of the workflows, not options you have to remember:

- Refresh tokens rotate. Replaying a used token revokes the whole token family.
- TOTP codes cannot be replayed within their time step.
- Registration answers the same way whether or not the email exists, and responses are held to a timing floor.
- Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` unless you turn that off.
- Passwords use scrypt. Session, refresh, and verification tokens are stored only as SHA-256 hashes.

**Verifiable.** The cryptographic design is written down in [`docs/get-started/cryptography.md`](./docs/get-started/cryptography.md), with a table linking each guarantee to the test that enforces it. The suite has [247] tests across [15] files. [A public attack-scenario suite you can run against any auth library is planned.]

**Your architecture stays yours.** Persistence goes through an adapter you implement. Email goes through hooks you provide. HTTP stays in your framework.

## Status

- Version \*\*0.1.4. The API may change before 1.0.
- Maintained by one person. [Independent security audit: not yet done.]
- Found a vulnerability? Please report it privately through [GitHub Security Advisories](https://github.com/jon-ozo/beaver-auth/security/advisories/new). See [SECURITY.md](./SECURITY.md).

## What Beaver-Auth does, and what you still do

| Concern                                                     | Beaver-Auth                                   | You                                                                          |
| ----------------------------------------------------------- | --------------------------------------------- | ---------------------------------------------------------------------------- |
| Password hashing, token hashing and lifecycle               | ✓                                             |                                                                              |
| Session and JWT issuance, refresh rotation, reuse detection | ✓                                             |                                                                              |
| Enumeration-safe responses and timing floors                | ✓                                             |                                                                              |
| Secure cookie defaults                                      | ✓                                             | Keep `Secure` on in production                                               |
| Rate limiting                                               | Provides the limiter and `checkAuthRateLimit` | Call it in your routes and choose the identifier                             |
| Persistence                                                 |                                               | Implement the adapter for your database                                      |
| Email delivery                                              | Calls your hook with a token                  | Send the email                                                               |
| Cleaning up expired records                                 | Provides the purge methods                    | Schedule them                                                                |
| Secrets, proxy and client-IP handling                       |                                               | Yours                                                                        |
| What you return to clients                                  |                                               | Never return the raw `User` object (it holds `passwordHash` and `mfaSecret`) |

The [production checklist](./docs/get-started/quick-start.md#before-you-go-to-production) covers each of these.

## Capabilities

| Capability                               | Status                                                                                        |
| ---------------------------------------- | --------------------------------------------------------------------------------------------- |
| Registration                             | Available                                                                                     |
| Password login                           | Available                                                                                     |
| Cookie sessions                          | Available                                                                                     |
| JWT access tokens with refresh rotation  | Available                                                                                     |
| Email verification                       | Available                                                                                     |
| Password reset                           | Available                                                                                     |
| TOTP multi-factor authentication         | Available [guide coming]                                                                      |
| Rate limiting                            | Building block: you wire it in                                                                |
| OAuth 2.0 (authorization code with PKCE) | Utilities: build the URL, exchange the code, fetch the profile. Linking accounts is up to you |
| Magic links                              | Planned                                                                                       |

## Documentation

- [Installation](./docs/get-started/installation.md)
- [Quick start](./docs/get-started/quick-start.md)
- [Core concepts](./docs/get-started/core-concepts.md)
- [Architecture](./docs/get-started/architecture.md)
- [Cryptography](./docs/get-started/cryptography.md)
- [Contributing](./CONTRIBUTING.md)

## Community

[Discussions link] · [Break Beaver-Auth: public security challenge, coming soon]

## License

[Apache-2.0](./LICENSE)
