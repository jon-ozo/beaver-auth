# Quick start

In about five minutes you will have a running server that registers users, logs them in with a cookie session, and issues JWTs with refresh-token rotation. Everything here uses an in-memory adapter, so there is nothing to set up except Node.

> **Requirements:** Node.js 20 or newer, and `@beaver-auth/core` [0.1.4] or later (the first release with the `@beaver-auth/core/testing` entry point).

## 1. Create a project

```bash
mkdir beaver-demo && cd beaver-demo
npm init -y
npm pkg set type=module
```

Install for the framework you use.

**Express**

```bash
npm install @beaver-auth/core express
npm install -D tsx typescript @types/express @types/node
```

**Hono**

```bash
npm install @beaver-auth/core hono @hono/node-server
npm install -D tsx typescript @types/node
```

## 2. Create `server.ts`

<details open>
<summary><strong>Express</strong></summary>

```ts
import { randomBytes } from 'node:crypto'
import express from 'express'
import { checkAuthRateLimit, createAuth, type User } from '@beaver-auth/core'
import { createMemoryAdapter } from '@beaver-auth/core/testing'

// Signs JWTs. In a real app, load a long random value from your secrets
// manager. Here we generate one per run so nothing sensitive is committed.
const JWT_SECRET = process.env.JWT_SECRET ?? randomBytes(32).toString('hex')

// In-memory storage: perfect for a first run, wrong for production.
const adapter = createMemoryAdapter()

const auth = createAuth({
	adapter,
	middleware: {
		jwtSecret: JWT_SECRET,
		isJwtRevoked: adapter.isJtiRevoked,
		// Cookies are Secure by default. We relax that for http://localhost only.
		cookieOptions: { secure: process.env.NODE_ENV === 'production' },
	},
	// Rate limiting is opt-in and is NOT applied for you: see the login route.
	rateLimiters: {
		login: { algorithm: 'sliding-window', maxRequests: 5, windowMs: 60_000 },
	},
})

const middleware = auth.middleware! // present because `middleware` is configured above

const loginGuard = {
	limiter: auth.rateLimiters.login!, // present because `rateLimiters.login` is configured above
	// One IP's attempts against one email. See the rate limiting guide.
	getIdentifier: ({
		email,
		ipAddress,
	}: {
		email?: string
		ipAddress?: string
	}) => `${ipAddress ?? 'unknown'}:${email ?? 'unknown'}`,
}

const app = express()
app.use(express.json())

app.post('/register', async (req, res) => {
	const { email, password, profile } = req.body ?? {}
	const result = await auth.registration.execute({ email, password, profile })

	switch (result.status) {
		case 'success':
		case 'success-pending-verification':
			return res.status(201).json({ status: result.status })
		case 'validation-error':
			return res
				.status(400)
				.json({ status: result.status, message: result.message })
		case 'email-already-exists':
			return res.status(409).json({ status: result.status })
		default:
			return res.status(500).json({ status: 'system-error' })
	}
})

app.post('/login', async (req, res) => {
	const { email, password } = req.body ?? {}
	// If you run behind a proxy or load balancer, configure Express's
	// `trust proxy` setting, otherwise req.ip is the proxy's address.
	const ipAddress = req.ip

	const limit = await checkAuthRateLimit(loginGuard, { email, ipAddress })
	if (!limit.success) {
		return res
			.status(429)
			.set('Retry-After', String(limit.retryAfter))
			.json({ status: 'too-many-attempts' })
	}

	const result = await auth.login.executePasswordStage(
		{ email, password },
		JWT_SECRET,
		{ userAgent: req.get('user-agent'), ipAddress },
		{ sessionType: 'session' },
	)

	switch (result.status) {
		case 'success-session':
			res.set(
				'Set-Cookie',
				middleware.setSessionCookie(result.token, result.session.expiresAt),
			)
			return res.json({ user: toPublicUser(result.user) })
		case 'mfa-required':
			return res.status(202).json({
				status: result.status,
				mfaChallengeToken: result.mfaChallengeToken,
			})
		case 'unverified':
			return res.status(403).json({ status: result.status })
		case 'invalid-credentials':
			return res.status(401).json({ status: result.status })
		default:
			return res.status(500).json({ status: 'system-error' })
	}
})

app.get('/me', async (req, res) => {
	const { user, cookieHeaderToBeSet } = await middleware.handleRequest(
		req.headers.cookie ?? null,
	)
	// The middleware asks you to (re)set the cookie when a session was extended or cleared.
	if (cookieHeaderToBeSet) res.set('Set-Cookie', cookieHeaderToBeSet)
	if (!user) return res.status(401).json({ status: 'unauthenticated' })
	return res.json({ user: toPublicUser(user) })
})

app.post('/logout', async (req, res) => {
	const raw = /(?:^|;\s*)auth_session=([^;]+)/.exec(
		req.headers.cookie ?? '',
	)?.[1]
	if (raw) await auth.sessions.invalidate(decodeURIComponent(raw))
	res.set('Set-Cookie', middleware.blankSessionCookie())
	return res.status(204).end()
})

app.listen(3000, () => {
	console.log('Beaver-Auth + Express on http://localhost:3000')
})
```

</details>

<details>
<summary><strong>Hono</strong></summary>

```ts
import { randomBytes } from 'node:crypto'
import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { getConnInfo } from '@hono/node-server/conninfo'
import { checkAuthRateLimit, createAuth, type User } from '@beaver-auth/core'
import { createMemoryAdapter } from '@beaver-auth/core/testing'

// Signs JWTs. In a real app, load a long random value from your secrets
// manager. Here we generate one per run so nothing sensitive is committed.
const JWT_SECRET = process.env.JWT_SECRET ?? randomBytes(32).toString('hex')

// In-memory storage: perfect for a first run, wrong for production.
const adapter = createMemoryAdapter()

const auth = createAuth({
	adapter,
	middleware: {
		jwtSecret: JWT_SECRET,
		isJwtRevoked: adapter.isJtiRevoked,
		// Cookies are Secure by default. We relax that for http://localhost only.
		cookieOptions: { secure: process.env.NODE_ENV === 'production' },
	},
	// Rate limiting is opt-in and is NOT applied for you: see the login route.
	rateLimiters: {
		login: { algorithm: 'sliding-window', maxRequests: 5, windowMs: 60_000 },
	},
})

const middleware = auth.middleware! // present because `middleware` is configured above

const loginGuard = {
	limiter: auth.rateLimiters.login!, // present because `rateLimiters.login` is configured above
	// One IP's attempts against one email. See the rate limiting guide.
	getIdentifier: ({
		email,
		ipAddress,
	}: {
		email?: string
		ipAddress?: string
	}) => `${ipAddress ?? 'unknown'}:${email ?? 'unknown'}`,
}

const app = new Hono()

app.post('/register', async (c) => {
	const { email, password, profile } = await c.req.json().catch(() => ({}))
	const result = await auth.registration.execute({ email, password, profile })

	switch (result.status) {
		case 'success':
		case 'success-pending-verification':
			return c.json({ status: result.status }, 201)
		case 'validation-error':
			return c.json({ status: result.status, message: result.message }, 400)
		case 'email-already-exists':
			return c.json({ status: result.status }, 409)
		default:
			return c.json({ status: 'system-error' }, 500)
	}
})

app.post('/login', async (c) => {
	const { email, password } = await c.req.json().catch(() => ({}))
	// Behind a proxy or load balancer, this is the proxy's address. Read the
	// client IP from the header your infrastructure sets, and only trust it
	// if the proxy is the one setting it.
	const ipAddress = getConnInfo(c).remote.address

	const limit = await checkAuthRateLimit(loginGuard, { email, ipAddress })
	if (!limit.success) {
		c.header('Retry-After', String(limit.retryAfter))
		return c.json({ status: 'too-many-attempts' }, 429)
	}

	const result = await auth.login.executePasswordStage(
		{ email, password },
		JWT_SECRET,
		{ userAgent: c.req.header('user-agent'), ipAddress },
		{ sessionType: 'session' },
	)

	switch (result.status) {
		case 'success-session':
			c.header(
				'Set-Cookie',
				middleware.setSessionCookie(result.token, result.session.expiresAt),
			)
			return c.json({ user: toPublicUser(result.user) })
		case 'mfa-required':
			return c.json(
				{ status: result.status, mfaChallengeToken: result.mfaChallengeToken },
				202,
			)
		case 'unverified':
			return c.json({ status: result.status }, 403)
		case 'invalid-credentials':
			return c.json({ status: result.status }, 401)
		default:
			return c.json({ status: 'system-error' }, 500)
	}
})

app.get('/me', async (c) => {
	const { user, cookieHeaderToBeSet } = await middleware.handleRequest(
		c.req.header('cookie') ?? null,
	)
	// The middleware asks you to (re)set the cookie when a session was extended or cleared.
	if (cookieHeaderToBeSet) c.header('Set-Cookie', cookieHeaderToBeSet)
	if (!user) return c.json({ status: 'unauthenticated' }, 401)
	return c.json({ user: toPublicUser(user) })
})

app.post('/logout', async (c) => {
	const raw = /(?:^|;\s*)auth_session=([^;]+)/.exec(
		c.req.header('cookie') ?? '',
	)?.[1]
	if (raw) await auth.sessions.invalidate(decodeURIComponent(raw))
	c.header('Set-Cookie', middleware.blankSessionCookie())
	return c.body(null, 204)
})

serve({ fetch: app.fetch, port: 3000 }, () => {
	console.log('Beaver-Auth + Hono on http://localhost:3000')
})
```

</details>

A few things in that file are worth understanding before you move on.

- **The adapter.** Beaver-Auth never touches your database directly. It calls an adapter you provide. `createMemoryAdapter()` is a complete implementation that keeps everything in memory, which makes it perfect for trying things out and wrong for production. See the [checklist](#before-you-go-to-production).
- **`middleware.jwtSecret` is required** whenever you configure `middleware`, even if you only use cookie sessions.
- **Rate limiting is opt-in and is not applied for you.** The login route calls `checkAuthRateLimit` before it calls the login engine. Remove that call and nothing throttles login attempts.
- **`toPublicUser`.** Login results contain the full user record, including `passwordHash` and `mfaSecret`. Never send that to a client.

## 3. Run it

```bash
npx tsx server.ts
```

## 4. Register, log in, and call a protected route

In a second terminal:

```bash
curl -s -X POST localhost:3000/register \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"SecurePassword123","profile":{"firstName":"Alice","lastName":"Johnson"}}'
# {"status":"success"}

curl -s -c jar.txt -X POST localhost:3000/login \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"SecurePassword123"}'
# {"user":{"id":"…","email":"alice@example.com","role":"user","profile":{…},"verificationStatus":"verified","mfaEnabled":false,"createdAt":"…"}}

curl -s -b jar.txt localhost:3000/me
# {"user":{…}}

curl -s -o /dev/null -w '%{http_code}\n' -b jar.txt -c jar.txt -X POST localhost:3000/logout
# 204

curl -s -o /dev/null -w '%{http_code}\n' -b jar.txt localhost:3000/me
# 401
```

Try registering `alice@example.com` a second time. You still get `{"status":"success"}`. That is enumeration protection: the response does not reveal whether an email is already taken.

Bad input is rejected with a message, for example `{"status":"validation-error","message":"…"}` for a malformed email.

## 5. Try JWTs and refresh-token rotation

Add these routes to `server.ts`, above the line that starts the server.

<details open>
<summary><strong>Express</strong></summary>

```ts
app.post('/login/jwt', async (req, res) => {
	const { email, password } = req.body ?? {}
	const ipAddress = req.ip

	const limit = await checkAuthRateLimit(loginGuard, { email, ipAddress })
	if (!limit.success) {
		return res
			.status(429)
			.set('Retry-After', String(limit.retryAfter))
			.json({ status: 'too-many-attempts' })
	}

	const result = await auth.login.executePasswordStage(
		{ email, password },
		JWT_SECRET,
		{ userAgent: req.get('user-agent'), ipAddress },
		{ sessionType: 'jwt' },
	)

	switch (result.status) {
		case 'success-jwt':
			return res.json({
				accessToken: result.accessToken,
				refreshToken: result.refreshToken,
				user: toPublicUser(result.user),
			})
		case 'mfa-required':
			return res.status(202).json({
				status: result.status,
				mfaChallengeToken: result.mfaChallengeToken,
			})
		case 'unverified':
			return res.status(403).json({ status: result.status })
		case 'invalid-credentials':
			return res.status(401).json({ status: result.status })
		default:
			return res.status(500).json({ status: 'system-error' })
	}
})

app.get('/me/jwt', async (req, res) => {
	const check = await middleware.handleJwtRequest(
		req.headers.authorization ?? null,
	)
	// JWT verification is stateless: it checks the signature, expiry, and (because
	// we passed `isJwtRevoked`) revocation, then returns the token's claims.
	// It does not load the user. Fetch it yourself if you need more than the claims.
	if (!check.valid || !check.payload)
		return res.status(401).json({ status: 'unauthenticated' })
	const { userId, email, role } = check.payload
	return res.json({ userId, email, role })
})

app.post('/refresh', async (req, res) => {
	const result = await auth.login.refreshAccessToken(
		req.body?.refreshToken ?? '',
		JWT_SECRET,
	)

	switch (result.status) {
		case 'success-jwt':
			return res.json({
				accessToken: result.accessToken,
				refreshToken: result.refreshToken,
			})
		case 'refresh-token-reused':
			// A rotated-out token was replayed. The engine has already revoked the whole family.
			return res.status(401).json({ status: result.status })
		case 'invalid-credentials':
			return res.status(401).json({ status: result.status })
		default:
			return res.status(500).json({ status: 'system-error' })
	}
})
```

</details>

<details>
<summary><strong>Hono</strong></summary>

```ts
app.post('/login/jwt', async (c) => {
	const { email, password } = await c.req.json().catch(() => ({}))
	const ipAddress = getConnInfo(c).remote.address

	const limit = await checkAuthRateLimit(loginGuard, { email, ipAddress })
	if (!limit.success) {
		c.header('Retry-After', String(limit.retryAfter))
		return c.json({ status: 'too-many-attempts' }, 429)
	}

	const result = await auth.login.executePasswordStage(
		{ email, password },
		JWT_SECRET,
		{ userAgent: c.req.header('user-agent'), ipAddress },
		{ sessionType: 'jwt' },
	)

	switch (result.status) {
		case 'success-jwt':
			return c.json({
				accessToken: result.accessToken,
				refreshToken: result.refreshToken,
				user: toPublicUser(result.user),
			})
		case 'mfa-required':
			return c.json(
				{ status: result.status, mfaChallengeToken: result.mfaChallengeToken },
				202,
			)
		case 'unverified':
			return c.json({ status: result.status }, 403)
		case 'invalid-credentials':
			return c.json({ status: result.status }, 401)
		default:
			return c.json({ status: 'system-error' }, 500)
	}
})

app.get('/me/jwt', async (c) => {
	const check = await middleware.handleJwtRequest(
		c.req.header('authorization') ?? null,
	)
	// JWT verification is stateless: it checks the signature, expiry, and (because
	// we passed `isJwtRevoked`) revocation, then returns the token's claims.
	// It does not load the user. Fetch it yourself if you need more than the claims.
	if (!check.valid || !check.payload)
		return c.json({ status: 'unauthenticated' }, 401)
	const { userId, email, role } = check.payload
	return c.json({ userId, email, role })
})

app.post('/refresh', async (c) => {
	const { refreshToken } = await c.req
		.json()
		.catch(() => ({ refreshToken: '' }))
	const result = await auth.login.refreshAccessToken(
		refreshToken ?? '',
		JWT_SECRET,
	)

	switch (result.status) {
		case 'success-jwt':
			return c.json({
				accessToken: result.accessToken,
				refreshToken: result.refreshToken,
			})
		case 'refresh-token-reused':
			// A rotated-out token was replayed. The engine has already revoked the whole family.
			return c.json({ status: result.status }, 401)
		case 'invalid-credentials':
			return c.json({ status: result.status }, 401)
		default:
			return c.json({ status: 'system-error' }, 500)
	}
})
```

</details>

Restart the server, then:

```bash
curl -s -X POST localhost:3000/login/jwt \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"SecurePassword123"}'
# {"accessToken":"…","refreshToken":"…","user":{…}}

curl -s -H "Authorization: Bearer $ACCESS" localhost:3000/me/jwt
# {"userId":"…","email":"alice@example.com","role":"user"}

curl -s -X POST localhost:3000/refresh \
  -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}"
# {"accessToken":"…","refreshToken":"…"}
```

Now the interesting part. Send the **original** refresh token again, as a thief who copied it would:

```bash
curl -s -X POST localhost:3000/refresh \
  -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}"
# {"status":"refresh-token-reused"}
```

Beaver-Auth treated the replay as theft and revoked the entire token family. The new refresh token from the previous step no longer works either:

```bash
# {"status":"invalid-credentials"}
```

The real user has to log in again, and the thief is locked out. Your server console will also show the detection, because security events like this are reported through the `onSystemError` handler (see the checklist).

## 6. Watch the rate limiter

Send six wrong passwords within a minute:

```bash
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w '%{http_code} ' -X POST localhost:3000/login \
    -H 'content-type: application/json' \
    -d '{"email":"alice@example.com","password":"wrong"}'
done
# 401 401 401 401 401 429
```

The 429 response carries a `Retry-After` header. Successful logins count against the same budget, so if you logged in a moment ago you will hit the 429 sooner.

## 7. Add email verification and password reset (optional)

Both are opt-in. Provide a hook and the feature turns on. Your hook sends the email; Beaver-Auth creates and validates the token.

```ts
const auth = createAuth({
	adapter,
	// ...the options from step 2
	verification: {
		hooks: {
			onVerificationRequired: async ({ email, token, expiresAt }) => {
				// Replace with your email provider.
				await sendEmail(email, `Your verification token: ${token}`)
			},
		},
	},
	passwordReset: {
		hooks: {
			onPasswordResetRequested: async ({ email, token, expiresAt }) => {
				await sendEmail(email, `Your reset token: ${token}`)
			},
		},
	},
})
```

With `verification` configured, registration returns `success-pending-verification`, and login returns `unverified` until the user verifies:

```ts
await auth.verification!.verifyEmail(email, token)
// { status: 'success', userId } | { status: 'invalid-token' } | { status: 'system-error', message }
```

Tokens are single-use: verifying with the same token twice returns `invalid-token`.

```ts
await auth.passwordReset!.requestReset(email)
// { status: 'request-processed' }

await auth.passwordReset!.completeReset(email, token, newPassword)
// { status: 'success', userId } and every session and refresh token for that user is revoked
```

Hooks run in the background, with retries, so a slow email provider does not slow down the response.

## Before you go to production

| Do this                                            | Why                                                                                                                                                                                                                                                                                                                   |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Replace the memory adapter**                     | It loses everything on restart and cannot be shared between processes. The adapter contract is 27 methods across `AuthRepoAdapter` and `AuthSessionAdapter`. [`src/testing/memory-adapter.ts`](../../src/testing/memory-adapter.ts) is a short reference for what each one must do. Put a unique constraint on email. |
| **Load `JWT_SECRET` from a secrets manager**       | Use a long random value. The examples generate one per run only so nothing sensitive is committed.                                                                                                                                                                                                                    |
| **Keep cookies `Secure`**                          | It is the default. The examples turn it off for `http://localhost` only.                                                                                                                                                                                                                                              |
| **Use a shared store for rate limiting**           | The built-in `MemoryStore` is per-process. With several instances, the effective limit becomes the configured limit times the number of instances. Provide your own `RateLimitStore` (for example Redis) through `rateLimiters.login.store`.                                                                          |
| **Get the real client IP**                         | Behind a proxy or load balancer, the connection address is the proxy's. Configure Express's `trust proxy` setting, or read the header your infrastructure sets. Only trust a header your own proxy controls.                                                                                                          |
| **Schedule cleanup**                               | Nothing purges expired records for you. Call `auth.registration.purgeExpiredRegistrations()`, `auth.sessions.purgeExpiredMfaChallengeTokens()`, and `new RefreshTokenEngine({ adapter }).purgeExpiredRefreshTokens()` on a schedule.                                                                                  |
| **Provide a `dispatcher` on serverless platforms** | The default `LocalTaskDispatcher` runs tasks inside your process, which is unreliable where the process can be frozen after the response. Use a dispatcher backed by a queue.                                                                                                                                         |
| **Route `onSystemError` to logging and alerting**  | It receives system errors and also security events, such as refresh-token reuse and replayed TOTP codes. The default prints to the console.                                                                                                                                                                           |
| **Encrypt MFA secrets at rest**                    | Whatever your adapter receives as `mfaSecret` is what it stores. Encrypt it there.                                                                                                                                                                                                                                    |

## Next steps

- [Core concepts](./core-concepts.md): the model behind engines, adapters, and hooks.
- [Architecture](./architecture.md): what Beaver-Auth owns and what you own.
- [Cryptography](./cryptography.md): the specification and the tests behind each guarantee.
- The complete, runnable versions of these servers live in [`examples/express`](../../examples/express/server.ts) and [`examples/hono`](../../examples/hono/server.ts).
