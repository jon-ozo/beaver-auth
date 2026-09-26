// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { randomBytes } from 'node:crypto'
import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { getConnInfo } from '@hono/node-server/conninfo'
import {
	checkAuthRateLimit,
	createBeaverAuth,
	type User,
} from '@beaver-auth/core'
import { createMemoryAdapter } from '@beaver-auth/core/testing'

// #region setup
// Signs JWTs. In a real app, load a long random value from your secrets
// manager. Here we generate one per run so nothing sensitive is committed.
const JWT_SECRET = process.env.JWT_SECRET ?? randomBytes(32).toString('hex')

// In-memory storage: perfect for a first run, wrong for production.
const adapter = createMemoryAdapter()

const auth = createBeaverAuth({
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
	getIdentifier: ({ email, ipAddress }: { email?: string; ipAddress?: string }) =>
		`${ipAddress ?? 'unknown'}:${email ?? 'unknown'}`,
}

// Never send the stored password hash or MFA secret to a client.
const toPublicUser = ({ passwordHash, mfaSecret, ...safe }: User) => safe
// #endregion

const app = new Hono()

// #region register
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
// #endregion

// #region login-session
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
			c.header('Set-Cookie', middleware.setSessionCookie(result.token, result.session.expiresAt))
			return c.json({ user: toPublicUser(result.user) })
		case 'mfa-required':
			return c.json({ status: result.status, mfaChallengeToken: result.mfaChallengeToken }, 202)
		case 'unverified':
			return c.json({ status: result.status }, 403)
		case 'invalid-credentials':
			return c.json({ status: result.status }, 401)
		default:
			return c.json({ status: 'system-error' }, 500)
	}
})
// #endregion

// #region me-session
app.get('/me', async (c) => {
	const { user, cookieHeaderToBeSet } = await middleware.handleRequest(c.req.header('cookie') ?? null)
	// The middleware asks you to (re)set the cookie when a session was extended or cleared.
	if (cookieHeaderToBeSet) c.header('Set-Cookie', cookieHeaderToBeSet)
	if (!user) return c.json({ status: 'unauthenticated' }, 401)
	return c.json({ user: toPublicUser(user) })
})

app.post('/logout', async (c) => {
	const raw = /(?:^|;\s*)auth_session=([^;]+)/.exec(c.req.header('cookie') ?? '')?.[1]
	if (raw) await auth.sessions.invalidate(decodeURIComponent(raw))
	c.header('Set-Cookie', middleware.blankSessionCookie())
	return c.body(null, 204)
})
// #endregion

// #region jwt
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
			return c.json({ status: result.status, mfaChallengeToken: result.mfaChallengeToken }, 202)
		case 'unverified':
			return c.json({ status: result.status }, 403)
		case 'invalid-credentials':
			return c.json({ status: result.status }, 401)
		default:
			return c.json({ status: 'system-error' }, 500)
	}
})

app.get('/me/jwt', async (c) => {
	const check = await middleware.handleJwtRequest(c.req.header('authorization') ?? null)
	// JWT verification is stateless: it checks the signature, expiry, and (because
	// we passed `isJwtRevoked`) revocation, then returns the token's claims.
	// It does not load the user. Fetch it yourself if you need more than the claims.
	if (!check.valid || !check.payload) return c.json({ status: 'unauthenticated' }, 401)
	const { userId, email, role } = check.payload
	return c.json({ userId, email, role })
})

app.post('/refresh', async (c) => {
	const { refreshToken } = await c.req.json().catch(() => ({ refreshToken: '' }))
	const result = await auth.login.refreshAccessToken(refreshToken ?? '', JWT_SECRET)

	switch (result.status) {
		case 'success-jwt':
			return c.json({ accessToken: result.accessToken, refreshToken: result.refreshToken })
		case 'refresh-token-reused':
			// A rotated-out token was replayed. The engine has already revoked the whole family.
			return c.json({ status: result.status }, 401)
		case 'invalid-credentials':
			return c.json({ status: result.status }, 401)
		default:
			return c.json({ status: 'system-error' }, 500)
	}
})
// #endregion

serve({ fetch: app.fetch, port: 3000 }, () => {
	console.log('Beaver-Auth + Hono on http://localhost:3000')
})
