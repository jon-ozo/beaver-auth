// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { randomBytes } from 'node:crypto'
import express from 'express'
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

const app = express()
app.use(express.json())

// #region register
app.post('/register', async (req, res) => {
	const { email, password, profile } = req.body ?? {}
	const result = await auth.registration.execute({ email, password, profile })

	switch (result.status) {
		case 'success':
		case 'success-pending-verification':
			return res.status(201).json({ status: result.status })
		case 'validation-error':
			return res.status(400).json({ status: result.status, message: result.message })
		case 'email-already-exists':
			return res.status(409).json({ status: result.status })
		default:
			return res.status(500).json({ status: 'system-error' })
	}
})
// #endregion

// #region login-session
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
			res.set('Set-Cookie', middleware.setSessionCookie(result.token, result.session.expiresAt))
			return res.json({ user: toPublicUser(result.user) })
		case 'mfa-required':
			return res.status(202).json({ status: result.status, mfaChallengeToken: result.mfaChallengeToken })
		case 'unverified':
			return res.status(403).json({ status: result.status })
		case 'invalid-credentials':
			return res.status(401).json({ status: result.status })
		default:
			return res.status(500).json({ status: 'system-error' })
	}
})
// #endregion

// #region me-session
app.get('/me', async (req, res) => {
	const { user, cookieHeaderToBeSet } = await middleware.handleRequest(req.headers.cookie ?? null)
	// The middleware asks you to (re)set the cookie when a session was extended or cleared.
	if (cookieHeaderToBeSet) res.set('Set-Cookie', cookieHeaderToBeSet)
	if (!user) return res.status(401).json({ status: 'unauthenticated' })
	return res.json({ user: toPublicUser(user) })
})

app.post('/logout', async (req, res) => {
	const raw = /(?:^|;\s*)auth_session=([^;]+)/.exec(req.headers.cookie ?? '')?.[1]
	if (raw) await auth.sessions.invalidate(decodeURIComponent(raw))
	res.set('Set-Cookie', middleware.blankSessionCookie())
	return res.status(204).end()
})
// #endregion

// #region jwt
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
			return res.status(202).json({ status: result.status, mfaChallengeToken: result.mfaChallengeToken })
		case 'unverified':
			return res.status(403).json({ status: result.status })
		case 'invalid-credentials':
			return res.status(401).json({ status: result.status })
		default:
			return res.status(500).json({ status: 'system-error' })
	}
})

app.get('/me/jwt', async (req, res) => {
	const check = await middleware.handleJwtRequest(req.headers.authorization ?? null)
	// JWT verification is stateless: it checks the signature, expiry, and (because
	// we passed `isJwtRevoked`) revocation, then returns the token's claims.
	// It does not load the user. Fetch it yourself if you need more than the claims.
	if (!check.valid || !check.payload) return res.status(401).json({ status: 'unauthenticated' })
	const { userId, email, role } = check.payload
	return res.json({ userId, email, role })
})

app.post('/refresh', async (req, res) => {
	const result = await auth.login.refreshAccessToken(req.body?.refreshToken ?? '', JWT_SECRET)

	switch (result.status) {
		case 'success-jwt':
			return res.json({ accessToken: result.accessToken, refreshToken: result.refreshToken })
		case 'refresh-token-reused':
			// A rotated-out token was replayed. The engine has already revoked the whole family.
			return res.status(401).json({ status: result.status })
		case 'invalid-credentials':
			return res.status(401).json({ status: result.status })
		default:
			return res.status(500).json({ status: 'system-error' })
	}
})
// #endregion

app.listen(3000, () => {
	console.log('Beaver-Auth + Express on http://localhost:3000')
})
