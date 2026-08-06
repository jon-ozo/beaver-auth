import { createHmac } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { AuthMiddlewareEngine, SessionManager, LoginEngine } from '@beaver-auth/core'
import { MockAdapter } from './support/mock-adapter.js'

const JWT_SECRET = 'a-test-secret-that-is-at-least-32-bytes-long'

function buildMiddleware(withJwt = true) {
	const adapter = new MockAdapter()
	const sessions = new SessionManager({ adapter })
	const middleware = withJwt
		? new AuthMiddlewareEngine(sessions, { secret: JWT_SECRET, adapter })
		: new AuthMiddlewareEngine(sessions)
	return { adapter, sessions, middleware }
}

/** Crafts a syntactically valid, correctly-signed JWT with an arbitrary payload — used to test edge cases (like a missing jti) that TokenEngine.createJwtToken would never itself produce. */
function craftJwt(payload: Record<string, unknown>, secret: string): string {
	const header = { alg: 'HS256', typ: 'JWT' }
	const b64 = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url')
	const encodedHeader = b64(header)
	const encodedPayload = b64(payload)
	const signature = createHmac('sha256', secret)
		.update(`${encodedHeader}.${encodedPayload}`)
		.digest('base64url')
	return `${encodedHeader}.${encodedPayload}.${signature}`
}

describe('AuthMiddlewareEngine — session (cookie) transport', () => {
	it('returns null session/user for a missing cookie header', async () => {
		const { middleware } = buildMiddleware()
		const result = await middleware.handleRequest(null)
		expect(result).toEqual({ session: null, user: null, cookieHeaderToBeSet: null })
	})

	it('returns null session/user when the cookie is present but not the auth cookie', async () => {
		const { middleware } = buildMiddleware()
		const result = await middleware.handleRequest('foo=bar; other=baz')
		expect(result.session).toBeNull()
		expect(result.cookieHeaderToBeSet).toBeNull()
	})

	it('finds the auth cookie among several others and validates it', async () => {
		const { adapter, sessions, middleware } = buildMiddleware()
		const user = adapter.seedUser({ email: 'user@example.com' })
		const { token } = await sessions.create(user.id)

		const result = await middleware.handleRequest(
			`foo=bar; auth_session=${token}; baz=qux`,
		)

		expect(result.session).not.toBeNull()
		expect(result.user!.id).toBe(user.id)
	})

	it('returns a blank-cookie instruction for an invalid/expired session token', async () => {
		const { middleware } = buildMiddleware()
		const result = await middleware.handleRequest('auth_session=' + 'a'.repeat(64))

		expect(result.session).toBeNull()
		expect(result.user).toBeNull()
		expect(result.cookieHeaderToBeSet).toContain('auth_session=;')
		expect(result.cookieHeaderToBeSet).toContain('Max-Age=0')
	})

	it('handles a URL-encoded custom cookie name correctly', async () => {
		const adapter = new MockAdapter()
		const sessions = new SessionManager({ adapter })
		const middleware = new AuthMiddlewareEngine(sessions, undefined, {
			name: 'my session', // contains a space — must round-trip through encodeURIComponent
		})
		const user = adapter.seedUser({ email: 'user@example.com' })
		const { token } = await sessions.create(user.id)

		const cookieHeader = middleware.setSessionCookie(token, new Date(Date.now() + 100_000))
		const rawCookiePart = cookieHeader.split(';')[0] // "my%20session=<token>"

		const result = await middleware.handleRequest(rawCookiePart)
		expect(result.user!.id).toBe(user.id)
	})

	it('emits a refreshed Set-Cookie only when the session was actually extended', async () => {
		const adapter = new MockAdapter()
		const sessions = new SessionManager({ adapter, sessionTimeoutMs: 40 })
		const middleware = new AuthMiddlewareEngine(sessions, { secret: JWT_SECRET, adapter })
		const user = adapter.seedUser({ email: 'user@example.com' })
		const { token } = await sessions.create(user.id)

		// Immediately after creation — well before the halfway mark, no
		// extension should happen.
		const early = await middleware.handleRequest(`auth_session=${token}`)
		expect(early.cookieHeaderToBeSet).toBeNull()

		// Past the halfway mark.
		await new Promise((r) => setTimeout(r, 25))
		const late = await middleware.handleRequest(`auth_session=${token}`)
		expect(late.cookieHeaderToBeSet).not.toBeNull()
		expect(late.cookieHeaderToBeSet).toContain('auth_session=')
		expect(late.cookieHeaderToBeSet).not.toContain('auth_session=;') // real token, not blanked
	})
})

describe('AuthMiddlewareEngine — cookie serialization', () => {
	it('includes HttpOnly, Secure, SameSite, Path, Expires, and Max-Age by default', () => {
		const { middleware } = buildMiddleware()
		const cookie = middleware.setSessionCookie('abc123', new Date(Date.now() + 60_000))

		expect(cookie).toContain('HttpOnly')
		expect(cookie).toContain('Secure')
		expect(cookie).toContain('SameSite=lax')
		expect(cookie).toContain('Path=/')
		expect(cookie).toMatch(/Max-Age=\d+/)
		expect(cookie).toContain('Expires=')
	})

	it('respects custom cookie options', () => {
		const adapter = new MockAdapter()
		const sessions = new SessionManager({ adapter })
		const middleware = new AuthMiddlewareEngine(sessions, undefined, {
			secure: false,
			httpOnly: false,
			sameSite: 'strict',
			domain: 'example.com',
			path: '/app',
		})

		const cookie = middleware.setSessionCookie('abc123', new Date(Date.now() + 60_000))

		expect(cookie).not.toContain('Secure')
		expect(cookie).not.toContain('HttpOnly')
		expect(cookie).toContain('SameSite=strict')
		expect(cookie).toContain('Domain=example.com')
		expect(cookie).toContain('Path=/app')
	})

	it('blankSessionCookie produces a Max-Age of 0 and an empty value', () => {
		const { middleware } = buildMiddleware()
		const cookie = middleware.blankSessionCookie()

		expect(cookie).toMatch(/^auth_session=;/)
		expect(cookie).toContain('Max-Age=0')
	})
})

describe('AuthMiddlewareEngine — JWT (bearer token) transport', () => {
	it('throws a clear error if constructed without jwtConfig and handleJwtRequest is called', async () => {
		const { middleware } = buildMiddleware(false)
		await expect(middleware.handleJwtRequest('Bearer whatever')).rejects.toThrow(
			/requires jwtConfig.secret/,
		)
	})

	it('rejects a missing Authorization header', async () => {
		const { middleware } = buildMiddleware()
		const result = await middleware.handleJwtRequest(null)
		expect(result).toEqual({
			valid: false,
			user: null,
			payload: null,
			reason: 'Missing Authorization header.',
		})
	})

	it('rejects a malformed (non-Bearer) Authorization header', async () => {
		const { middleware } = buildMiddleware()
		const result = await middleware.handleJwtRequest('Basic abc123')
		expect(result.valid).toBe(false)
		expect(result.reason).toBe('Expected Bearer token.')
	})

	it('accepts a valid, correctly-signed JWT issued through a real login', async () => {
		const { adapter, middleware } = buildMiddleware()
		const sessions = new SessionManager({ adapter })
		const login = new LoginEngine({ adapter, sessions })
		const crypto = await import('@beaver-auth/core').then((m) => new m.CryptoEngine())
		const passwordHash = await crypto.hashPassword('CorrectHorse9')
		const user = adapter.seedUser({
			email: 'jwt-user@example.com',
			passwordHash,
			verificationStatus: 'verified',
		})

		const loginResult = await login.executePasswordStage(
			{ email: 'jwt-user@example.com', password: 'CorrectHorse9' },
			JWT_SECRET,
			undefined,
			{ sessionType: 'jwt' },
		)
		if (loginResult.status !== 'success-jwt') throw new Error('expected success-jwt')

		const result = await middleware.handleJwtRequest(`Bearer ${loginResult.accessToken}`)

		expect(result.valid).toBe(true)
		expect(result.payload?.userId).toBe(user.id)
	})

	it('rejects a JWT signed with the wrong secret', async () => {
		const { middleware } = buildMiddleware()
		const token = craftJwt(
			{ userId: 'x', jti: 'abc', iat: 1, exp: Math.floor(Date.now() / 1000) + 60 },
			'a-completely-different-secret-that-is-32-bytes',
		)

		const result = await middleware.handleJwtRequest(`Bearer ${token}`)
		expect(result.valid).toBe(false)
	})

	it('rejects a JWT missing jti when revocation checking is configured', async () => {
		const adapter = new MockAdapter()
		const sessions = new SessionManager({ adapter })
		const isJwtRevoked = vi.fn().mockResolvedValue(false)
		const middleware = new AuthMiddlewareEngine(sessions, {
			secret: JWT_SECRET,
			adapter,
			isJwtRevoked,
		})

		// Deliberately crafted WITHOUT a jti — TokenEngine.createJwtToken
		// always includes one, so this exercises a shape a real token from
		// this package could never actually have, but that handleJwtRequest
		// must still defend against (e.g. a token from a different issuer).
		const token = craftJwt(
			{ userId: 'x', iat: 1, exp: Math.floor(Date.now() / 1000) + 60 },
			JWT_SECRET,
		)

		const result = await middleware.handleJwtRequest(`Bearer ${token}`)

		expect(result.valid).toBe(false)
		expect(result.reason).toMatch(/missing jti/)
		expect(isJwtRevoked).not.toHaveBeenCalled()
	})

	it('rejects a revoked JWT when isJwtRevoked returns true', async () => {
		const adapter = new MockAdapter()
		const sessions = new SessionManager({ adapter })
		const isJwtRevoked = vi.fn().mockResolvedValue(true)
		const middleware = new AuthMiddlewareEngine(sessions, {
			secret: JWT_SECRET,
			adapter,
			isJwtRevoked,
		})

		const token = craftJwt(
			{ userId: 'x', jti: 'revoked-jti', iat: 1, exp: Math.floor(Date.now() / 1000) + 60 },
			JWT_SECRET,
		)

		const result = await middleware.handleJwtRequest(`Bearer ${token}`)

		expect(result).toEqual({
			valid: false,
			user: null,
			payload: null,
			reason: 'Token has been revoked.',
		})
		expect(isJwtRevoked).toHaveBeenCalledWith('revoked-jti')
	})

	it('does NOT call isJwtRevoked when it was not configured (fully stateless path)', async () => {
		const { middleware } = buildMiddleware()
		const token = craftJwt(
			{ userId: 'x', jti: 'some-jti', iat: 1, exp: Math.floor(Date.now() / 1000) + 60 },
			JWT_SECRET,
		)

		const result = await middleware.handleJwtRequest(`Bearer ${token}`)
		expect(result.valid).toBe(true)
	})
})

describe('AuthMiddlewareEngine.revokeJwt', () => {
	it('throws if the adapter does not implement recordRevokedJti', async () => {
		const adapter = new MockAdapter()
		// @ts-expect-error deliberately shadowing the prototype method with
		// undefined to simulate an adapter that doesn't implement it — a
		// bare `delete` wouldn't work here since recordRevokedJti lives on
		// the prototype, not as an own property.
		adapter.recordRevokedJti = undefined
		const sessions = new SessionManager({ adapter })
		const middleware = new AuthMiddlewareEngine(sessions, { secret: JWT_SECRET, adapter })

		await expect(middleware.revokeJwt('some-jti')).rejects.toThrow(
			/requires the adapter to implement recordRevokedJti/,
		)
	})

	it('records the jti via the adapter when supported', async () => {
		const { adapter, middleware } = buildMiddleware()
		await middleware.revokeJwt('jti-to-revoke')
		expect(adapter.revokedJtis.has('jti-to-revoke')).toBe(true)
	})

	it('throws when constructed without jwtConfig at all', async () => {
		const { middleware } = buildMiddleware(false)
		await expect(middleware.revokeJwt('jti')).rejects.toThrow()
	})
})
