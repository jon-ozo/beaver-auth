import { createHmac } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { TokenEngine } from '@beaver-auth/core'
import { MockAdapter } from './support/mock-adapter.js'

const SECRET = 'a-test-secret-that-is-at-least-32-bytes-long'

function b64(obj: unknown): string {
	return Buffer.from(JSON.stringify(obj)).toString('base64url')
}

describe('TokenEngine.create / consume (opaque verification tokens)', () => {
	it('creates a token, stores it hashed, and it consumes successfully exactly once', async () => {
		const adapter = new MockAdapter()
		const tokens = new TokenEngine({ adapter })

		const { token, expiresAt } = await tokens.create('user@example.com', 'email-verification')

		expect(token).toMatch(/^[0-9a-f]{64}$/)
		expect(expiresAt.getTime()).toBeGreaterThan(Date.now())

		// The raw token is never used as the storage key.
		expect(adapter.verificationTokens.has(token)).toBe(false)

		const first = await tokens.consume('user@example.com', token, 'email-verification')
		expect(first).toBe(true)

		const second = await tokens.consume('user@example.com', token, 'email-verification')
		expect(second).toBe(false) // single-use — already consumed
	})

	it('is case-insensitive and trims the email for the identifier', async () => {
		const adapter = new MockAdapter()
		const tokens = new TokenEngine({ adapter })

		const { token } = await tokens.create('  User@Example.com  ', 'password-reset')

		expect(
			await tokens.consume('user@example.com', token, 'password-reset'),
		).toBe(true)
	})

	it('rejects the correct token under the wrong purpose', async () => {
		const adapter = new MockAdapter()
		const tokens = new TokenEngine({ adapter })

		const { token } = await tokens.create('user@example.com', 'email-verification')

		expect(await tokens.consume('user@example.com', token, 'password-reset')).toBe(false)
	})

	it('rejects a wrong token for a real, existing identifier', async () => {
		const adapter = new MockAdapter()
		const tokens = new TokenEngine({ adapter })
		await tokens.create('user@example.com', 'email-verification')

		expect(
			await tokens.consume('user@example.com', 'f'.repeat(64), 'email-verification'),
		).toBe(false)
	})

	it('returns false for a nonexistent identifier entirely', async () => {
		const adapter = new MockAdapter()
		const tokens = new TokenEngine({ adapter })

		expect(
			await tokens.consume('nobody@example.com', 'a'.repeat(64), 'email-verification'),
		).toBe(false)
	})

	it('rejects (and consumes) an expired token', async () => {
		const adapter = new MockAdapter()
		const tokens = new TokenEngine({ adapter })

		const { token } = await tokens.create('user@example.com', 'email-verification', 10)
		await new Promise((r) => setTimeout(r, 30))

		const result = await tokens.consume('user@example.com', token, 'email-verification')
		expect(result).toBe(false)

		// "Consumed but dead" — the record should be gone even though it
		// failed, so a subsequent legitimate request can't reuse the slot
		// weirdly and the identifier is clean for a fresh token.
		expect(adapter.verificationTokens.size).toBe(0)
	})
})

describe('TokenEngine.createJwtToken / verifyJwtToken', () => {
	const tokens = new TokenEngine({ adapter: new MockAdapter() })

	it('round-trips a payload correctly, with auto-added jti/iat/exp', () => {
		const token = tokens.createJwtToken({ userId: 'u-1', role: 'user' }, 3600, SECRET)
		const result = tokens.verifyJwtToken(token, SECRET)

		expect(result.valid).toBe(true)
		if (result.valid) {
			expect(result.payload.userId).toBe('u-1')
			expect(result.payload.role).toBe('user')
			expect(typeof result.payload.jti).toBe('string')
			expect(typeof result.payload.iat).toBe('number')
			expect(typeof result.payload.exp).toBe('number')
		}
	})

	it('rejects a secret under 32 bytes with a clear error message', () => {
		expect(() => tokens.createJwtToken({ userId: 'u-1' }, 3600, 'too-short')).toThrow(
			/must be at least 32 bytes/,
		)
	})

	it('rejects verification with the wrong secret', () => {
		const token = tokens.createJwtToken({ userId: 'u-1' }, 3600, SECRET)
		const result = tokens.verifyJwtToken(token, 'a-different-secret-also-32-bytes-long')
		expect(result.valid).toBe(false)
	})

	it('rejects a tampered payload (signature no longer matches)', () => {
		const token = tokens.createJwtToken({ userId: 'u-1', role: 'user' }, 3600, SECRET)
		const [header, payload, signature] = token.split('.')

		const tamperedPayload = b64({ userId: 'ADMIN-INJECTED', role: 'admin' })
		const tamperedToken = `${header}.${tamperedPayload}.${signature}`

		const result = tokens.verifyJwtToken(tamperedToken, SECRET)
		expect(result.valid).toBe(false)
	})

	it('rejects an expired token', () => {
		const token = tokens.createJwtToken({ userId: 'u-1' }, -10, SECRET) // already expired
		const result = tokens.verifyJwtToken(token, SECRET)
		expect(result.valid).toBe(false)
		if (!result.valid) expect(result.reason).toMatch(/expired/i)
	})

	it('rejects a malformed token (wrong number of segments)', () => {
		const result = tokens.verifyJwtToken('not.a.valid.jwt.token', SECRET)
		expect(result.valid).toBe(false)
	})

	it('rejects an empty token or empty secret', () => {
		expect(tokens.verifyJwtToken('', SECRET).valid).toBe(false)
		const token = tokens.createJwtToken({ userId: 'u-1' }, 3600, SECRET)
		expect(tokens.verifyJwtToken(token, '').valid).toBe(false)
	})

	it('rejects a token with an unsupported/tampered algorithm header (alg confusion defense)', () => {
		const header = b64({ alg: 'none', typ: 'JWT' })
		const payload = b64({ userId: 'u-1', exp: Math.floor(Date.now() / 1000) + 3600 })
		const forgedToken = `${header}.${payload}.` // "none" alg, empty signature

		const result = tokens.verifyJwtToken(forgedToken, SECRET)
		expect(result.valid).toBe(false)
		if (!result.valid) expect(result.reason).toMatch(/[Uu]nsupported.*algorithm/)
	})

	it('rejects a payload that decodes to something other than a plain object', () => {
		const header = b64({ alg: 'HS256', typ: 'JWT' })
		const payload = Buffer.from(JSON.stringify(['not', 'an', 'object'])).toString('base64url')
		const signature = createHmac('sha256', SECRET)
			.update(`${header}.${payload}`)
			.digest('base64url')
		const token = `${header}.${payload}.${signature}`

		const result = tokens.verifyJwtToken(token, SECRET)
		expect(result.valid).toBe(false)
	})

	it('normalizes the JWT payload — a __proto__ key does not pollute or crash', () => {
		const maliciousPayload = JSON.parse('{"userId":"u-1","__proto__":{"polluted":"yes"}}')
		const token = tokens.createJwtToken(maliciousPayload, 3600, SECRET)
		const result = tokens.verifyJwtToken(token, SECRET)

		expect(result.valid).toBe(true)
		expect(({} as Record<string, unknown>).polluted).toBeUndefined()
	})
})
