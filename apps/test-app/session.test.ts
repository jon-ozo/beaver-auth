import { describe, expect, it } from 'vitest'
import { SessionManager } from '@beaver-auth/core'
import { MockAdapter } from './support/mock-adapter.js'

function buildSessions(opts?: {
	sessionTimeoutMs?: number
	mfaChallengeTimeoutMs?: number
}) {
	const adapter = new MockAdapter()
	const sessions = new SessionManager({
		adapter,
		sessionTimeoutMs: opts?.sessionTimeoutMs,
		mfaChallengeTimeoutMs: opts?.mfaChallengeTimeoutMs,
	})
	return { adapter, sessions }
}

describe('SessionManager.create / validate / invalidate', () => {
	it('creates a session and returns a raw token that validates back to the right user', async () => {
		const { adapter, sessions } = buildSessions()
		const user = adapter.seedUser({ email: 'user@example.com' })

		const { token, session } = await sessions.create(user.id, {
			userAgent: 'test-agent',
			ipAddress: '1.2.3.4',
		})

		expect(token).toMatch(/^[0-9a-f]{64}$/)
		expect(session.userId).toBe(user.id)

		const validated = await sessions.validate(token)
		expect(validated).not.toBeNull()
		expect(validated!.user.id).toBe(user.id)
		expect(validated!.session.userAgent).toBe('test-agent')
		expect(validated!.session.ipAddress).toBe('1.2.3.4')
		expect(validated!.expiryExtended).toBe(false)
	})

	it('never stores the raw token itself — only its hash is used as the storage key', async () => {
		const { adapter, sessions } = buildSessions()
		const user = adapter.seedUser({ email: 'user@example.com' })

		const { token } = await sessions.create(user.id)

		// The adapter's Map is keyed by tokenHash, not by the raw token —
		// looking the raw token up directly against the storage layer
		// should find nothing.
		expect(adapter.sessions.has(token)).toBe(false)
		// But going through validate() (which hashes first) finds it fine.
		expect(await sessions.validate(token)).not.toBeNull()
	})

	it('returns null for a token that was never issued', async () => {
		const { sessions } = buildSessions()
		const result = await sessions.validate('f'.repeat(64))
		expect(result).toBeNull()
	})

	it('returns null and deletes the record for an expired session', async () => {
		const { adapter, sessions } = buildSessions({ sessionTimeoutMs: 10 })
		const user = adapter.seedUser({ email: 'user@example.com' })
		const { token } = await sessions.create(user.id)

		await new Promise((r) => setTimeout(r, 30))

		const result = await sessions.validate(token)
		expect(result).toBeNull()
		expect(adapter.sessions.size).toBe(0)
	})

	it('extends expiry once past the halfway mark, and reports expiryExtended', async () => {
		const { adapter, sessions } = buildSessions({ sessionTimeoutMs: 40 })
		const user = adapter.seedUser({ email: 'user@example.com' })
		const { token } = await sessions.create(user.id)

		// Past the halfway point (20ms) but not yet expired (40ms).
		await new Promise((r) => setTimeout(r, 22))

		const result = await sessions.validate(token)

		expect(result).not.toBeNull()
		expect(result!.expiryExtended).toBe(true)

		// A second, immediate validate should NOT extend again — plenty of
		// time remains now.
		const second = await sessions.validate(token)
		expect(second!.expiryExtended).toBe(false)
	})

	it('does not extend expiry before the halfway mark', async () => {
		const { adapter, sessions } = buildSessions({ sessionTimeoutMs: 10_000 })
		const user = adapter.seedUser({ email: 'user@example.com' })
		const { token } = await sessions.create(user.id)

		const result = await sessions.validate(token)
		expect(result!.expiryExtended).toBe(false)
	})

	it('invalidate() removes the session — a subsequent validate() fails', async () => {
		const { adapter, sessions } = buildSessions()
		const user = adapter.seedUser({ email: 'user@example.com' })
		const { token } = await sessions.create(user.id)

		await sessions.invalidate(token)

		expect(await sessions.validate(token)).toBeNull()
		expect(adapter.sessions.size).toBe(0)
	})

	it('supports multiple concurrent sessions for the same user', async () => {
		const { adapter, sessions } = buildSessions()
		const user = adapter.seedUser({ email: 'user@example.com' })

		const s1 = await sessions.create(user.id, { userAgent: 'phone' })
		const s2 = await sessions.create(user.id, { userAgent: 'laptop' })

		expect(s1.token).not.toBe(s2.token)
		expect(await sessions.validate(s1.token)).not.toBeNull()
		expect(await sessions.validate(s2.token)).not.toBeNull()

		// Invalidating one leaves the other intact.
		await sessions.invalidate(s1.token)
		expect(await sessions.validate(s1.token)).toBeNull()
		expect(await sessions.validate(s2.token)).not.toBeNull()
	})
})

describe('SessionManager MFA challenge tokens', () => {
	it('creates a challenge token, verifies it, and it is single-purpose (revoke removes it)', async () => {
		const { adapter, sessions } = buildSessions()
		const user = adapter.seedUser({ email: 'user@example.com' })

		const rawToken = await sessions.createTemporaryMfaToken(user.id)
		expect(rawToken).toMatch(/^[0-9a-f]{64}$/)

		const verified = await sessions.verifyTemporaryMfaToken(rawToken)
		expect(verified).toEqual({ userId: user.id, isExpired: false })

		await sessions.revokeTemporaryMfaToken(rawToken)
		expect(await sessions.verifyTemporaryMfaToken(rawToken)).toBeNull()
	})

	it('reports isExpired: true for an expired (but not yet purged) challenge token', async () => {
		const { adapter, sessions } = buildSessions({ mfaChallengeTimeoutMs: 10 })
		const user = adapter.seedUser({ email: 'user@example.com' })
		const rawToken = await sessions.createTemporaryMfaToken(user.id)

		await new Promise((r) => setTimeout(r, 30))

		const verified = await sessions.verifyTemporaryMfaToken(rawToken)
		expect(verified).toEqual({ userId: user.id, isExpired: true })
		// verifyTemporaryMfaToken reports expiry but does not itself delete —
		// the record should still be present until explicitly
		// revoked/purged.
		expect(adapter.mfaChallengeTokens.size).toBe(1)
	})

	it('returns null for a nonexistent challenge token', async () => {
		const { sessions } = buildSessions()
		expect(await sessions.verifyTemporaryMfaToken('a'.repeat(64))).toBeNull()
	})

	it('purgeExpiredMfaChallengeTokens removes only expired tokens', async () => {
		const { adapter, sessions } = buildSessions()
		const user = adapter.seedUser({ email: 'user@example.com' })

		adapter.mfaChallengeTokens.set('expired-hash', {
			tokenHash: 'expired-hash',
			userId: user.id,
			expiresAt: new Date(Date.now() - 1000),
		})
		adapter.mfaChallengeTokens.set('valid-hash', {
			tokenHash: 'valid-hash',
			userId: user.id,
			expiresAt: new Date(Date.now() + 100_000),
		})

		const { purgedCount } = await sessions.purgeExpiredMfaChallengeTokens()

		expect(purgedCount).toBe(1)
		expect(adapter.mfaChallengeTokens.has('expired-hash')).toBe(false)
		expect(adapter.mfaChallengeTokens.has('valid-hash')).toBe(true)
	})
})
