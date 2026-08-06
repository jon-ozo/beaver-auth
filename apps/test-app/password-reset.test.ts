import { describe, expect, it, vi } from 'vitest'
import { PasswordResetEngine, CryptoEngine, SessionManager } from '@beaver-auth/core'
import { MockAdapter } from './support/mock-adapter.js'
import { SyncTaskDispatcher } from './support/sync-dispatcher.js'
import type { PasswordResetHookPayload } from '@beaver-auth/core'

const OLD_PASSWORD = 'OldPassword9'
const NEW_PASSWORD = 'BrandNewPassword9'

function buildEngine(opts?: { responseFloorMs?: number }) {
	const adapter = new MockAdapter()
	const dispatcher = new SyncTaskDispatcher()
	const onSystemError = vi.fn()
	const received: PasswordResetHookPayload[] = []

	const passwordReset = new PasswordResetEngine({
		adapter,
		hooks: {
			onPasswordResetRequested: async (payload) => {
				received.push(payload)
			},
		},
		dispatcher,
		onSystemError,
		responseFloorMs: opts?.responseFloorMs ?? 0,
	})

	return { adapter, dispatcher, onSystemError, received, passwordReset }
}

async function seedUserWithPassword(adapter: MockAdapter) {
	const crypto = new CryptoEngine()
	const passwordHash = await crypto.hashPassword(OLD_PASSWORD)
	return adapter.seedUser({
		email: 'reset-me@example.com',
		passwordHash,
		verificationStatus: 'verified',
	})
}

describe('PasswordResetEngine.requestReset', () => {
	it('returns the SAME response for an existing email as for a nonexistent one', async () => {
		const { passwordReset, adapter } = buildEngine()
		await seedUserWithPassword(adapter)

		const existing = await passwordReset.requestReset('reset-me@example.com')
		const nonexistent = await passwordReset.requestReset('nobody@example.com')

		expect(existing).toEqual(nonexistent)
		expect(existing).toEqual({ status: 'request-processed' })
	})

	it('dispatches the hook only for a real account, with a consumable token', async () => {
		const { passwordReset, adapter, received } = buildEngine()
		const user = await seedUserWithPassword(adapter)

		await passwordReset.requestReset('reset-me@example.com')

		await vi.waitFor(() => expect(received).toHaveLength(1))
		expect(received[0].email).toBe(user.email)
		expect(received[0].userId).toBe(user.id)
		expect(received[0].token).toMatch(/^[0-9a-f]{64}$/)
	})

	it('does NOT dispatch anything for a nonexistent email', async () => {
		const { passwordReset, received } = buildEngine()

		await passwordReset.requestReset('nobody@example.com')
		// Give any accidental fire-and-forget work a chance to run.
		await new Promise((r) => setTimeout(r, 20))

		expect(received).toHaveLength(0)
	})

	it('rejects a missing/empty email as a validation error', async () => {
		const { passwordReset } = buildEngine()

		const result = await passwordReset.requestReset('')
		expect(result.status).toBe('validation-error')

		const result2 = await passwordReset.requestReset(undefined)
		expect(result2.status).toBe('validation-error')
	})

	it('holds both existing and nonexistent-email responses to at least responseFloorMs', async () => {
		const { passwordReset, adapter } = buildEngine({ responseFloorMs: 60 })
		await seedUserWithPassword(adapter)

		const start1 = Date.now()
		await passwordReset.requestReset('reset-me@example.com')
		expect(Date.now() - start1).toBeGreaterThanOrEqual(55)

		const start2 = Date.now()
		await passwordReset.requestReset('nobody@example.com')
		expect(Date.now() - start2).toBeGreaterThanOrEqual(55)
	})

	it('reports via onSystemError and returns system-error when the adapter throws unexpectedly', async () => {
		const { passwordReset, adapter, onSystemError } = buildEngine()
		vi.spyOn(adapter, 'findUserByEmail').mockRejectedValueOnce(new Error('db down'))

		const result = await passwordReset.requestReset('anyone@example.com')

		expect(result.status).toBe('system-error')
		expect(onSystemError).toHaveBeenCalled()
	})
})

describe('PasswordResetEngine.completeReset', () => {
	it('changes the password, and the new password now works for login-style verification', async () => {
		const { passwordReset, adapter, received } = buildEngine()
		const user = await seedUserWithPassword(adapter)

		await passwordReset.requestReset('reset-me@example.com')
		await vi.waitFor(() => expect(received).toHaveLength(1))
		const token = received[0].token

		const result = await passwordReset.completeReset(
			'reset-me@example.com',
			token,
			NEW_PASSWORD,
		)

		expect(result).toEqual({ status: 'success', userId: user.id })

		const updated = await adapter.findUserById(user.id)
		const crypto = new CryptoEngine()
		expect(await crypto.verifyPassword(NEW_PASSWORD, updated!.passwordHash!)).toBe(true)
		expect(await crypto.verifyPassword(OLD_PASSWORD, updated!.passwordHash!)).toBe(false)
	})

	it('revokes all existing sessions and refresh tokens for the user on success', async () => {
		const { passwordReset, adapter, received } = buildEngine()
		const user = await seedUserWithPassword(adapter)
		const otherUser = adapter.seedUser({
			email: 'unaffected@example.com',
			passwordHash: 'x',
		})

		const sessions = new SessionManager({ adapter })
		await sessions.create(user.id)
		await sessions.create(user.id) // a second concurrent session
		await adapter.createRefreshToken({
			tokenHash: 'refresh-hash-for-user',
			userId: user.id,
			familyId: 'family-1',
			status: 'active',
			expiresAt: new Date(Date.now() + 100000),
		})
		await sessions.create(otherUser.id)

		expect(adapter.sessions.size).toBe(3)
		expect(adapter.refreshTokens.size).toBe(1)

		await passwordReset.requestReset('reset-me@example.com')
		await vi.waitFor(() => expect(received).toHaveLength(1))
		const token = received[0].token

		await passwordReset.completeReset('reset-me@example.com', token, NEW_PASSWORD)

		// This user's sessions/refresh tokens are gone...
		let remainingForUser = 0
		for (const s of adapter.sessions.values()) {
			if (s.userId === user.id) remainingForUser++
		}
		expect(remainingForUser).toBe(0)
		expect(adapter.refreshTokens.size).toBe(0)

		// ...but the other user's session is untouched.
		let remainingForOther = 0
		for (const s of adapter.sessions.values()) {
			if (s.userId === otherUser.id) remainingForOther++
		}
		expect(remainingForOther).toBe(1)
	})

	it('rejects an invalid token', async () => {
		const { passwordReset, adapter } = buildEngine()
		await seedUserWithPassword(adapter)

		const result = await passwordReset.completeReset(
			'reset-me@example.com',
			'a'.repeat(64),
			NEW_PASSWORD,
		)

		expect(result).toEqual({ status: 'invalid-token' })
	})

	it('a reset token is single-use', async () => {
		const { passwordReset, adapter, received } = buildEngine()
		await seedUserWithPassword(adapter)

		await passwordReset.requestReset('reset-me@example.com')
		await vi.waitFor(() => expect(received).toHaveLength(1))
		const token = received[0].token

		const first = await passwordReset.completeReset(
			'reset-me@example.com',
			token,
			NEW_PASSWORD,
		)
		expect(first.status).toBe('success')

		const second = await passwordReset.completeReset(
			'reset-me@example.com',
			token,
			'AnotherPassword9',
		)
		expect(second).toEqual({ status: 'invalid-token' })
	})

	it('rejects a weak new password WITHOUT consuming the token, so a valid retry still works', async () => {
		const { passwordReset, adapter, received } = buildEngine()
		await seedUserWithPassword(adapter)

		await passwordReset.requestReset('reset-me@example.com')
		await vi.waitFor(() => expect(received).toHaveLength(1))
		const token = received[0].token

		const weakAttempt = await passwordReset.completeReset(
			'reset-me@example.com',
			token,
			'weak',
		)
		expect(weakAttempt.status).toBe('validation-error')

		const validAttempt = await passwordReset.completeReset(
			'reset-me@example.com',
			token,
			NEW_PASSWORD,
		)
		expect(validAttempt.status).toBe('success')
	})

	it('holds every outcome (success, invalid-token, validation-error) to at least responseFloorMs', async () => {
		const { passwordReset, adapter, received } = buildEngine({ responseFloorMs: 60 })
		await seedUserWithPassword(adapter)
		await passwordReset.requestReset('reset-me@example.com')
		await vi.waitFor(() => expect(received).toHaveLength(1))
		const token = received[0].token

		const s1 = Date.now()
		await passwordReset.completeReset('reset-me@example.com', 'a'.repeat(64), NEW_PASSWORD)
		expect(Date.now() - s1).toBeGreaterThanOrEqual(55)

		const s2 = Date.now()
		await passwordReset.completeReset('reset-me@example.com', token, 'weak')
		expect(Date.now() - s2).toBeGreaterThanOrEqual(55)

		const s3 = Date.now()
		await passwordReset.completeReset('reset-me@example.com', token, NEW_PASSWORD)
		expect(Date.now() - s3).toBeGreaterThanOrEqual(55)
	})

	it('still reports success even if session/refresh-token revocation fails, but reports the failure via onSystemError', async () => {
		const { passwordReset, adapter, onSystemError, received } = buildEngine()
		const user = await seedUserWithPassword(adapter)

		await passwordReset.requestReset('reset-me@example.com')
		await vi.waitFor(() => expect(received).toHaveLength(1))
		const token = received[0].token

		vi.spyOn(adapter, 'deleteUserSessions').mockRejectedValueOnce(
			new Error('cleanup blip'),
		)

		const result = await passwordReset.completeReset(
			'reset-me@example.com',
			token,
			NEW_PASSWORD,
		)

		// The password change itself must not be rolled back or hidden just
		// because best-effort cleanup afterward had trouble.
		expect(result).toEqual({ status: 'success', userId: user.id })
		expect(onSystemError).toHaveBeenCalled()

		const updated = await adapter.findUserById(user.id)
		const crypto = new CryptoEngine()
		expect(await crypto.verifyPassword(NEW_PASSWORD, updated!.passwordHash!)).toBe(true)
	})
})
