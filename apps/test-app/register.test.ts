import { describe, expect, it, vi } from 'vitest'
import { RegistrationEngine, VerificationEngine } from '@beaver-auth/core'
import { MockAdapter } from './support/mock-adapter.js'
import { SyncTaskDispatcher } from './support/sync-dispatcher.js'
import type { VerificationHookPayload } from '@beaver-auth/core'

function buildEngines(opts?: {
	withVerification?: boolean
	protectAgainstEnumeration?: boolean
	responseFloorMs?: number
}) {
	const adapter = new MockAdapter()
	const dispatcher = new SyncTaskDispatcher()
	const onSystemError = vi.fn()
	const receivedHooks: VerificationHookPayload[] = []

	const verification =
		(opts?.withVerification ?? true)
			? new VerificationEngine({
					adapter,
					hooks: {
						onVerificationRequired: async (payload) => {
							receivedHooks.push(payload)
						},
					},
					dispatcher,
					onSystemError,
				})
			: undefined

	const registration = new RegistrationEngine({
		adapter,
		verification,
		onSystemError,
		protectAgainstEnumeration: opts?.protectAgainstEnumeration,
		responseFloorMs: opts?.responseFloorMs ?? 0,
	})

	return {
		adapter,
		dispatcher,
		onSystemError,
		verification,
		registration,
		receivedHooks,
	}
}

const VALID_INPUT = { email: 'new-user@example.com', password: 'CorrectHorse9' }

describe('RegistrationEngine', () => {
	describe('happy path with verification configured', () => {
		it('creates a pending user and dispatches a verification hook with a consumable token', async () => {
			const { registration, adapter, receivedHooks, verification } =
				buildEngines()

			const result = await registration.execute(VALID_INPUT)

			expect(result).toEqual({ status: 'success-pending-verification' })

			const user = await adapter.findUserByEmail('new-user@example.com')
			expect(user).not.toBeNull()
			expect(user!.verificationStatus).toBe('pending')
			expect(user!.passwordHash).not.toBeNull()
			expect(user!.passwordHash).not.toBe(VALID_INPUT.password)

			// createAndDispatch is fire-and-forget from performRegistration —
			// wait for it to actually land rather than assuming it's done the
			// instant execute() resolves.
			await vi.waitFor(() => expect(receivedHooks).toHaveLength(1))

			const hook = receivedHooks[0]
			expect(hook.email).toBe('new-user@example.com')
			expect(hook.userId).toBe(user!.id)
			expect(hook.token).toMatch(/^[0-9a-f]{64}$/)

			// The dispatched token should actually verify the correct user.
			const verifyResult = await verification!.verifyEmail(
				'new-user@example.com',
				hook.token,
			)
			expect(verifyResult).toEqual({ status: 'success', userId: user!.id })

			const verifiedUser = await adapter.findUserById(user!.id)
			expect(verifiedUser!.verificationStatus).toBe('verified')
		})

		it('lowercases and trims the email before storing', async () => {
			const { registration, adapter } = buildEngines()

			await registration.execute({
				email: '  New-User@Example.com  ',
				password: 'CorrectHorse9',
			})

			expect(
				await adapter.findUserByEmail('new-user@example.com'),
			).not.toBeNull()
			expect(await adapter.findUserByEmail('New-User@Example.com')).toBeNull()
		})
	})

	describe('happy path without verification configured', () => {
		it('creates an immediately-verified user and returns a plain success', async () => {
			const { registration, adapter, receivedHooks } = buildEngines({
				withVerification: false,
			})

			const result = await registration.execute(VALID_INPUT)

			expect(result).toEqual({ status: 'success' })
			const user = await adapter.findUserByEmail('new-user@example.com')
			expect(user!.verificationStatus).toBe('verified')
			expect(receivedHooks).toHaveLength(0)
		})
	})

	describe('enumeration protection', () => {
		it('returns the SAME response shape for an existing email as for a new one, with verification enabled', async () => {
			const { registration, adapter } = buildEngines()
			adapter.seedUser({ email: 'existing@example.com', passwordHash: 'x' })

			const existingResult = await registration.execute({
				email: 'existing@example.com',
				password: 'CorrectHorse9',
			})
			const newResult = await registration.execute({
				email: 'brand-new@example.com',
				password: 'CorrectHorse9',
			})

			expect(existingResult).toEqual(newResult)
			expect(existingResult).toEqual({ status: 'success-pending-verification' })
		})

		it('returns the SAME response shape for an existing email as for a new one, with verification disabled', async () => {
			const { registration, adapter } = buildEngines({
				withVerification: false,
			})
			adapter.seedUser({ email: 'existing@example.com', passwordHash: 'x' })

			const existingResult = await registration.execute({
				email: 'existing@example.com',
				password: 'CorrectHorse9',
			})
			const newResult = await registration.execute({
				email: 'brand-new-2@example.com',
				password: 'CorrectHorse9',
			})

			expect(existingResult).toEqual(newResult)
			expect(existingResult).toEqual({ status: 'success' })
		})

		it('does NOT create a second user record for an existing email', async () => {
			const { registration, adapter } = buildEngines()
			adapter.seedUser({ email: 'existing@example.com', passwordHash: 'x' })

			await registration.execute({
				email: 'existing@example.com',
				password: 'CorrectHorse9',
			})

			let count = 0
			for (const u of adapter.users.values()) {
				if (u.email === 'existing@example.com') count++
			}
			expect(count).toBe(1)
		})

		it('reveals existence via email-already-exists when protection is explicitly disabled', async () => {
			const { registration, adapter } = buildEngines({
				protectAgainstEnumeration: false,
			})
			adapter.seedUser({ email: 'existing@example.com', passwordHash: 'x' })

			const result = await registration.execute({
				email: 'existing@example.com',
				password: 'CorrectHorse9',
			})

			expect(result).toEqual({ status: 'email-already-exists' })
		})
	})

	describe('validation', () => {
		it('rejects a malformed email', async () => {
			const { registration } = buildEngines()

			const result = await registration.execute({
				email: 'not-an-email',
				password: 'CorrectHorse9',
			})

			expect(result.status).toBe('validation-error')
		})

		it('rejects a password under 8 characters', async () => {
			const { registration } = buildEngines()

			const result = await registration.execute({
				email: 'shortpw@example.com',
				password: 'a1',
			})

			expect(result.status).toBe('validation-error')
		})

		it('rejects a password over 128 characters', async () => {
			const { registration } = buildEngines()

			const result = await registration.execute({
				email: 'longpw@example.com',
				password: 'a1'.repeat(70), // 140 chars
			})

			expect(result.status).toBe('validation-error')
		})

		it('does NOT create a user when validation fails', async () => {
			const { registration, adapter } = buildEngines()

			await registration.execute({
				email: 'not-an-email',
				password: 'CorrectHorse9',
			})

			expect(await adapter.findUserByEmail('not-an-email')).toBeNull()
		})
	})

	describe('response floor', () => {
		it('holds successful registration to at least responseFloorMs', async () => {
			const { registration } = buildEngines({ responseFloorMs: 60 })

			const start = Date.now()
			await registration.execute({
				email: 'floor-test@example.com',
				password: 'CorrectHorse9',
			})
			const elapsed = Date.now() - start

			expect(elapsed).toBeGreaterThanOrEqual(55) // small tolerance for scheduler jitter
		})

		it('does NOT hold the validation-error path to the floor (documents current behavior)', async () => {
			const { registration } = buildEngines({ responseFloorMs: 200 })

			const start = Date.now()
			await registration.execute({
				email: 'not-an-email',
				password: 'CorrectHorse9',
			})
			const elapsed = Date.now() - start

			// Documents the current implementation: the validation try/catch in
			// execute() returns before `start`/holdToFloor are ever reached, so
			// a validation-error response is fast regardless of
			// responseFloorMs. Flagged separately as a worthwhile consistency
			// fix (LoginEngine's equivalent path DOES floor validation
			// failures) — this test exists to make that gap visible and
			// catch any accidental change to it either way.
			expect(elapsed).toBeLessThan(100)
		})
	})

	describe('system error handling', () => {
		it('reports via onSystemError and returns system-error when the adapter throws unexpectedly', async () => {
			const { registration, adapter, onSystemError } = buildEngines()
			vi.spyOn(adapter, 'findUserByEmail').mockRejectedValueOnce(
				new Error('db connection lost'),
			)

			const result = await registration.execute({
				email: 'boom@example.com',
				password: 'CorrectHorse9',
			})

			expect(result.status).toBe('system-error')
			expect(onSystemError).toHaveBeenCalledTimes(1)
			expect(onSystemError.mock.calls[0][0]).toBeInstanceOf(Error)
		})

		it('does not leak the raw internal error message to the caller', async () => {
			const { registration, adapter } = buildEngines()
			vi.spyOn(adapter, 'findUserByEmail').mockRejectedValueOnce(
				new Error('super secret internal db schema detail'),
			)

			const result = await registration.execute({
				email: 'boom2@example.com',
				password: 'CorrectHorse9',
			})

			expect(result).toMatchObject({ status: 'system-error' })
			if (result.status === 'system-error') {
				expect(result.message).not.toContain('super secret')
			}
		})
	})

	describe('purgeExpiredRegistrations', () => {
		it('deletes pending users past the grace period and leaves recent/verified ones', async () => {
			const { registration, adapter } = buildEngines()

			const old = new Date(Date.now() - 1000 * 60 * 60 * 24 * 3) // 3 days ago
			adapter.seedUser({
				email: 'old-pending@example.com',
				verificationStatus: 'pending',
				createdAt: old,
			})
			adapter.seedUser({
				email: 'recent-pending@example.com',
				verificationStatus: 'pending',
				createdAt: new Date(),
			})
			adapter.seedUser({
				email: 'old-verified@example.com',
				verificationStatus: 'verified',
				createdAt: old,
			})

			const { purgedCount } = await registration.purgeExpiredRegistrations()

			expect(purgedCount).toBe(1)
			expect(
				await adapter.findUserByEmail('old-pending@example.com'),
			).toBeNull()
			expect(
				await adapter.findUserByEmail('recent-pending@example.com'),
			).not.toBeNull()
			expect(
				await adapter.findUserByEmail('old-verified@example.com'),
			).not.toBeNull()
		})
	})
})
