import { describe, expect, it, vi } from 'vitest'
import { VerificationEngine, LocalTaskDispatcher } from '@beaver-auth/core'
import { MockAdapter } from './support/mock-adapter.js'
import { SyncTaskDispatcher } from './support/sync-dispatcher.js'
import type { VerificationHookPayload } from '@beaver-auth/core'

function buildEngine(dispatcher: SyncTaskDispatcher | LocalTaskDispatcher, onSystemError = vi.fn()) {
	const adapter = new MockAdapter()
	const received: VerificationHookPayload[] = []
	const engine = new VerificationEngine({
		adapter,
		hooks: {
			onVerificationRequired: async (payload) => {
				received.push(payload)
			},
		},
		dispatcher,
		onSystemError,
	})
	return { adapter, engine, received, onSystemError }
}

describe('VerificationEngine.createAndDispatch + verifyEmail', () => {
	it('creates a token, dispatches the hook with correct payload, and the token verifies the right user', async () => {
		const { adapter, engine, received } = buildEngine(new SyncTaskDispatcher())
		const user = adapter.seedUser({
			email: 'verify-me@example.com',
			verificationStatus: 'pending',
		})

		await engine.createAndDispatch({ email: user.email, userId: user.id })

		expect(received).toHaveLength(1)
		expect(received[0].email).toBe(user.email)
		expect(received[0].userId).toBe(user.id)
		expect(received[0].token).toMatch(/^[0-9a-f]{64}$/)

		const result = await engine.verifyEmail(user.email, received[0].token)
		expect(result).toEqual({ status: 'success', userId: user.id })

		const updated = await adapter.findUserById(user.id)
		expect(updated!.verificationStatus).toBe('verified')
	})

	it('REGRESSION GUARD: works correctly against the real, default LocalTaskDispatcher (not just the test SyncTaskDispatcher)', async () => {
		// This is the exact bug found and fixed while building this suite:
		// LocalTaskDispatcher.dispatch() was missing its `payload` parameter,
		// which silently shifted every subsequent argument by one position.
		// The payload object landed in the `handler` slot, and calling it as
		// a function threw at runtime — while TypeScript's structural typing
		// let it compile clean because the interface's `payload: unknown`
		// accepted anything. This test exercises the REAL dispatcher (not
		// the deterministic test double) end-to-end specifically so a
		// regression here is caught by the suite, not just by code review.
		const onSystemError = vi.fn()
		const dispatcher = new LocalTaskDispatcher({ onSystemError })
		const { adapter, engine, received } = buildEngine(dispatcher, onSystemError)
		const user = adapter.seedUser({
			email: 'real-dispatcher@example.com',
			verificationStatus: 'pending',
		})

		await engine.createAndDispatch({ email: user.email, userId: user.id })

		// LocalTaskDispatcher runs the handler via setImmediate — wait for it.
		await vi.waitFor(() => expect(received).toHaveLength(1), { timeout: 2000 })

		expect(onSystemError).not.toHaveBeenCalled()
		expect(received[0].email).toBe(user.email)
		expect(received[0].userId).toBe(user.id)

		const result = await engine.verifyEmail(user.email, received[0].token)
		expect(result.status).toBe('success')
	})

	it('a token is single-use — verifying twice with the same token fails the second time', async () => {
		const { adapter, engine, received } = buildEngine(new SyncTaskDispatcher())
		const user = adapter.seedUser({
			email: 'single-use@example.com',
			verificationStatus: 'pending',
		})

		await engine.createAndDispatch({ email: user.email, userId: user.id })
		const token = received[0].token

		const first = await engine.verifyEmail(user.email, token)
		expect(first.status).toBe('success')

		const second = await engine.verifyEmail(user.email, token)
		expect(second).toEqual({ status: 'invalid-token' })
	})

	it('rejects an incorrect token for a real pending user', async () => {
		const { adapter, engine } = buildEngine(new SyncTaskDispatcher())
		const user = adapter.seedUser({
			email: 'wrong-token@example.com',
			verificationStatus: 'pending',
		})

		const result = await engine.verifyEmail(user.email, 'a'.repeat(64))
		expect(result).toEqual({ status: 'invalid-token' })
	})

	it('rejects a token presented against the wrong email', async () => {
		const { adapter, engine, received } = buildEngine(new SyncTaskDispatcher())
		const userA = adapter.seedUser({
			email: 'user-a@example.com',
			verificationStatus: 'pending',
		})
		adapter.seedUser({ email: 'user-b@example.com', verificationStatus: 'pending' })

		await engine.createAndDispatch({ email: userA.email, userId: userA.id })
		const tokenForA = received[0].token

		const result = await engine.verifyEmail('user-b@example.com', tokenForA)
		expect(result).toEqual({ status: 'invalid-token' })

		// user-a should remain unverified since ITS token wasn't consumed by
		// this failed cross-account attempt... actually it WAS consumed
		// (tokens are keyed by purpose+email, so this call looked up
		// user-b's identifier, found nothing, and consumed nothing of
		// user-a's). Confirm user-a's real token still works.
		const realAttempt = await engine.verifyEmail(userA.email, tokenForA)
		expect(realAttempt).toEqual({ status: 'success', userId: userA.id })
	})

	it('does not mark a nonexistent user verified even with a token that happens to match nothing', async () => {
		const { engine } = buildEngine(new SyncTaskDispatcher())
		const result = await engine.verifyEmail('ghost@example.com', 'a'.repeat(64))
		expect(result).toEqual({ status: 'invalid-token' })
	})

	it('retries token creation on transient adapter failure, then succeeds', async () => {
		const { adapter, engine, received } = buildEngine(
			new SyncTaskDispatcher(),
		)
		const user = adapter.seedUser({
			email: 'retry-me@example.com',
			verificationStatus: 'pending',
		})

		const spy = vi.spyOn(adapter, 'setVerificationToken')
		spy.mockRejectedValueOnce(new Error('transient db blip'))

		const engineWithFastRetry = new VerificationEngine({
			adapter,
			hooks: {
				onVerificationRequired: async (p) => {
					received.push(p)
				},
			},
			dispatcher: new SyncTaskDispatcher(),
			tokenCreationRetry: { maxRetries: 2, initialDelayMs: 5, backoffFactor: 2 },
		})

		await engineWithFastRetry.createAndDispatch({ email: user.email, userId: user.id })

		expect(received).toHaveLength(1)
		expect(spy).toHaveBeenCalledTimes(2)
	})

	it('reports via onSystemError and leaves the user unverified when token creation exhausts all retries', async () => {
		const { adapter, onSystemError } = buildEngine(new SyncTaskDispatcher())
		const user = adapter.seedUser({
			email: 'always-fails@example.com',
			verificationStatus: 'pending',
		})
		vi.spyOn(adapter, 'setVerificationToken').mockRejectedValue(
			new Error('db is down'),
		)

		const engine = new VerificationEngine({
			adapter,
			hooks: { onVerificationRequired: vi.fn() },
			dispatcher: new SyncTaskDispatcher(),
			onSystemError,
			tokenCreationRetry: { maxRetries: 1, initialDelayMs: 1, backoffFactor: 1 },
		})

		await engine.createAndDispatch({ email: user.email, userId: user.id })

		expect(onSystemError).toHaveBeenCalled()
		const updated = await adapter.findUserById(user.id)
		expect(updated!.verificationStatus).toBe('pending')
	})
})
