import { describe, expect, it, vi } from 'vitest'
import { RefreshTokenEngine } from '@beaver-auth/core'
import { MockAdapter } from './support/mock-adapter.js'

function buildEngine(opts?: { refreshTokenTimeoutMs?: number }) {
	const adapter = new MockAdapter()
	const onSystemError = vi.fn()
	const engine = new RefreshTokenEngine({
		adapter,
		onSystemError,
		refreshTokenTimeoutMs: opts?.refreshTokenTimeoutMs,
	})
	return { adapter, onSystemError, engine }
}

describe('RefreshTokenEngine.issue', () => {
	it('creates an active refresh token record, storing only the hash', async () => {
		const { adapter, engine } = buildEngine()

		const { refreshToken, familyId, expiresAt } = await engine.issue('user-1')

		expect(refreshToken).toMatch(/^[0-9a-f]{64}$/)
		expect(familyId).toMatch(/^[0-9a-f]{64}$/)
		expect(expiresAt.getTime()).toBeGreaterThan(Date.now())
		expect(adapter.refreshTokens.has(refreshToken)).toBe(false) // raw token never stored as key

		const rotation = await engine.rotate(refreshToken)
		expect(rotation.status).toBe('success') // proves it round-trips correctly
	})

	it('issues a fresh, distinct family each time', async () => {
		const { engine } = buildEngine()
		const a = await engine.issue('user-1')
		const b = await engine.issue('user-1')
		expect(a.familyId).not.toBe(b.familyId)
		expect(a.refreshToken).not.toBe(b.refreshToken)
	})
})

describe('RefreshTokenEngine.rotate', () => {
	it('rotation issues a NEW token in the SAME family and marks the old one used', async () => {
		const { adapter, engine } = buildEngine()
		const { refreshToken, familyId } = await engine.issue('user-1')

		const result = await engine.rotate(refreshToken)

		expect(result.status).toBe('success')
		if (result.status !== 'success') throw new Error('unreachable')
		expect(result.familyId).toBe(familyId)
		expect(result.refreshToken).not.toBe(refreshToken)
		expect(result.userId).toBe('user-1')

		// Exactly 2 records now exist for this family: the old (used) one
		// and the new (active) one.
		const familyRecords = [...adapter.refreshTokens.values()].filter(
			(r) => r.familyId === familyId,
		)
		expect(familyRecords).toHaveLength(2)
		expect(familyRecords.filter((r) => r.status === 'used')).toHaveLength(1)
		expect(familyRecords.filter((r) => r.status === 'active')).toHaveLength(1)
	})

	it('returns invalid for a token that was never issued', async () => {
		const { engine } = buildEngine()
		const result = await engine.rotate('f'.repeat(64))
		expect(result).toEqual({ status: 'invalid' })
	})

	it('returns expired for a token past its expiry, without rotating or marking it used', async () => {
		const { adapter, engine } = buildEngine({ refreshTokenTimeoutMs: 10 })
		const { refreshToken, familyId } = await engine.issue('user-1')

		await new Promise((r) => setTimeout(r, 30))

		const result = await engine.rotate(refreshToken)
		expect(result).toEqual({ status: 'expired' })

		const familyRecords = [...adapter.refreshTokens.values()].filter(
			(r) => r.familyId === familyId,
		)
		expect(familyRecords).toHaveLength(1)
		expect(familyRecords[0].status).toBe('active')
	})

	it('reusing an already-rotated token triggers reuse detection and revokes the WHOLE family', async () => {
		const { adapter, engine, onSystemError } = buildEngine()
		const { refreshToken, familyId } = await engine.issue('user-1')

		const firstRotation = await engine.rotate(refreshToken)
		expect(firstRotation.status).toBe('success')

		const reuseResult = await engine.rotate(refreshToken)
		expect(reuseResult).toEqual({
			status: 'reused-token-family-revoked',
			userId: 'user-1',
			familyId,
		})
		expect(onSystemError).toHaveBeenCalledTimes(1)

		const familyRecords = [...adapter.refreshTokens.values()].filter(
			(r) => r.familyId === familyId,
		)
		expect(familyRecords).toHaveLength(0)

		if (firstRotation.status === 'success') {
			const secondRotationAttempt = await engine.rotate(firstRotation.refreshToken)
			expect(secondRotationAttempt).toEqual({ status: 'invalid' })
		}
	})

	it('a rotation chain can continue multiple times within the same family', async () => {
		const { engine } = buildEngine()
		const { refreshToken, familyId } = await engine.issue('user-1')

		const r1 = await engine.rotate(refreshToken)
		if (r1.status !== 'success') throw new Error('unreachable')
		const r2 = await engine.rotate(r1.refreshToken)
		if (r2.status !== 'success') throw new Error('unreachable')
		const r3 = await engine.rotate(r2.refreshToken)

		expect(r3.status).toBe('success')
		if (r3.status === 'success') {
			expect(r3.familyId).toBe(familyId)
		}
	})
})

describe('RefreshTokenEngine.revokeFamily / revokeAllForUser', () => {
	it('revokeFamily removes only that family, leaving other families for the same user intact', async () => {
		const { engine } = buildEngine()
		const familyA = await engine.issue('user-1')
		const familyB = await engine.issue('user-1')

		await engine.revokeFamily(familyA.familyId)

		expect(await engine.rotate(familyA.refreshToken)).toEqual({ status: 'invalid' })
		const stillValid = await engine.rotate(familyB.refreshToken)
		expect(stillValid.status).toBe('success')
	})

	it('revokeAllForUser removes every family for that user but not other users', async () => {
		const { engine } = buildEngine()
		const userAFamily1 = await engine.issue('user-a')
		const userAFamily2 = await engine.issue('user-a')
		const userBFamily = await engine.issue('user-b')

		await engine.revokeAllForUser('user-a')

		expect(await engine.rotate(userAFamily1.refreshToken)).toEqual({ status: 'invalid' })
		expect(await engine.rotate(userAFamily2.refreshToken)).toEqual({ status: 'invalid' })
		expect((await engine.rotate(userBFamily.refreshToken)).status).toBe('success')
	})
})

describe('RefreshTokenEngine.purgeExpiredRefreshTokens', () => {
	it('removes expired tokens regardless of status, and leaves unexpired ones', async () => {
		const { adapter, engine } = buildEngine()

		await adapter.createRefreshToken({
			tokenHash: 'expired-active',
			userId: 'user-1',
			familyId: 'fam-1',
			status: 'active',
			expiresAt: new Date(Date.now() - 1000),
		})
		await adapter.createRefreshToken({
			tokenHash: 'expired-used',
			userId: 'user-1',
			familyId: 'fam-1',
			status: 'used',
			expiresAt: new Date(Date.now() - 1000),
		})
		await adapter.createRefreshToken({
			tokenHash: 'still-valid',
			userId: 'user-1',
			familyId: 'fam-2',
			status: 'active',
			expiresAt: new Date(Date.now() + 100_000),
		})

		const { purgedCount } = await engine.purgeExpiredRefreshTokens()

		expect(purgedCount).toBe(2)
		expect(adapter.refreshTokens.has('expired-active')).toBe(false)
		expect(adapter.refreshTokens.has('expired-used')).toBe(false)
		expect(adapter.refreshTokens.has('still-valid')).toBe(true)
	})
})
