import { describe, expect, it, vi } from 'vitest'
import {
	LoginEngine,
	SessionManager,
	CryptoEngine,
	TokenEngine,
} from '@beaver-auth/core'
import { MockAdapter } from './support/mock-adapter.js'
import { currentTotpCode, TEST_TOTP_SECRET } from './support/totp.js'

const JWT_SECRET = 'a-test-secret-that-is-at-least-32-bytes-long'
const PASSWORD = 'CorrectHorse9'

async function seedVerifiedUser(
	adapter: MockAdapter,
	overrides: Partial<Parameters<MockAdapter['seedUser']>[0]> = {},
) {
	const crypto = new CryptoEngine()
	const passwordHash = await crypto.hashPassword(PASSWORD)
	return adapter.seedUser({
		email: 'login-test@example.com',
		passwordHash,
		verificationStatus: 'verified',
		...overrides,
	})
}

function buildLoginEngine(opts?: { responseFloorMs?: number }) {
	const adapter = new MockAdapter()
	const sessions = new SessionManager({ adapter })
	const onSystemError = vi.fn()
	const login = new LoginEngine({
		adapter,
		sessions,
		onSystemError,
		responseFloorMs: opts?.responseFloorMs ?? 0,
	})
	return { adapter, sessions, onSystemError, login }
}

describe('LoginEngine.executePasswordStage', () => {
	it('returns invalid-credentials for a nonexistent email', async () => {
		const { login } = buildLoginEngine()
		const result = await login.executePasswordStage(
			{ email: 'nobody@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		expect(result).toEqual({ status: 'invalid-credentials' })
	})

	it('returns invalid-credentials for a wrong password', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedVerifiedUser(adapter)

		const result = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: 'WrongPassword9' },
			JWT_SECRET,
		)
		expect(result).toEqual({ status: 'invalid-credentials' })
	})

	it('gives the SAME response shape for a nonexistent user and a wrong password', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedVerifiedUser(adapter)

		const nonexistent = await login.executePasswordStage(
			{ email: 'nobody@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		const wrongPassword = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: 'WrongPassword9' },
			JWT_SECRET,
		)
		expect(nonexistent).toEqual(wrongPassword)
	})

	it('logs in successfully with the default (session) type and returns a usable session token', async () => {
		const { login, adapter, sessions } = buildLoginEngine()
		const user = await seedVerifiedUser(adapter)

		const result = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
		)

		expect(result.status).toBe('success-session')
		if (result.status !== 'success-session') throw new Error('unreachable')
		expect(result.user.id).toBe(user.id)
		expect(result.token).toMatch(/^[0-9a-f]{64}$/)

		const validated = await sessions.validate(result.token)
		expect(validated).not.toBeNull()
		expect(validated!.user.id).toBe(user.id)
	})

	it('logs in successfully with sessionType jwt and issues a verifiable access token plus a usable refresh token', async () => {
		const { login, adapter } = buildLoginEngine()
		const user = await seedVerifiedUser(adapter)
		const tokens = new TokenEngine({ adapter })

		const result = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
			undefined,
			{ sessionType: 'jwt' },
		)

		expect(result.status).toBe('success-jwt')
		if (result.status !== 'success-jwt') throw new Error('unreachable')
		expect(result.familyId).toBeTruthy()

		const verified = tokens.verifyJwtToken(result.accessToken, JWT_SECRET)
		expect(verified.valid).toBe(true)
		if (verified.valid) {
			expect(verified.payload.userId).toBe(user.id)
		}

		// familyId is what makes logout actually work — refreshAccessToken
		// should succeed once with the issued refresh token.
		const refreshed = await login.refreshAccessToken(
			result.refreshToken,
			JWT_SECRET,
		)
		expect(refreshed.status).toBe('success-jwt')
	})

	it('rejects login for an unverified (pending) user without revealing anything else', async () => {
		const { login, adapter } = buildLoginEngine()
		const user = await seedVerifiedUser(adapter, {
			verificationStatus: 'pending',
		})

		const result = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
		)

		expect(result).toEqual({ status: 'unverified', userId: user.id })
	})

	it('requires a correct password before ever revealing unverified status', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedVerifiedUser(adapter, { verificationStatus: 'pending' })

		const result = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: 'WrongPassword9' },
			JWT_SECRET,
		)

		// Wrong password on a pending account must still look identical to
		// wrong password on a verified account — never 'unverified'.
		expect(result).toEqual({ status: 'invalid-credentials' })
	})

	it('returns mfa-required for an MFA-enabled user and does not issue a session yet', async () => {
		const { login, adapter, sessions } = buildLoginEngine()
		await seedVerifiedUser(adapter, {
			mfaEnabled: true,
			mfaSecret: TEST_TOTP_SECRET,
		})

		const result = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
		)

		expect(result.status).toBe('mfa-required')
		if (result.status !== 'mfa-required') throw new Error('unreachable')
		expect(result.mfaChallengeToken).toMatch(/^[0-9a-f]{64}$/)

		// No session should exist yet — MFA stage hasn't completed.
		expect(adapter.sessions.size).toBe(0)
	})

	it('holds successful login to at least responseFloorMs', async () => {
		const { login, adapter } = buildLoginEngine({ responseFloorMs: 60 })
		await seedVerifiedUser(adapter)

		const start = Date.now()
		await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		expect(Date.now() - start).toBeGreaterThanOrEqual(55)
	})

	it('holds invalid-credentials (nonexistent user) to at least responseFloorMs too', async () => {
		const { login } = buildLoginEngine({ responseFloorMs: 60 })

		const start = Date.now()
		await login.executePasswordStage(
			{ email: 'nobody@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		expect(Date.now() - start).toBeGreaterThanOrEqual(55)
	})

	it('reports via onSystemError and returns system-error when the adapter throws unexpectedly', async () => {
		const { login, adapter, onSystemError } = buildLoginEngine()
		vi.spyOn(adapter, 'findUserByEmail').mockRejectedValueOnce(
			new Error('db down'),
		)

		const result = await login.executePasswordStage(
			{ email: 'anyone@example.com', password: PASSWORD },
			JWT_SECRET,
		)

		expect(result.status).toBe('system-error')
		expect(onSystemError).toHaveBeenCalledTimes(1)
	})
})

describe('LoginEngine MFA flow (executeMfaStage)', () => {
	async function seedMfaUser(adapter: MockAdapter) {
		return seedVerifiedUser(adapter, {
			mfaEnabled: true,
			mfaSecret: TEST_TOTP_SECRET,
		})
	}

	it('completes login with a valid TOTP code', async () => {
		const { login, adapter } = buildLoginEngine()
		const user = await seedMfaUser(adapter)

		const stage1 = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		if (stage1.status !== 'mfa-required')
			throw new Error('expected mfa-required')

		const code = currentTotpCode(TEST_TOTP_SECRET)
		const stage2 = await login.executeMfaStage(
			{ mfaChallengeToken: stage1.mfaChallengeToken, code },
			JWT_SECRET,
		)

		expect(stage2.status).toBe('success-session')
		if (stage2.status === 'success-session') {
			expect(stage2.user.id).toBe(user.id)
		}
	})

	it('rejects an incorrect TOTP code', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedMfaUser(adapter)

		const stage1 = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		if (stage1.status !== 'mfa-required')
			throw new Error('expected mfa-required')

		const stage2 = await login.executeMfaStage(
			{ mfaChallengeToken: stage1.mfaChallengeToken, code: '000000' },
			JWT_SECRET,
		)

		expect(stage2).toEqual({ status: 'invalid-mfa-code' })
	})

	it('the MFA challenge token is single-use — a second attempt (even with the correct code) fails', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedMfaUser(adapter)

		const stage1 = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		if (stage1.status !== 'mfa-required')
			throw new Error('expected mfa-required')

		const code = currentTotpCode(TEST_TOTP_SECRET)
		await login.executeMfaStage(
			{ mfaChallengeToken: stage1.mfaChallengeToken, code },
			JWT_SECRET,
		)

		const secondAttempt = await login.executeMfaStage(
			{ mfaChallengeToken: stage1.mfaChallengeToken, code },
			JWT_SECRET,
		)
		expect(secondAttempt).toEqual({ status: 'invalid-mfa-token' })
	})

	it('rejects replaying the same TOTP code across two separate MFA challenges', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedMfaUser(adapter)
		const code = currentTotpCode(TEST_TOTP_SECRET)

		const first = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		if (first.status !== 'mfa-required')
			throw new Error('expected mfa-required')
		const firstStage2 = await login.executeMfaStage(
			{ mfaChallengeToken: first.mfaChallengeToken, code },
			JWT_SECRET,
		)
		expect(firstStage2.status).toBe('success-session')

		// A fresh login attempt gets a NEW challenge token, but the same TOTP
		// code (same 30s window) should be rejected as a replay.
		const second = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		if (second.status !== 'mfa-required')
			throw new Error('expected mfa-required')
		const secondStage2 = await login.executeMfaStage(
			{ mfaChallengeToken: second.mfaChallengeToken, code },
			JWT_SECRET,
		)
		expect(secondStage2).toEqual({ status: 'invalid-mfa-code' })
	})
})

describe('LoginEngine refresh token rotation', () => {
	it('rotates the refresh token on use — the old token cannot be reused', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedVerifiedUser(adapter)

		const loginResult = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
			undefined,
			{ sessionType: 'jwt' },
		)
		if (loginResult.status !== 'success-jwt')
			throw new Error('expected success-jwt')

		const firstRefresh = await login.refreshAccessToken(
			loginResult.refreshToken,
			JWT_SECRET,
		)
		expect(firstRefresh.status).toBe('success-jwt')

		// Reusing the ORIGINAL (now-rotated-away) refresh token must fail —
		// and specifically as reuse detection, not a generic invalid token.
		const reuseAttempt = await login.refreshAccessToken(
			loginResult.refreshToken,
			JWT_SECRET,
		)
		expect(reuseAttempt.status).toBe('refresh-token-reused')
	})

	it('reused-token detection revokes the whole family — even the rotated (valid) token stops working', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedVerifiedUser(adapter)

		const loginResult = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
			undefined,
			{ sessionType: 'jwt' },
		)
		if (loginResult.status !== 'success-jwt')
			throw new Error('expected success-jwt')

		const firstRefresh = await login.refreshAccessToken(
			loginResult.refreshToken,
			JWT_SECRET,
		)
		if (firstRefresh.status !== 'success-jwt')
			throw new Error('expected success-jwt')

		// Trigger reuse detection on the original token.
		await login.refreshAccessToken(loginResult.refreshToken, JWT_SECRET)

		// The legitimately-rotated token should now ALSO be dead, since the
		// whole family was revoked.
		const afterFamilyRevoked = await login.refreshAccessToken(
			firstRefresh.refreshToken,
			JWT_SECRET,
		)
		expect(afterFamilyRevoked.status).toBe('invalid-credentials')
	})

	it('logoutJwtSession revokes the family — the refresh token stops working', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedVerifiedUser(adapter)

		const loginResult = await login.executePasswordStage(
			{ email: 'login-test@example.com', password: PASSWORD },
			JWT_SECRET,
			undefined,
			{ sessionType: 'jwt' },
		)
		if (loginResult.status !== 'success-jwt')
			throw new Error('expected success-jwt')

		await login.logoutJwtSession(loginResult.familyId)

		const afterLogout = await login.refreshAccessToken(
			loginResult.refreshToken,
			JWT_SECRET,
		)
		expect(afterLogout.status).toBe('invalid-credentials')
	})
})

describe('LoginEngine.resendVerification', () => {
	it('requires the correct password before revealing pending status', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedVerifiedUser(adapter, { verificationStatus: 'pending' })

		const result = await login.resendVerification({
			email: 'login-test@example.com',
			password: 'WrongPassword9',
		})
		expect(result).toEqual({ status: 'invalid-credentials' })
	})

	it('reports already-verified for a verified account with the correct password', async () => {
		const { login, adapter } = buildLoginEngine()
		await seedVerifiedUser(adapter, { verificationStatus: 'verified' })

		const result = await login.resendVerification({
			email: 'login-test@example.com',
			password: PASSWORD,
		})
		expect(result).toEqual({ status: 'already-verified' })
	})

	it('returns system-error (not a crash) when no VerificationEngine was configured, for a genuinely pending user', async () => {
		const { login, adapter, onSystemError } = buildLoginEngine()
		await seedVerifiedUser(adapter, { verificationStatus: 'pending' })

		const result = await login.resendVerification({
			email: 'login-test@example.com',
			password: PASSWORD,
		})

		expect(result.status).toBe('system-error')
		expect(onSystemError).toHaveBeenCalled()
	})
})
