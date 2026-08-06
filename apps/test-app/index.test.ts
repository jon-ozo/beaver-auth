import { describe, expect, it, vi } from 'vitest'
import {
	createBeaverAuth,
	VerificationEngine,
	PasswordResetEngine,
	AuthMiddlewareEngine,
} from '@beaver-auth/core'
import { MockAdapter } from './support/mock-adapter.js'
import { SyncTaskDispatcher } from './support/sync-dispatcher.js'
import type {
	VerificationHookPayload,
	PasswordResetHookPayload,
} from '@beaver-auth/core'

const JWT_SECRET = 'a-test-secret-that-is-at-least-32-bytes-long'
const PASSWORD = 'CorrectHorse9'

describe('createBeaverAuth — minimal config (adapter only)', () => {
	it('constructs registration, login, and sessions, with everything else undefined/empty', () => {
		const adapter = new MockAdapter()
		const auth = createBeaverAuth({ adapter })

		expect(auth.registration).toBeDefined()
		expect(auth.login).toBeDefined()
		expect(auth.sessions).toBeDefined()
		expect(auth.verification).toBeUndefined()
		expect(auth.passwordReset).toBeUndefined()
		expect(auth.middleware).toBeUndefined()
		expect(auth.rateLimiters).toEqual({})
	})

	it('an unverified-by-default registration immediately logs in without a pending/unverified step', async () => {
		const adapter = new MockAdapter()
		const auth = createBeaverAuth({ adapter })

		const regResult = await auth.registration.execute({
			email: 'user@example.com',
			password: PASSWORD,
		})
		expect(regResult).toEqual({ status: 'success' })

		const loginResult = await auth.login.executePasswordStage(
			{ email: 'user@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		expect(loginResult.status).toBe('success-session')
	})
})

describe('createBeaverAuth — the returned bundle is immutable', () => {
	it('throws when attempting to reassign a top-level property', () => {
		const adapter = new MockAdapter()
		const auth = createBeaverAuth({ adapter })

		expect(() => {
			;(auth as any).login = null
		}).toThrow(TypeError)
	})

	it('throws when attempting to reassign a nested rateLimiters property', () => {
		const adapter = new MockAdapter()
		const auth = createBeaverAuth({
			adapter,
			rateLimiters: {
				login: {
					algorithm: 'token-bucket',
					maxTokens: 5,
					refillRateMs: 1000,
					refillAmount: 1,
				},
			},
		})

		expect(() => {
			;(auth.rateLimiters as any).login = null
		}).toThrow(TypeError)
	})
})

describe('createBeaverAuth — verification wiring', () => {
	it('shares ONE VerificationEngine/hook configuration between registration and resendVerification', async () => {
		const adapter = new MockAdapter()
		const received: VerificationHookPayload[] = []

		const auth = createBeaverAuth({
			adapter,
			verification: {
				hooks: {
					onVerificationRequired: async (payload) => {
						received.push(payload)
					},
				},
				dispatcher: new SyncTaskDispatcher(),
			},
		})

		expect(auth.verification).toBeInstanceOf(VerificationEngine)

		await auth.registration.execute({
			email: 'user@example.com',
			password: PASSWORD,
		})
		expect(received).toHaveLength(1)

		// resendVerification (on LoginEngine) must go through the exact same
		// configured hook — proving both engines share the same
		// VerificationEngine wiring, not two independently-configured ones.
		const resendResult = await auth.login.resendVerification({
			email: 'user@example.com',
			password: PASSWORD,
		})
		expect(resendResult).toEqual({ status: 'resent' })
		await vi.waitFor(() => expect(received).toHaveLength(2))
		expect(received[1].email).toBe('user@example.com')
	})

	it('registration is pending and login is blocked until verifyEmail completes', async () => {
		const adapter = new MockAdapter()
		const received: VerificationHookPayload[] = []
		const auth = createBeaverAuth({
			adapter,
			verification: {
				hooks: { onVerificationRequired: async (p) => void received.push(p) },
				dispatcher: new SyncTaskDispatcher(),
			},
		})

		await auth.registration.execute({
			email: 'user@example.com',
			password: PASSWORD,
		})

		const blockedLogin = await auth.login.executePasswordStage(
			{ email: 'user@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		expect(blockedLogin.status).toBe('unverified')

		const verifyResult = await auth.verification!.verifyEmail(
			'user@example.com',
			received[0].token,
		)
		expect(verifyResult.status).toBe('success')

		const allowedLogin = await auth.login.executePasswordStage(
			{ email: 'user@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		expect(allowedLogin.status).toBe('success-session')
	})
})

describe('createBeaverAuth — password reset wiring', () => {
	it('bundle.passwordReset is present only when configured, and is fully functional', async () => {
		const adapter = new MockAdapter()
		const received: PasswordResetHookPayload[] = []
		const auth = createBeaverAuth({
			adapter,
			passwordReset: {
				hooks: { onPasswordResetRequested: async (p) => void received.push(p) },
				dispatcher: new SyncTaskDispatcher(),
			},
		})

		expect(auth.passwordReset).toBeInstanceOf(PasswordResetEngine)

		await auth.registration.execute({
			email: 'user@example.com',
			password: PASSWORD,
		})
		await auth.passwordReset!.requestReset('user@example.com')
		expect(received).toHaveLength(1)

		const newPassword = 'BrandNewPassword9'
		const resetResult = await auth.passwordReset!.completeReset(
			'user@example.com',
			received[0].token,
			newPassword,
		)
		expect(resetResult.status).toBe('success')

		const oldPwLogin = await auth.login.executePasswordStage(
			{ email: 'user@example.com', password: PASSWORD },
			JWT_SECRET,
		)
		expect(oldPwLogin).toEqual({ status: 'invalid-credentials' })

		const newPwLogin = await auth.login.executePasswordStage(
			{ email: 'user@example.com', password: newPassword },
			JWT_SECRET,
		)
		expect(newPwLogin.status).toBe('success-session')
	})
})

describe('createBeaverAuth — middleware wiring', () => {
	it('is undefined when not configured', () => {
		const auth = createBeaverAuth({ adapter: new MockAdapter() })
		expect(auth.middleware).toBeUndefined()
	})

	it('REGRESSION GUARD: constructs AuthMiddlewareEngine with the correct argument order — a real JWT signed with the configured secret validates', async () => {
		// This is the exact bug found and fixed earlier: the factory used to
		// call `new AuthMiddlewareEngine(sessions, cookieOptions, jwtConfig)`
		// — cookieOptions and jwtConfig swapped relative to the real
		// constructor signature `(sessions, jwtConfig, cookieOptions)`. Under
		// that bug, handleJwtRequest would have no real secret/adapter to
		// work with. This test proves the wiring is correct end-to-end by
		// actually validating a real, freshly-issued JWT through it.
		const adapter = new MockAdapter()
		const auth = createBeaverAuth({
			adapter,
			middleware: { jwtSecret: JWT_SECRET },
		})

		expect(auth.middleware).toBeInstanceOf(AuthMiddlewareEngine)

		await auth.registration.execute({
			email: 'user@example.com',
			password: PASSWORD,
		})
		const loginResult = await auth.login.executePasswordStage(
			{ email: 'user@example.com', password: PASSWORD },
			JWT_SECRET,
			undefined,
			{ sessionType: 'jwt' },
		)
		if (loginResult.status !== 'success-jwt')
			throw new Error('expected success-jwt')

		const middlewareResult = await auth.middleware!.handleJwtRequest(
			`Bearer ${loginResult.accessToken}`,
		)
		expect(middlewareResult.valid).toBe(true)
	})

	it('cookieOptions actually reach the middleware (further proof the argument order is correct)', () => {
		const adapter = new MockAdapter()
		const auth = createBeaverAuth({
			adapter,
			middleware: {
				jwtSecret: JWT_SECRET,
				cookieOptions: { name: 'my_custom_cookie' },
			},
		})

		const cookie = auth.middleware!.setSessionCookie(
			'abc',
			new Date(Date.now() + 10000),
		)
		expect(cookie).toMatch(/^my_custom_cookie=/)
	})
})

describe('createBeaverAuth — rate limiter wiring', () => {
	it('constructs only the configured rate limiters, each independently functional', async () => {
		const adapter = new MockAdapter()
		const auth = createBeaverAuth({
			adapter,
			rateLimiters: {
				login: {
					algorithm: 'token-bucket',
					maxTokens: 1,
					refillRateMs: 1000,
					refillAmount: 1,
				},
			},
		})

		expect(auth.rateLimiters.login).toBeDefined()
		expect(auth.rateLimiters.registration).toBeUndefined()
		expect(auth.rateLimiters.passwordReset).toBeUndefined()

		const first = await auth.rateLimiters.login!.acquire('user-a')
		const second = await auth.rateLimiters.login!.acquire('user-a')
		expect(first.success).toBe(true)
		expect(second.success).toBe(false)
	})
})

describe('createBeaverAuth — shared onSystemError', () => {
	it('a single provided onSystemError is used by registration AND the nested verification engine', async () => {
		const adapter = new MockAdapter()
		const onSystemError = vi.fn()

		const auth = createBeaverAuth({
			adapter,
			onSystemError,
			verification: {
				hooks: { onVerificationRequired: vi.fn() },
				dispatcher: new SyncTaskDispatcher(),
			},
		})

		vi.spyOn(adapter, 'findUserByEmail').mockRejectedValueOnce(
			new Error('db down'),
		)
		await auth.registration.execute({
			email: 'a@example.com',
			password: PASSWORD,
		})
		expect(onSystemError).toHaveBeenCalledTimes(1)

		// Trigger a verification-level (nested engine) system error — proves
		// the SAME onSystemError reached the VerificationEngine constructed
		// internally by the factory, not a separate default logger.
		vi.spyOn(adapter, 'setVerificationToken').mockRejectedValue(
			new Error('db down again'),
		)
		await auth.registration.execute({
			email: 'b@example.com',
			password: PASSWORD,
		})
		await vi.waitFor(() =>
			expect(onSystemError.mock.calls.length).toBeGreaterThan(1),
		)
	})
})

describe('createBeaverAuth — full realistic end-to-end flow', () => {
	it('register → verify → login (jwt) → refresh → logout, all through one bundle', async () => {
		const adapter = new MockAdapter()
		const received: VerificationHookPayload[] = []
		const auth = createBeaverAuth({
			adapter,
			verification: {
				hooks: { onVerificationRequired: async (p) => void received.push(p) },
				dispatcher: new SyncTaskDispatcher(),
			},
		})

		const regResult = await auth.registration.execute({
			email: 'e2e@example.com',
			password: PASSWORD,
		})
		expect(regResult).toEqual({ status: 'success-pending-verification' })

		await auth.verification!.verifyEmail('e2e@example.com', received[0].token)

		const loginResult = await auth.login.executePasswordStage(
			{ email: 'e2e@example.com', password: PASSWORD },
			JWT_SECRET,
			undefined,
			{ sessionType: 'jwt' },
		)
		if (loginResult.status !== 'success-jwt')
			throw new Error('expected success-jwt')

		const refreshed = await auth.login.refreshAccessToken(
			loginResult.refreshToken,
			JWT_SECRET,
		)
		expect(refreshed.status).toBe('success-jwt')

		await auth.login.logoutJwtSession(loginResult.familyId)

		const afterLogout = await auth.login.refreshAccessToken(
			loginResult.refreshToken,
			JWT_SECRET,
		)
		expect(afterLogout.status).toBe('invalid-credentials')
	})
})
