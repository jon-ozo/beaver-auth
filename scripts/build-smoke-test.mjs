// Deliberately importing from the BUILT dist output, not source — this
// simulates exactly what a real npm-installed consumer would experience.
//
// This is intentionally separate from the Vitest suite (apps/test-app),
// which aliases @beaver-auth/core straight to source for fast iteration and
// never actually exercises the built artifact.

// Usage: pnpm --filter @beaver-auth/core run build && node scripts/build-smoke-test.mjs
import { createAuth } from '../packages/core/dist/index.js'

// Minimal in-memory adapter, built fresh here (not reusing test helpers)
// specifically so this smoke test has zero dependency on the test suite —
// it should stand alone as proof the published package works.
class SmokeAdapter {
	users = new Map()
	verificationTokens = new Map()
	refreshTokens = new Map()
	sessions = new Map()
	mfaChallengeTokens = new Map()

	async createUser(data) {
		const user = { id: crypto.randomUUID(), createdAt: new Date(), ...data }
		this.users.set(user.id, user)
		return user
	}
	async findUserByEmail(email) {
		for (const u of this.users.values()) if (u.email === email) return u
		return null
	}
	async findUserById(id) {
		return this.users.get(id) ?? null
	}
	async deleteUserById(id) {
		this.users.delete(id)
	}
	async deleteExpiredUnverifiedUsers() {
		return 0
	}
	async deleteExpiredRefreshTokens() {
		return 0
	}
	async deleteVerificationToken(id) {
		this.verificationTokens.delete(id)
	}
	async setVerificationToken(t) {
		this.verificationTokens.set(t.identifier, t)
	}
	async getVerificationToken(id) {
		return this.verificationTokens.get(id) ?? null
	}
	async markUserVerified(id) {
		const u = this.users.get(id)
		if (u) u.verificationStatus = 'verified'
	}
	async updateUser(id, data) {
		const u = this.users.get(id)
		Object.assign(u, data)
		return u
	}
	async updateLastUsedTotpStep() {}
	async recordRevokedJti() {}
	async createRefreshToken(r) {
		this.refreshTokens.set(r.tokenHash, r)
	}
	async findRefreshTokenByHash(h) {
		return this.refreshTokens.get(h) ?? null
	}
	async markRefreshTokenUsed(h) {
		const r = this.refreshTokens.get(h)
		if (!r || r.status !== 'active') return false
		r.status = 'used'
		return true
	}
	async revokeRefreshTokenFamily(fid) {
		for (const [h, r] of this.refreshTokens)
			if (r.familyId === fid) this.refreshTokens.delete(h)
	}
	async revokeAllRefreshTokensForUser(uid) {
		for (const [h, r] of this.refreshTokens)
			if (r.userId === uid) this.refreshTokens.delete(h)
	}
	async createSession(d) {
		this.sessions.set(d.tokenHash, d)
		return d
	}
	async findSessionByTokenHash(h) {
		const s = this.sessions.get(h)
		if (!s) return null
		return { ...s, user: this.users.get(s.userId) }
	}
	async deleteSessionByTokenHash(h) {
		this.sessions.delete(h)
	}
	async deleteUserSessions(uid) {
		for (const [h, s] of this.sessions)
			if (s.userId === uid) this.sessions.delete(h)
	}
	async updateSessionExpiry(h, exp) {
		const s = this.sessions.get(h)
		if (s) s.expiresAt = exp
	}
	async createMfaChallengeToken(o) {
		this.mfaChallengeTokens.set(o.tokenHash, o)
		return o
	}
	async findMfaChallengeTokenByHash(h) {
		return this.mfaChallengeTokens.get(h) ?? null
	}
	async deleteMfaChallengeTokenByHash(h) {
		this.mfaChallengeTokens.delete(h)
	}
	async deleteExpiredMfaChallengeTokens() {
		return 0
	}
}

const adapter = new SmokeAdapter()
const received = []

const auth = createAuth({
	adapter,
	verification: {
		hooks: {
			onVerificationRequired: async (payload) => {
				received.push(payload)
			},
		},
		dispatcher: {
			async dispatch(taskName, payload, handler) {
				await handler()
			},
		},
	},
})

let failed = false
function check(label, condition) {
	console.log(`${condition ? 'PASS' : 'FAIL'}: ${label}`)
	if (!condition) failed = true
}

const reg = await auth.registration.execute({
	email: 'smoke@example.com',
	password: 'CorrectHorse9',
})
check(
	'registration returns success-pending-verification',
	reg.status === 'success-pending-verification',
)
check(
	'verification hook fired with a token',
	received.length === 1 && typeof received[0].token === 'string',
)

const blocked = await auth.login.executePasswordStage(
	{ email: 'smoke@example.com', password: 'CorrectHorse9' },
	'a-smoke-test-secret-that-is-at-least-32-bytes',
)
check('login blocked before verification', blocked.status === 'unverified')

const verifyResult = await auth.verification.verifyEmail(
	'smoke@example.com',
	received[0].token,
)
check('email verification succeeds', verifyResult.status === 'success')

const login = await auth.login.executePasswordStage(
	{ email: 'smoke@example.com', password: 'CorrectHorse9' },
	'a-smoke-test-secret-that-is-at-least-32-bytes',
	undefined,
	{ sessionType: 'jwt' },
)
check('jwt login succeeds after verification', login.status === 'success-jwt')
check('familyId is present on the result', typeof login.familyId === 'string')

const refreshed = await auth.login.refreshAccessToken(
	login.refreshToken,
	'a-smoke-test-secret-that-is-at-least-32-bytes',
)
check('refresh token rotation succeeds', refreshed.status === 'success-jwt')

const reuseAttempt = await auth.login.refreshAccessToken(
	login.refreshToken,
	'a-smoke-test-secret-that-is-at-least-32-bytes',
)
check(
	'reusing the original (rotated-away) refresh token is detected',
	reuseAttempt.status === 'refresh-token-reused',
)

// Regression check: two concurrent rotate() calls on the same token must
// not both succeed — this is the real-world race condition this release
// fixes (markRefreshTokenUsed now atomically reports whether IT performed
// the active->used transition).
await auth.registration.execute({
	email: 'race@example.com',
	password: 'CorrectHorse9',
})
// createAndDispatch is fire-and-forget from registration — poll briefly
// for the hook to actually land before trying to verify.
for (let i = 0; i < 20 && received.length < 2; i++) {
	await new Promise((r) => setTimeout(r, 10))
}
const raceToken = received.find((p) => p.email === 'race@example.com')?.token
await auth.verification.verifyEmail('race@example.com', raceToken)
const raceLogin = await auth.login.executePasswordStage(
	{ email: 'race@example.com', password: 'CorrectHorse9' },
	'a-smoke-test-secret-that-is-at-least-32-bytes',
	undefined,
	{ sessionType: 'jwt' },
)
check(
	'race-test user login succeeds after verification',
	raceLogin.status === 'success-jwt',
)
const [raceA, raceB] = await Promise.all([
	auth.login.refreshAccessToken(
		raceLogin.refreshToken,
		'a-smoke-test-secret-that-is-at-least-32-bytes',
	),
	auth.login.refreshAccessToken(
		raceLogin.refreshToken,
		'a-smoke-test-secret-that-is-at-least-32-bytes',
	),
])
const raceStatuses = [raceA.status, raceB.status].sort()
check(
	'concurrent refresh of the same token: exactly one succeeds, the other is detected as reuse',
	JSON.stringify(raceStatuses) ===
		JSON.stringify(['refresh-token-reused', 'success-jwt']),
)

process.exit(failed ? 1 : 0)
