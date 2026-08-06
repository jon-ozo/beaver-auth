import { randomUUID } from 'node:crypto'
import type {
	AuthRepoAdapter,
	AuthSessionAdapter,
	Session,
	TemporaryMfaToken,
	User,
	VerificationToken,
} from '@beaver-auth/core'

interface RefreshTokenRecord {
	tokenHash: string
	userId: string
	familyId: string
	status: 'active' | 'used'
	expiresAt: Date
}

interface SessionRecord extends Session {
	// storage-only convenience — mirrors Session, kept separate from the
	// public shape returned to callers
}

/**
 * Full in-memory implementation of AuthRepoAdapter & AuthSessionAdapter, for
 * use in tests only. Deliberately simple (Maps, linear scans) — this is a
 * test double, not a reference implementation for real adapter authors.
 */
export class MockAdapter implements AuthRepoAdapter, AuthSessionAdapter {
	users = new Map<string, User>()
	verificationTokens = new Map<string, VerificationToken>()
	refreshTokens = new Map<string, RefreshTokenRecord>()
	sessions = new Map<string, SessionRecord>()
	mfaChallengeTokens = new Map<string, TemporaryMfaToken>()
	revokedJtis = new Set<string>()

	// ── test helpers (not part of either adapter interface) ──────────────

	/** Directly inserts a fully-formed user, bypassing createUser's ID/date generation, for test setup. */
	seedUser(partial: Partial<User> & { email: string }): User {
		const user: User = {
			id: partial.id ?? randomUUID(),
			profile: partial.profile ?? {},
			email: partial.email,
			passwordHash: partial.passwordHash ?? null,
			role: partial.role ?? 'user',
			mfaSecret: partial.mfaSecret ?? null,
			mfaEnabled: partial.mfaEnabled ?? false,
			createdAt: partial.createdAt ?? new Date(),
			verificationStatus: partial.verificationStatus ?? 'verified',
			lastUsedTotpStep: partial.lastUsedTotpStep,
		}
		this.users.set(user.id, user)
		return user
	}

	reset(): void {
		this.users.clear()
		this.verificationTokens.clear()
		this.refreshTokens.clear()
		this.sessions.clear()
		this.mfaChallengeTokens.clear()
		this.revokedJtis.clear()
	}

	// ── AuthRepoAdapter ────────────────────────────────────────────────

	async createRefreshToken(record: RefreshTokenRecord): Promise<void> {
		this.refreshTokens.set(record.tokenHash, { ...record })
	}

	async createUser(data: {
		email: string
		passwordHash: string | null
		role: string
		profile: Record<string, unknown>
		verificationStatus: 'pending' | 'verified'
	}): Promise<User> {
		const user: User = {
			id: randomUUID(),
			profile: data.profile,
			email: data.email,
			passwordHash: data.passwordHash,
			role: data.role,
			mfaSecret: null,
			mfaEnabled: false,
			createdAt: new Date(),
			verificationStatus: data.verificationStatus,
		}
		this.users.set(user.id, user)
		return user
	}

	async findUserByEmail(email: string): Promise<User | null> {
		for (const user of this.users.values()) {
			if (user.email === email) return user
		}
		return null
	}

	async findUserById(id: string): Promise<User | null> {
		return this.users.get(id) ?? null
	}

	async deleteUserById(id: string): Promise<void> {
		this.users.delete(id)
	}

	async deleteExpiredUnverifiedUsers(date: Date): Promise<number> {
		let count = 0
		for (const [id, user] of this.users.entries()) {
			if (user.verificationStatus === 'pending' && user.createdAt < date) {
				this.users.delete(id)
				count++
			}
		}
		return count
	}

	async deleteExpiredRefreshTokens(cutoff: Date): Promise<number> {
		let count = 0
		for (const [hash, record] of this.refreshTokens.entries()) {
			if (record.expiresAt < cutoff) {
				this.refreshTokens.delete(hash)
				count++
			}
		}
		return count
	}

	async deleteVerificationToken(identifier: string): Promise<void> {
		this.verificationTokens.delete(identifier)
	}

	async findRefreshTokenByHash(tokenHash: string): Promise<{
		userId: string
		familyId: string
		status: 'active' | 'used'
		expiresAt: Date
	} | null> {
		const record = this.refreshTokens.get(tokenHash)
		if (!record) return null
		return {
			userId: record.userId,
			familyId: record.familyId,
			status: record.status,
			expiresAt: record.expiresAt,
		}
	}

	async getVerificationToken(
		identifier: string,
	): Promise<VerificationToken | null> {
		return this.verificationTokens.get(identifier) ?? null
	}

	async markRefreshTokenUsed(tokenHash: string): Promise<void> {
		const record = this.refreshTokens.get(tokenHash)
		if (record) record.status = 'used'
	}

	async markUserVerified(id: string): Promise<void> {
		const user = this.users.get(id)
		if (user) user.verificationStatus = 'verified'
	}

	async recordRevokedJti(jti: string): Promise<void> {
		this.revokedJtis.add(jti)
	}

	async revokeRefreshTokenFamily(familyId: string): Promise<void> {
		for (const [hash, record] of this.refreshTokens.entries()) {
			if (record.familyId === familyId) this.refreshTokens.delete(hash)
		}
	}

	async revokeAllRefreshTokensForUser(userId: string): Promise<void> {
		for (const [hash, record] of this.refreshTokens.entries()) {
			if (record.userId === userId) this.refreshTokens.delete(hash)
		}
	}

	async setVerificationToken(token: VerificationToken): Promise<void> {
		this.verificationTokens.set(token.identifier, token)
	}

	async updateLastUsedTotpStep(userId: string, step: number): Promise<void> {
		const user = this.users.get(userId)
		if (user) user.lastUsedTotpStep = step
	}

	async updateUser(
		id: string,
		data: Partial<Pick<User, 'passwordHash' | 'mfaSecret' | 'mfaEnabled'>>,
	): Promise<User> {
		const user = this.users.get(id)
		if (!user) throw new Error(`MockAdapter.updateUser: no user with id ${id}`)
		Object.assign(user, data)
		return user
	}

	// ── AuthSessionAdapter ─────────────────────────────────────────────

	async createMfaChallengeToken(options: {
		tokenHash: string
		userId: string
		expiresAt: Date
	}): Promise<TemporaryMfaToken> {
		const record: TemporaryMfaToken = { ...options }
		this.mfaChallengeTokens.set(options.tokenHash, record)
		return record
	}

	async createSession(data: {
		tokenHash: string
		userId: string
		expiresAt: Date
		userAgent?: string
		ipAddress?: string
	}): Promise<Session> {
		const session: SessionRecord = { ...data }
		this.sessions.set(data.tokenHash, session)
		return session
	}

	async deleteExpiredMfaChallengeTokens(date: Date): Promise<number> {
		let count = 0
		for (const [hash, record] of this.mfaChallengeTokens.entries()) {
			if (record.expiresAt < date) {
				this.mfaChallengeTokens.delete(hash)
				count++
			}
		}
		return count
	}

	async deleteMfaChallengeTokenByHash(tokenHash: string): Promise<void> {
		this.mfaChallengeTokens.delete(tokenHash)
	}

	async deleteSessionByTokenHash(tokenHash: string): Promise<void> {
		this.sessions.delete(tokenHash)
	}

	async deleteUserSessions(userId: string): Promise<void> {
		for (const [hash, session] of this.sessions.entries()) {
			if (session.userId === userId) this.sessions.delete(hash)
		}
	}

	async findMfaChallengeTokenByHash(
		tokenHash: string,
	): Promise<{ userId: string; expiresAt: Date } | null> {
		const record = this.mfaChallengeTokens.get(tokenHash)
		if (!record) return null
		return { userId: record.userId, expiresAt: record.expiresAt }
	}

	async findSessionByTokenHash(
		hash: string,
	): Promise<(Session & { user: User }) | null> {
		const session = this.sessions.get(hash)
		if (!session) return null
		const user = this.users.get(session.userId)
		if (!user) return null
		return { ...session, user }
	}

	async updateSessionExpiry(tokenHash: string, date: Date): Promise<void> {
		const session = this.sessions.get(tokenHash)
		if (session) session.expiresAt = date
	}
}
