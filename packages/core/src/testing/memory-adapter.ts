// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { randomUUID } from 'node:crypto'
import type {
	AuthRepoAdapter,
	AuthSessionAdapter,
	Session,
	TemporaryMfaToken,
	User,
	VerificationToken,
} from '../../types.js'

type RefreshTokenRecord = {
	userId: string
	familyId: string
	status: 'active' | 'used'
	expiresAt: Date
}

/**
 * An in-memory implementation of both adapter contracts.
 *
 * ⚠️ NOT FOR PRODUCTION. Everything is lost on restart, nothing is shared
 * between processes, and there is no durability or concurrency control
 * beyond what a single Node process gives you. Use it to try Beaver-Auth
 * in a minute, to write examples, and to test your own integration. For a
 * real application, implement the adapter contracts against your database.
 */
export interface MemoryAdapter extends AuthRepoAdapter, AuthSessionAdapter {
	/** Removes all stored data. Handy between tests. */
	reset(): void

	/**
	 * Reads back the JTIs recorded by `recordRevokedJti`. Pass it as
	 * `isJwtRevoked` in the middleware config to get logout-before-expiry
	 * for JWTs while developing.
	 */
	isJtiRevoked(jti: string): Promise<boolean>
}

export function createMemoryAdapter(): MemoryAdapter {
	const users = new Map<string, User>()
	const userIdByEmail = new Map<string, string>()
	const sessions = new Map<string, Session>()
	const refreshTokens = new Map<string, RefreshTokenRecord>()
	const verificationTokens = new Map<string, VerificationToken>()
	const mfaChallengeTokens = new Map<string, TemporaryMfaToken>()
	const revokedJtis = new Set<string>()

	const emailKey = (email: string) => email.trim().toLowerCase()

	// Adapters hand back copies so engines can never mutate stored state by
	// accident — the same guarantee a database gives you for free.
	const copyUser = (user: User): User => ({
		...user,
		profile: { ...user.profile },
	})

	const removeWhere = <T>(
		map: Map<string, T>,
		predicate: (value: T) => boolean,
	): number => {
		let removed = 0
		for (const [key, value] of map) {
			if (predicate(value)) {
				map.delete(key)
				removed++
			}
		}
		return removed
	}

	const deleteUser = (id: string): void => {
		const user = users.get(id)
		if (!user) return
		users.delete(id)
		userIdByEmail.delete(emailKey(user.email))
		// Mirror the ON DELETE CASCADE you would normally have.
		removeWhere(sessions, (s) => s.userId === id)
		removeWhere(refreshTokens, (t) => t.userId === id)
		removeWhere(mfaChallengeTokens, (t) => t.userId === id)
	}

	return {
		// ── AuthRepoAdapter: users ──────────────────────────────────────

		async createUser(data) {
			const key = emailKey(data.email)
			if (userIdByEmail.has(key)) {
				// A real database would raise a unique-constraint violation here.
				throw new Error('MemoryAdapter: a user with this email already exists')
			}
			const user: User = {
				id: randomUUID(),
				email: data.email,
				passwordHash: data.passwordHash,
				role: data.role,
				profile: { ...data.profile },
				verificationStatus: data.verificationStatus,
				mfaSecret: null,
				mfaEnabled: false,
				createdAt: new Date(),
			}
			users.set(user.id, user)
			userIdByEmail.set(key, user.id)
			return copyUser(user)
		},

		async findUserByEmail(email) {
			const id = userIdByEmail.get(emailKey(email))
			const user = id ? users.get(id) : undefined
			return user ? copyUser(user) : null
		},

		async findUserById(id) {
			const user = users.get(id)
			return user ? copyUser(user) : null
		},

		async updateUser(id, data) {
			const user = users.get(id)
			if (!user) throw new Error('MemoryAdapter: user not found')
			if (data.passwordHash !== undefined) user.passwordHash = data.passwordHash
			if (data.mfaSecret !== undefined) user.mfaSecret = data.mfaSecret
			if (data.mfaEnabled !== undefined) user.mfaEnabled = data.mfaEnabled
			return copyUser(user)
		},

		async markUserVerified(id) {
			const user = users.get(id)
			if (user) user.verificationStatus = 'verified'
		},

		async updateLastUsedTotpStep(userId, step) {
			const user = users.get(userId)
			if (user) user.lastUsedTotpStep = step
		},

		deleteUserById: async (id) => deleteUser(id),

		async deleteExpiredUnverifiedUsers(cutoff) {
			let removed = 0
			for (const user of [...users.values()]) {
				if (
					user.verificationStatus === 'pending' &&
					user.createdAt.getTime() < cutoff.getTime()
				) {
					deleteUser(user.id)
					removed++
				}
			}
			return removed
		},

		// ── AuthRepoAdapter: verification tokens ────────────────────────

		async setVerificationToken(token) {
			verificationTokens.set(token.identifier, { ...token })
		},

		async getVerificationToken(identifier) {
			const token = verificationTokens.get(identifier)
			return token ? { ...token } : null
		},

		async deleteVerificationToken(identifier) {
			verificationTokens.delete(identifier)
		},

		// ── AuthRepoAdapter: refresh tokens ─────────────────────────────

		async createRefreshToken(record) {
			const { tokenHash, ...rest } = record
			refreshTokens.set(tokenHash, { ...rest })
		},

		async findRefreshTokenByHash(tokenHash) {
			const record = refreshTokens.get(tokenHash)
			return record ? { ...record } : null
		},

		async markRefreshTokenUsed(tokenHash) {
			const record = refreshTokens.get(tokenHash)
			if (record) record.status = 'used'
		},

		async revokeRefreshTokenFamily(familyId) {
			removeWhere(refreshTokens, (t) => t.familyId === familyId)
		},

		async revokeAllRefreshTokensForUser(userId) {
			removeWhere(refreshTokens, (t) => t.userId === userId)
		},

		async deleteExpiredRefreshTokens(cutoff) {
			return removeWhere(
				refreshTokens,
				(t) => t.expiresAt.getTime() < cutoff.getTime(),
			)
		},

		// ── AuthRepoAdapter: JWT revocation ─────────────────────────────

		async recordRevokedJti(jti) {
			revokedJtis.add(jti)
		},

		// ── AuthSessionAdapter: sessions ────────────────────────────────

		async createSession(data) {
			const session: Session = { ...data }
			sessions.set(session.tokenHash, session)
			return { ...session }
		},

		async findSessionByTokenHash(hash) {
			const session = sessions.get(hash)
			if (!session) return null
			const user = users.get(session.userId)
			if (!user) return null
			return { ...session, user: copyUser(user) }
		},

		async updateSessionExpiry(tokenHash, date) {
			const session = sessions.get(tokenHash)
			if (session) session.expiresAt = date
		},

		async deleteSessionByTokenHash(tokenHash) {
			sessions.delete(tokenHash)
		},

		async deleteUserSessions(userId) {
			removeWhere(sessions, (s) => s.userId === userId)
		},

		// ── AuthSessionAdapter: MFA challenge tokens ────────────────────

		async createMfaChallengeToken(options) {
			const token: TemporaryMfaToken = { ...options }
			mfaChallengeTokens.set(token.tokenHash, token)
			return { ...token }
		},

		async findMfaChallengeTokenByHash(tokenHash) {
			const token = mfaChallengeTokens.get(tokenHash)
			return token ? { userId: token.userId, expiresAt: token.expiresAt } : null
		},

		async deleteMfaChallengeTokenByHash(tokenHash) {
			mfaChallengeTokens.delete(tokenHash)
		},

		async deleteExpiredMfaChallengeTokens(date) {
			return removeWhere(
				mfaChallengeTokens,
				(t) => t.expiresAt.getTime() < date.getTime(),
			)
		},

		// ── Helpers that are not part of the adapter contracts ──────────

		reset() {
			users.clear()
			userIdByEmail.clear()
			sessions.clear()
			refreshTokens.clear()
			verificationTokens.clear()
			mfaChallengeTokens.clear()
			revokedJtis.clear()
		},

		async isJtiRevoked(jti) {
			return revokedJtis.has(jti)
		},
	}
}
