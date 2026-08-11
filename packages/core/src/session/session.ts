// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { AuthSessionAdapter, Session, User } from '../../types.js'
import {
	generateSecureToken,
	hashSecureToken,
} from '../internal/secure-token.js'

export interface SessionManagerConfig {
	adapter: AuthSessionAdapter
	sessionTimeoutMs?: number // Defaults to 30 days
	mfaChallengeTimeoutMs?: number // Defaults to 5 minutes
}

export class SessionManager {
	private adapter: AuthSessionAdapter
	private timeoutMs: number
	private mfaChallengeTimeoutMs: number

	private static readonly DEFAULT_MFA_CHALLENGE_TIMEOUT_MS = 1000 * 60 * 5 // 5 minutes

	constructor(config: SessionManagerConfig) {
		this.adapter = config.adapter
		this.timeoutMs = config.sessionTimeoutMs ?? 1000 * 60 * 60 * 24 * 30 // 30 days
		this.mfaChallengeTimeoutMs =
			config.mfaChallengeTimeoutMs ??
			SessionManager.DEFAULT_MFA_CHALLENGE_TIMEOUT_MS
	}

	public async create(
		userId: string,
		context?: { userAgent?: string; ipAddress?: string },
	): Promise<{ token: string; session: Session }> {
		const rawToken = generateSecureToken()
		const tokenHash = hashSecureToken(rawToken)
		const expiresAt = new Date(Date.now() + this.timeoutMs)

		const session = await this.adapter.createSession({
			tokenHash,
			userId,
			expiresAt,
			userAgent: context?.userAgent,
			ipAddress: context?.ipAddress,
		})

		return { token: rawToken, session }
	}

	/**
	 * Validates a session token. Extends expiration if valid and past the
	 * halfway mark, or purges if expired. `expiryExtended` tells the caller
	 * (e.g. cookie middleware) whether an extension actually happened on
	 * this call, so callers never need to reimplement or guess at the
	 * half-life logic themselves.
	 */
	public async validate(rawToken: string): Promise<{
		session: Session
		user: User
		expiryExtended: boolean
	} | null> {
		const tokenHash = hashSecureToken(rawToken)
		const result = await this.adapter.findSessionByTokenHash(tokenHash)
		if (!result) return null

		const { user, ...session } = result
		const isExpired = Date.now() >= session.expiresAt.getTime()

		if (isExpired) {
			await this.adapter.deleteSessionByTokenHash(tokenHash)
			return null
		}

		const halfLife = this.timeoutMs / 2
		const timeRemaining = session.expiresAt.getTime() - Date.now()
		let expiryExtended = false

		if (timeRemaining < halfLife) {
			const newExpiration = new Date(Date.now() + this.timeoutMs)
			await this.adapter.updateSessionExpiry(tokenHash, newExpiration)
			session.expiresAt = newExpiration
			expiryExtended = true
		}

		return { session, user, expiryExtended }
	}

	public async invalidate(rawToken: string): Promise<void> {
		const tokenHash = hashSecureToken(rawToken)
		await this.adapter.deleteSessionByTokenHash(tokenHash)
	}

	public async createTemporaryMfaToken(userId: string): Promise<string> {
		const rawToken = generateSecureToken()
		const tokenHash = hashSecureToken(rawToken)
		const expiresAt = new Date(Date.now() + this.mfaChallengeTimeoutMs)

		await this.adapter.createMfaChallengeToken({
			tokenHash,
			userId,
			expiresAt,
		})

		return rawToken
	}

	public async verifyTemporaryMfaToken(
		rawToken: string,
	): Promise<{ userId: string; isExpired: boolean } | null> {
		const tokenHash = hashSecureToken(rawToken)
		const tokenRecord =
			await this.adapter.findMfaChallengeTokenByHash(tokenHash)
		if (!tokenRecord) return null

		const isExpired = Date.now() >= tokenRecord.expiresAt.getTime()

		return {
			userId: tokenRecord.userId,
			isExpired,
		}
	}

	public async revokeTemporaryMfaToken(rawToken: string): Promise<void> {
		const tokenHash = hashSecureToken(rawToken)
		await this.adapter.deleteMfaChallengeTokenByHash(tokenHash)
	}

	public async purgeExpiredMfaChallengeTokens(): Promise<{
		purgedCount: number
	}> {
		const purgedCount = await this.adapter.deleteExpiredMfaChallengeTokens(
			new Date(),
		)
		return { purgedCount }
	}
}
