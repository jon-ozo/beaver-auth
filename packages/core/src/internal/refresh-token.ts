// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { AuthRepoAdapter } from '../../types.js'
import { generateSecureToken, hashSecureToken } from './secure-token.js'

export interface RefreshTokenEngineConfig {
	adapter: AuthRepoAdapter
	refreshTokenTimeoutMs?: number // Defaults to 30 days
	onSystemError?: (error: unknown) => void
}

export type RefreshResult =
	| {
			status: 'success'
			refreshToken: string
			userId: string
			familyId: string
	  }
	| { status: 'invalid' }
	| { status: 'expired' }
	// A used token was presented again — the entire family (every token
	// descended from one original login) has been revoked. The caller
	// MUST treat this as a security event: force full re-authentication,
	// and consider notifying the user (e.g. "new sign-in detected" email)
	// since this indicates a stolen token was in play.
	| { status: 'reused-token-family-revoked'; userId: string; familyId: string }

export class RefreshTokenEngine {
	private adapter: AuthRepoAdapter
	private timeoutMs: number
	private onSystemError: (error: unknown) => void

	private static readonly DEFAULT_TIMEOUT_MS = 1000 * 60 * 60 * 24 * 30 // 30 days

	constructor(config: RefreshTokenEngineConfig) {
		this.adapter = config.adapter
		this.timeoutMs =
			config.refreshTokenTimeoutMs ?? RefreshTokenEngine.DEFAULT_TIMEOUT_MS
		this.onSystemError =
			config.onSystemError ??
			((error) => {
				console.error('[beaver-auth]', error)
			})
	}

	/**
	 * Issues the first refresh token in a new family (i.e. at login). Every
	 * subsequent rotation for this login session stays in the same family,
	 * which is what makes family-wide revocation on reuse detection possible.
	 */
	public async issue(
		userId: string,
	): Promise<{ refreshToken: string; familyId: string; expiresAt: Date }> {
		const rawToken = generateSecureToken()
		const tokenHash = hashSecureToken(rawToken)
		const familyId = generateSecureToken()
		const expiresAt = new Date(Date.now() + this.timeoutMs)

		await this.adapter.createRefreshToken({
			tokenHash,
			userId,
			familyId,
			status: 'active',
			expiresAt,
		})

		return { refreshToken: rawToken, familyId, expiresAt }
	}

	/**
	 * Exchanges a refresh token for a new one (rotation). The old token is
	 * marked 'used', not deleted, specifically so a later replay of it can be
	 * detected as reuse rather than just failing as "not found."
	 */
	public async rotate(rawToken: string): Promise<RefreshResult> {
		const tokenHash = hashSecureToken(rawToken)
		const record = await this.adapter.findRefreshTokenByHash(tokenHash)

		if (!record) {
			return { status: 'invalid' }
		}

		if (record.status === 'used') {
			// Reuse of an already-rotated token. Whether this is the original
			// legitimate call happening twice (e.g. a network retry) or a
			// stolen token being replayed, we cannot safely distinguish the
			// two — so we fail closed and kill the whole family.
			await this.adapter.revokeRefreshTokenFamily(record.familyId)
			this.onSystemError(
				new Error(
					`Refresh token reuse detected for user ${record.userId}, ` +
						`family ${record.familyId}. Family revoked.`,
				),
			)
			return {
				status: 'reused-token-family-revoked',
				userId: record.userId,
				familyId: record.familyId,
			}
		}

		if (Date.now() >= record.expiresAt.getTime()) {
			return { status: 'expired' }
		}

		await this.adapter.markRefreshTokenUsed(tokenHash)

		const newRawToken = generateSecureToken()
		const newTokenHash = hashSecureToken(newRawToken)
		const expiresAt = new Date(Date.now() + this.timeoutMs)

		await this.adapter.createRefreshToken({
			tokenHash: newTokenHash,
			userId: record.userId,
			familyId: record.familyId,
			status: 'active',
			expiresAt,
		})

		return {
			status: 'success',
			refreshToken: newRawToken,
			userId: record.userId,
			familyId: record.familyId,
		}
	}

	/**
	 * Revokes every token in a family — used for explicit logout (kills the
	 * refresh chain so no further access tokens can be minted from it) and
	 * internally on reuse detection.
	 */
	public async revokeFamily(familyId: string): Promise<void> {
		await this.adapter.revokeRefreshTokenFamily(familyId)
	}

	/**
	 * Revokes every refresh token family belonging to a user — "log out
	 * everywhere."
	 */
	public async revokeAllForUser(userId: string): Promise<void> {
		await this.adapter.revokeAllRefreshTokensForUser(userId)
	}

	/**
	 * Sweeps refresh tokens (active or used) past their expiry. Not invoked
	 * internally — consumers should call this on a schedule, same pattern as
	 * the other purge methods in this package.
	 */
	public async purgeExpiredRefreshTokens(): Promise<{ purgedCount: number }> {
		const purgedCount = await this.adapter.deleteExpiredRefreshTokens(
			new Date(),
		)
		return { purgedCount }
	}
}
