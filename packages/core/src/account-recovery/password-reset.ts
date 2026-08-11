// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import {
	AuthRepoAdapter,
	AuthSessionAdapter,
	PasswordResetHooks,
	PasswordResetHookPayload,
	TaskDispatcher,
	RequestPasswordResetResult,
	CompletePasswordResetResult,
} from '../../types.js'
import { CryptoEngine } from '../internal/crypto.js'
import { TokenEngine } from '../internal/token.js'
import { ValidationEngine } from '../internal/validation.js'
import { ValidationError } from '../internal/error.js'
import { LocalTaskDispatcher } from '../register/in-memory-dispatcher.js'
import { holdToFloor } from '../internal/hold-to-floor.js'
import { completeAccountRecovery } from '../internal/complete-account-recovery.js'
import {
	DEFAULT_RETRY_OPTIONS,
	RetryOptions,
	retryWithBackoff,
} from '../internal/retry.js'

export interface PasswordResetEngineConfig {
	adapter: AuthRepoAdapter & AuthSessionAdapter
	hooks: PasswordResetHooks
	dispatcher?: TaskDispatcher
	onSystemError?: (error: unknown) => void
	tokenCreationRetry?: RetryOptions
	defaultTokenTimeoutMs?: number
	responseFloorMs?: number
}

export class PasswordResetEngine {
	private adapter: AuthRepoAdapter & AuthSessionAdapter
	private crypto: CryptoEngine
	private tokens: TokenEngine
	private validation: ValidationEngine
	private hooks: PasswordResetHooks
	private dispatcher: TaskDispatcher
	private onSystemError: (error: unknown) => void
	private tokenCreationRetry: RetryOptions
	private defaultTokenTimeoutMs: number
	private responseFloorMs: number

	private static readonly DEFAULT_TOKEN_TIMEOUT_MS = 1000 * 60 * 15
	private static readonly DEFAULT_RESPONSE_FLOOR_MS = 150

	constructor(config: PasswordResetEngineConfig) {
		this.adapter = config.adapter
		this.crypto = new CryptoEngine()
		this.tokens = new TokenEngine({ adapter: config.adapter })
		this.validation = new ValidationEngine()
		this.hooks = config.hooks
		this.onSystemError =
			config.onSystemError ??
			((error) => {
				console.error('[beaver-auth]', error)
			})
		this.dispatcher =
			config.dispatcher ??
			new LocalTaskDispatcher({ onSystemError: this.onSystemError })
		this.tokenCreationRetry = config.tokenCreationRetry ?? DEFAULT_RETRY_OPTIONS
		this.defaultTokenTimeoutMs =
			config.defaultTokenTimeoutMs ??
			PasswordResetEngine.DEFAULT_TOKEN_TIMEOUT_MS
		this.responseFloorMs =
			config.responseFloorMs ?? PasswordResetEngine.DEFAULT_RESPONSE_FLOOR_MS
	}

	public async requestReset(
		rawEmail: unknown,
		timeoutMs?: number,
	): Promise<RequestPasswordResetResult> {
		const start = Date.now()

		try {
			if (typeof rawEmail !== 'string' || !rawEmail.trim()) {
				await holdToFloor(this.responseFloorMs, start)
				return {
					status: 'validation-error',
					message: "Field 'email' is required.",
				}
			}

			const email = rawEmail.trim().toLowerCase()
			const user = await this.adapter.findUserByEmail(email)

			if (user) {
				void this.createAndDispatch(user.id, email, timeoutMs).catch((err) => {
					this.onSystemError(err)
				})
			}

			await holdToFloor(this.responseFloorMs, start)
			return { status: 'request-processed' }
		} catch (err) {
			this.onSystemError(err)
			await holdToFloor(this.responseFloorMs, start)
			return {
				status: 'system-error',
				message:
					'An unexpected internal core auth engine processing exception was securely handled.',
			}
		}
	}

	/**
	 * Completes a password reset: validates the token (single-use), then
	 * delegates to the shared completeAccountRecovery step (set new password
	 * hash, revoke all sessions/refresh tokens) — the same step any future
	 * recovery method (SMS, backup codes, etc.) will use once identity is
	 * re-proven through its own channel-specific check.
	 */
	public async completeReset(
		rawEmail: unknown,
		token: string,
		rawNewPassword: unknown,
	): Promise<CompletePasswordResetResult> {
		const start = Date.now()

		try {
			if (typeof rawEmail !== 'string' || !rawEmail.trim()) {
				await holdToFloor(this.responseFloorMs, start)
				return {
					status: 'validation-error',
					message: "Field 'email' is required.",
				}
			}

			let newPassword: string
			try {
				newPassword = this.validation.validateNewPassword(rawNewPassword)
			} catch (validationError: unknown) {
				await holdToFloor(this.responseFloorMs, start)
				const message =
					validationError instanceof ValidationError
						? validationError.message
						: 'Invalid password.'
				return { status: 'validation-error', message }
			}

			const email = rawEmail.trim().toLowerCase()

			const isValid = await this.tokens.consume(email, token, 'password-reset')
			if (!isValid) {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-token' }
			}

			const user = await this.adapter.findUserByEmail(email)
			if (!user) {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-token' }
			}

			const passwordHash = await this.crypto.hashPassword(newPassword)

			// Identity re-proven via the email token above (channel-specific
			// step, unique to this recovery method) — everything from here on
			// is the shared "recovery completed" routine, reused as-is by any
			// future recovery method once ITS OWN identity check succeeds.
			await completeAccountRecovery(
				this.adapter,
				user.id,
				passwordHash,
				this.onSystemError,
			)

			await holdToFloor(this.responseFloorMs, start)
			return { status: 'success', userId: user.id }
		} catch (err) {
			this.onSystemError(err)
			await holdToFloor(this.responseFloorMs, start)
			return {
				status: 'system-error',
				message:
					'An unexpected internal core auth engine processing exception was securely handled.',
			}
		}
	}

	private async createAndDispatch(
		userId: string,
		email: string,
		timeoutMs?: number,
	): Promise<void> {
		let token: string
		let expiresAt: Date

		try {
			const created = await retryWithBackoff(
				() =>
					this.tokens.create(
						email,
						'password-reset',
						timeoutMs ?? this.defaultTokenTimeoutMs,
					),
				this.tokenCreationRetry,
				(attempt, max, delay, error) => {
					this.onSystemError(
						new Error(
							`[Queue Retry] Password reset token creation for user ` +
								`${userId} failed (attempt ${attempt}/${max}). Retrying in ` +
								`${delay}ms. Cause: ${
									error instanceof Error ? error.message : String(error)
								}`,
						),
					)
				},
			)
			token = created.token
			expiresAt = created.expiresAt
		} catch (err) {
			this.onSystemError(
				new Error(
					`Password reset token creation exhausted all ` +
						`${this.tokenCreationRetry.maxRetries} retries for user ${userId} ` +
						`(${email}). Cause: ${err instanceof Error ? err.message : String(err)}`,
				),
			)
			return
		}

		const hookPayload: PasswordResetHookPayload = {
			email,
			userId,
			token,
			expiresAt,
		}

		await this.dispatcher.dispatch(
			'password-reset-hook',
			hookPayload,
			async () => {
				await this.hooks.onPasswordResetRequested(hookPayload)
			},
			async (error) => {
				this.onSystemError(
					new Error(
						`Password reset hook dispatch exhausted retries for user ` +
							`${userId} (${email}). Cause: ${
								error instanceof Error ? error.message : String(error)
							}`,
					),
				)
			},
		)
	}
}
