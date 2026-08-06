import {
	AuthRepoAdapter,
	VerificationHooks,
	TaskDispatcher,
	VerificationHookPayload,
	VerifyEmailResult,
} from '../../types.js'
import { TokenEngine } from '../internal/token.js'
import { LocalTaskDispatcher } from '../register/in-memory-dispatcher.js'
import {
	DEFAULT_RETRY_OPTIONS,
	RetryOptions,
	retryWithBackoff,
} from '../internal/retry.js'

export interface VerificationEngineConfig {
	adapter: AuthRepoAdapter
	hooks: VerificationHooks
	dispatcher?: TaskDispatcher
	onSystemError?: (error: unknown) => void

	/**
	 * Retry/backoff settings for verification token creation (a single DB
	 * write). Independent of the TaskDispatcher's retry settings, which
	 * govern hook dispatch separately.
	 * @default { maxRetries: 3, initialDelayMs: 1000, backoffFactor: 2 }
	 */
	tokenCreationRetry?: RetryOptions

	/** @default 900000 (15 minutes) */
	defaultTokenTimeoutMs?: number
}

/**
 * Owns the full lifecycle of an email-verification token: creating one and
 * dispatching a hook to send it (createAndDispatch), and later validating a
 * presented token and reporting the result (verifyEmail). Deliberately not
 * scoped to registration — RegistrationEngine uses this for the initial
 * verification email, LoginEngine uses the same instance for resending a
 * verification email to an unverified user at login time. Any future
 * "verify a changed email address" flow would reuse this too.
 */
export class VerificationEngine {
	private adapter: AuthRepoAdapter
	private tokens: TokenEngine
	private hooks: VerificationHooks
	private dispatcher: TaskDispatcher
	private onSystemError: (error: unknown) => void
	private tokenCreationRetry: RetryOptions
	private defaultTokenTimeoutMs: number

	private static readonly DEFAULT_TOKEN_TIMEOUT_MS = 1000 * 60 * 15 // 15 minutes

	constructor(config: VerificationEngineConfig) {
		this.adapter = config.adapter
		this.tokens = new TokenEngine({ adapter: config.adapter })
		this.onSystemError =
			config.onSystemError ??
			((error) => {
				console.error('[beaver-auth]', error)
			})
		this.hooks = config.hooks
		this.dispatcher =
			config.dispatcher ??
			new LocalTaskDispatcher({ onSystemError: this.onSystemError })
		this.tokenCreationRetry = config.tokenCreationRetry ?? DEFAULT_RETRY_OPTIONS
		this.defaultTokenTimeoutMs =
			config.defaultTokenTimeoutMs ??
			VerificationEngine.DEFAULT_TOKEN_TIMEOUT_MS
	}

	/**
	 * Creates a verification token (retried per tokenCreationRetry) and hands
	 * dispatch of the "send it" hook off to the configured TaskDispatcher,
	 * which owns all retry/backoff for the hook itself. Fire-and-forget by
	 * design — callers should not await this on a response path; if it
	 * ultimately fails after all retries, the affected user simply stays
	 * unverified and can be resent a link later (see LoginEngine.resendVerification).
	 */
	public async createAndDispatch(params: {
		email: string
		userId: string
		timeoutMs?: number
	}): Promise<void> {
		let token: string
		let expiresAt: Date

		try {
			const created = await retryWithBackoff(
				() =>
					this.tokens.create(
						params.email,
						'email-verification',
						params.timeoutMs ?? this.defaultTokenTimeoutMs,
					),
				this.tokenCreationRetry,
				(attempt, max, delay, error) => {
					this.onSystemError(
						new Error(
							`[Queue Retry] Verification token creation for user ` +
								`${params.userId} failed (attempt ${attempt}/${max}). ` +
								`Retrying in ${delay}ms. Cause: ${
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
					`Verification token creation exhausted all ` +
						`${this.tokenCreationRetry.maxRetries} retries for user ` +
						`${params.userId} (${params.email}); left unverified. Cause: ` +
						`${err instanceof Error ? err.message : String(err)}`,
				),
			)
			return
		}

		const hookPayload: VerificationHookPayload = {
			email: params.email,
			userId: params.userId,
			token,
			expiresAt,
		}

		await this.dispatcher.dispatch(
			'verification-hook',
			hookPayload,
			async () => {
				await this.hooks.onVerificationRequired(hookPayload)
			},
			async (error) => {
				this.onSystemError(
					new Error(
						`Verification hook dispatch exhausted retries for user ` +
							`${params.userId} (${params.email}); left unverified. Cause: ` +
							`${error instanceof Error ? error.message : String(error)}`,
					),
				)
			},
		)
	}

	/**
	 * Validates a presented token (single-use, via TokenEngine.consume) and,
	 * if valid, flips the user to 'verified'.
	 */
	public async verifyEmail(
		email: string,
		token: string,
	): Promise<VerifyEmailResult> {
		try {
			const isValid = await this.tokens.consume(
				email,
				token,
				'email-verification',
			)
			if (!isValid) {
				return { status: 'invalid-token' }
			}

			const user = await this.adapter.findUserByEmail(email)
			if (!user) {
				return { status: 'invalid-token' }
			}

			await this.adapter.markUserVerified(user.id)
			return { status: 'success', userId: user.id }
		} catch (err) {
			this.onSystemError(err)
			return {
				status: 'system-error',
				message:
					'An unexpected internal core auth engine processing exception was securely handled.',
			}
		}
	}
}
