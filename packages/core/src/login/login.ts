import {
	AuthRepoAdapter,
	LoginResult,
	ResendVerificationResult,
} from '../../types.js'
import { CryptoEngine } from '../internal/crypto.js'
import { SessionManager } from '../session/session.js'
import { VerificationEngine } from '../verification/verification.js'
import { TokenEngine } from '../internal/token.js'
import { ValidationEngine } from '../internal/validation.js'
import { RefreshTokenEngine } from '../internal/refresh-token.js'
import { holdToFloor } from '../internal/hold-to-floor.js'

export interface LoginEngineConfig {
	adapter: AuthRepoAdapter
	verification?: VerificationEngine
	sessions: SessionManager
	onSystemError?: (error: unknown) => void
	responseFloorMs?: number
}

export class LoginEngine {
	private adapter: AuthRepoAdapter
	private readonly verification?: VerificationEngine
	private crypto: CryptoEngine
	private sessions: SessionManager
	private tokens: TokenEngine
	private validation: ValidationEngine
	private onSystemError: (error: unknown) => void
	private responseFloorMs: number
	private static readonly STATIC_DUMMY_HASH =
		'scrypt$16384$8$1$73616c74$64756d6d7968617368'
	private readonly DEFAULT_SESSION_TYPE = 'session'
	private readonly FLAGS = ['jwt', this.DEFAULT_SESSION_TYPE]
	private readonly DEFAULT_TOKEN_TIMEOUT_MS = 1000 * 60 * 15 // 15 minutes
	private static readonly DEFAULT_RESPONSE_FLOOR_MS = 150
	private readonly refreshTokens: RefreshTokenEngine

	constructor(config: LoginEngineConfig) {
		this.adapter = config.adapter
		this.crypto = new CryptoEngine()
		this.tokens = new TokenEngine({ adapter: config.adapter })
		this.sessions = config.sessions
		this.verification = config.verification
		this.validation = new ValidationEngine()
		this.onSystemError =
			config.onSystemError ??
			((error) => {
				console.error('[beaver-auth]', error)
			})
		this.responseFloorMs =
			config.responseFloorMs ?? LoginEngine.DEFAULT_RESPONSE_FLOOR_MS
		this.refreshTokens = new RefreshTokenEngine({
			adapter: this.adapter,
			onSystemError: this.onSystemError,
		})
	}

	private async systemError(start: number): Promise<LoginResult> {
		return await holdToFloor(this.responseFloorMs, start).then(() => ({
			status: 'system-error',
			message:
				'An unexpected internal core auth engine processing exception was securely handled.',
		}))
	}

	public async executePasswordStage(
		rawInput: Record<string, unknown>,
		secret: string,
		context?: { userAgent?: string; ipAddress?: string },
		options?: { sessionType?: 'jwt' | 'session'; tokenTimeoutMs?: number },
	): Promise<LoginResult> {
		const start = Date.now()

		try {
			let sanitizedEmail = ''
			let providedPassword = ''

			try {
				const validated = this.validation.validateInputs(rawInput)
				sanitizedEmail = validated.email
				providedPassword = validated.password ?? ''
			} catch {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-credentials' }
			}

			const user = await this.adapter.findUserByEmail(sanitizedEmail)

			if (!user || !user.passwordHash) {
				await this.crypto.verifyPassword(
					providedPassword,
					LoginEngine.STATIC_DUMMY_HASH,
				)
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-credentials' }
			}

			const isPasswordValid = await this.crypto.verifyPassword(
				providedPassword,
				user.passwordHash,
			)

			if (!isPasswordValid) {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-credentials' }
			}

			if (user.verificationStatus === 'pending') {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'unverified', userId: user.id }
			}

			if (user.mfaEnabled) {
				const mfaChallengeToken = await this.sessions.createTemporaryMfaToken(
					user.id,
				)

				await holdToFloor(this.responseFloorMs, start)
				return {
					status: 'mfa-required',
					userId: user.id,
					mfaChallengeToken,
				}
			}

			const sessionType = options?.sessionType ?? this.DEFAULT_SESSION_TYPE

			if (sessionType && !this.FLAGS.includes(sessionType)) {
				throw new Error(
					`Invalid session type provided. Must be one of: ${this.FLAGS.join(', ')}`,
				)
			}

			if (sessionType === 'jwt') {
				const payload = { email: user.email, userId: user.id, role: user.role }
				const accessToken = this.tokens.createJwtToken(
					payload,
					options?.tokenTimeoutMs ?? this.DEFAULT_TOKEN_TIMEOUT_MS,
					secret,
				)
				const { refreshToken, familyId } = await this.refreshTokens.issue(
					user.id,
				)

				await holdToFloor(this.responseFloorMs, start)
				return {
					status: 'success-jwt',
					user,
					accessToken,
					refreshToken,
					familyId,
				}
			}

			const { token, session } = await this.sessions.create(user.id, context)

			await holdToFloor(this.responseFloorMs, start)
			return { status: 'success-session', user, session, token }
		} catch (err) {
			this.onSystemError(err)
			return this.systemError(start)
		}
	}

	public async refreshAccessToken(
		rawRefreshToken: string,
		secret: string,
		options?: { tokenTimeoutMs?: number },
	): Promise<LoginResult> {
		const start = Date.now()

		try {
			const rotation = await this.refreshTokens.rotate(rawRefreshToken)

			if (rotation.status === 'invalid' || rotation.status === 'expired') {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-credentials' }
			}

			if (rotation.status === 'reused-token-family-revoked') {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'refresh-token-reused', userId: rotation.userId }
			}

			const user = await this.adapter.findUserById(rotation.userId)
			if (!user) {
				await this.refreshTokens.revokeFamily(rotation.familyId)
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-credentials' }
			}

			const payload = { email: user.email, userId: user.id, role: user.role }
			const accessToken = this.tokens.createJwtToken(
				payload,
				options?.tokenTimeoutMs ?? this.DEFAULT_TOKEN_TIMEOUT_MS,
				secret,
			)

			await holdToFloor(this.responseFloorMs, start)
			return {
				status: 'success-jwt',
				user,
				accessToken,
				refreshToken: rotation.refreshToken,
				familyId: rotation.familyId,
			}
		} catch (err) {
			this.onSystemError(err)
			return this.systemError(start)
		}
	}

	public async logoutJwtSession(familyId: string): Promise<void> {
		await this.refreshTokens.revokeFamily(familyId)
	}

	public async executeMfaStage(
		rawInput: Record<string, unknown>,
		secret: string,
		context?: { userAgent?: string; ipAddress?: string },
		options?: { sessionType?: 'jwt' | 'session'; tokenTimeoutMs?: number },
	): Promise<LoginResult> {
		const start = Date.now()

		try {
			let mfaChallengeToken = ''
			let providedCode = ''

			try {
				const validated = this.validation.validateMfaPayload(rawInput)
				mfaChallengeToken = validated.mfaChallengeToken
				providedCode = validated.code
			} catch {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-mfa-code' }
			}

			const temporarySession =
				await this.sessions.verifyTemporaryMfaToken(mfaChallengeToken)
			if (!temporarySession || temporarySession.isExpired) {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-mfa-token' }
			}

			await this.sessions.revokeTemporaryMfaToken(mfaChallengeToken)

			const user = await this.adapter.findUserById(temporarySession.userId)
			if (!user) {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-credentials' }
			}

			if (!user.mfaEnabled || !user.mfaSecret) {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-mfa-code' }
			}

			const totpResult = this.crypto.verifyTotpCode(
				providedCode,
				user.mfaSecret,
			)

			if (!totpResult.valid || totpResult.matchedCounter === null) {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-mfa-code' }
			}

			const matchedCounter = totpResult.matchedCounter

			if (
				typeof user.lastUsedTotpStep === 'number' &&
				matchedCounter <= user.lastUsedTotpStep
			) {
				this.onSystemError(
					new Error(
						`Rejected replayed TOTP code for user ${user.id}: ` +
							`matched step ${matchedCounter} <= last used step ${user.lastUsedTotpStep}.`,
					),
				)
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-mfa-code' }
			}

			await this.adapter.updateLastUsedTotpStep(user.id, matchedCounter)

			const sessionType = options?.sessionType ?? this.DEFAULT_SESSION_TYPE

			if (sessionType && !this.FLAGS.includes(sessionType)) {
				throw new Error(
					`Invalid session type provided. Must be one of: ${this.FLAGS.join(', ')}`,
				)
			}

			if (sessionType === 'jwt') {
				const payload = { email: user.email, userId: user.id, role: user.role }
				const accessToken = this.tokens.createJwtToken(
					payload,
					options?.tokenTimeoutMs ?? this.DEFAULT_TOKEN_TIMEOUT_MS,
					secret,
				)
				const { refreshToken, familyId } = await this.refreshTokens.issue(
					user.id,
				)

				await holdToFloor(this.responseFloorMs, start)
				return {
					status: 'success-jwt',
					user,
					accessToken,
					refreshToken,
					familyId,
				}
			}

			const { token, session } = await this.sessions.create(user.id, context)
			await holdToFloor(this.responseFloorMs, start)
			return { status: 'success-session', user, session, token }
		} catch (err) {
			this.onSystemError(err)
			return this.systemError(start)
		}
	}

	/**
	 * Resends a verification email for a pending user. Gated behind a
	 * correct password — same enumeration-safe ordering as
	 * executePasswordStage's own unverified check: password proves account
	 * ownership BEFORE anything about verification status is revealed or
	 * acted on. Without this gate, resend would be a free enumeration
	 * side-channel (and a spam vector against real users) independent of
	 * login itself.
	 */
	public async resendVerification(
		rawInput: Record<string, unknown>,
	): Promise<ResendVerificationResult> {
		const start = Date.now()

		try {
			let sanitizedEmail = ''
			let providedPassword = ''

			try {
				const validated = this.validation.validateInputs(rawInput)
				sanitizedEmail = validated.email
				providedPassword = validated.password ?? ''
			} catch {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-credentials' }
			}

			const user = await this.adapter.findUserByEmail(sanitizedEmail)

			if (!user || !user.passwordHash) {
				await this.crypto.verifyPassword(
					providedPassword,
					LoginEngine.STATIC_DUMMY_HASH,
				)
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-credentials' }
			}

			const isPasswordValid = await this.crypto.verifyPassword(
				providedPassword,
				user.passwordHash,
			)

			if (!isPasswordValid) {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'invalid-credentials' }
			}

			// Password is proven correct at this point — the caller owns this
			// account, so revealing verification status here is safe (unlike
			// during a plain login attempt from an unproven caller).
			if (user.verificationStatus !== 'pending') {
				await holdToFloor(this.responseFloorMs, start)
				return { status: 'already-verified' }
			}

			if (!this.verification) {
				this.onSystemError(
					new Error(
						`resendVerification called for pending user ${user.id}, but this ` +
							`LoginEngine was not configured with a VerificationEngine. This ` +
							`indicates a configuration mismatch — a user exists in 'pending' ` +
							`status with no way to complete verification.`,
					),
				)
				await holdToFloor(this.responseFloorMs, start)
				return {
					status: 'system-error',
					message:
						'An unexpected internal core auth engine processing exception was securely handled.',
				}
			}

			void this.verification
				.createAndDispatch({
					email: user.email,
					userId: user.id,
				})
				.catch((err) => this.onSystemError(err))

			await holdToFloor(this.responseFloorMs, start)
			return { status: 'resent' }
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
}
