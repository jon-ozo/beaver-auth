// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

// ── Barrel exports — for consumers who want to construct and wire
export { RegistrationEngine } from './src/register/register.js'
export { LoginEngine } from './src/login/login.js'
export { VerificationEngine } from './src/verification/verification.js'
export { PasswordResetEngine } from './src/account-recovery/password-reset.js'
export { SessionManager } from './src/session/session.js'
export { AuthMiddlewareEngine } from './src/middleware/middleware.js'
export { RefreshTokenEngine } from './src/internal/refresh-token.js'
export { TokenEngine } from './src/internal/token.js'
export { CryptoEngine } from './src/internal/crypto.js'
export { ValidationEngine } from './src/internal/validation.js'
export { ValidationError } from './src/internal/error.js'
export { MfaEngine } from './src/mfa/mfa.js'
export { OAuthEngine } from './src/oauth/oauth.js'
export type { OAuthProviderConfig } from './src/oauth/oauth.js'
export { LocalTaskDispatcher } from './src/register/in-memory-dispatcher.js'
export { RateLimiterEngine } from './src/rate-limit/rate-limit.js'
export { MemoryStore } from './src/rate-limit/rate-limit.store.js'
export { checkAuthRateLimit } from './src/rate-limit/rate-limit.guard.js'

export * from './types.js'
export * from './src/rate-limit/rate-limit.types.js'

import {
	AuthRepoAdapter,
	AuthSessionAdapter,
	VerificationHooks,
	PasswordResetHooks,
} from './types.js'
import { RateLimiterConfig } from './src/rate-limit/rate-limit.types.js'
import { RegistrationEngine } from './src/register/register.js'
import { LoginEngine } from './src/login/login.js'
import { VerificationEngine } from './src/verification/verification.js'
import { PasswordResetEngine } from './src/account-recovery/password-reset.js'
import { SessionManager } from './src/session/session.js'
import {
	AuthMiddlewareEngine,
	CookieOptions,
} from './src/middleware/middleware.js'
import { TaskDispatcher } from './types.js'
import { RateLimiterEngine } from './src/rate-limit/rate-limit.js'
import { OAuthEngine } from './src/oauth/oauth.js'

export interface CreateBeaverAuthConfig {
	adapter: AuthRepoAdapter & AuthSessionAdapter

	/**
	 * Shared across every engine constructed by this factory, so all
	 * failures/retries reach the same observability sink by default. Any
	 * individual sub-config below can still override it.
	 * @default console.error
	 */
	onSystemError?: (error: unknown) => void

	/**
	 * Shared default TaskDispatcher, used by VerificationEngine and
	 * PasswordResetEngine unless they're given their own. Defaults to a
	 * per-engine LocalTaskDispatcher if omitted here AND in the sub-configs
	 * — see LocalTaskDispatcher's own docs for its serverless limitations.
	 */
	dispatcher?: TaskDispatcher

	/**
	 * Shared default response-floor (ms) applied across registration,
	 * login, verification, and password-reset unless a sub-config
	 * overrides it. @default 150
	 */
	responseFloorMs?: number

	/**
	 * Presence enables email verification (RegistrationEngine issues a
	 * 'pending' user + verification email; LoginEngine gains
	 * resendVerification). Omit entirely to skip verification, matching
	 * every individual engine's own optional-verification behavior.
	 */
	verification?: {
		hooks: VerificationHooks
		dispatcher?: TaskDispatcher
		defaultTokenTimeoutMs?: number
	}

	/**
	 * Presence enables the "forgot password" flow. Omit to skip it
	 * entirely — RegistrationEngine/LoginEngine work the same either way.
	 */
	passwordReset?: {
		hooks: PasswordResetHooks
		dispatcher?: TaskDispatcher
		defaultTokenTimeoutMs?: number
	}

	session?: {
		sessionTimeoutMs?: number
		mfaChallengeTimeoutMs?: number
	}

	/**
	 * Presence constructs an AuthMiddlewareEngine for protected-route use.
	 * jwtConfig.secret/adapter are required by AuthMiddlewareEngine itself
	 * (a deliberate choice made earlier in this build — no half-configured
	 * middleware), so this whole block is required together, not optional
	 * field-by-field.
	 */
	middleware?: {
		jwtSecret: string
		isJwtRevoked?: (jti: string) => Promise<boolean>
		cookieOptions?: CookieOptions
	}

	/**
	 * Presence per key enables rate limiting for that specific flow. Each
	 * is independently optional — e.g. rate-limit login without
	 * rate-limiting registration. Constructed engines are handed back for
	 * you to wire into your own route handlers via checkAuthRateLimit,
	 * exactly as designed earlier — this factory does NOT call them
	 * automatically inside registration/login/reset, since rate-limit
	 * identifier strategy (IP, email, composite) is a threat-model
	 * decision this package deliberately leaves to you.
	 */
	rateLimiters?: {
		registration?: RateLimiterConfig
		login?: RateLimiterConfig
		passwordReset?: RateLimiterConfig
	}

	registration?: {
		protectAgainstEnumeration?: boolean
		verificationGracePeriodMs?: number
		runInTransaction?: <T>(
			work: (txAdapter: AuthRepoAdapter & AuthSessionAdapter) => Promise<T>,
		) => Promise<T>
	}
}

interface MutableRateLimiters {
	registration?: RateLimiterEngine
	login?: RateLimiterEngine
	passwordReset?: RateLimiterEngine
}

export interface BeaverAuth {
	readonly registration: RegistrationEngine
	readonly login: LoginEngine
	readonly sessions: SessionManager
	readonly verification?: VerificationEngine
	readonly passwordReset?: PasswordResetEngine
	readonly middleware?: AuthMiddlewareEngine
	readonly oauth: OAuthEngine
	readonly rateLimiters: {
		readonly registration?: RateLimiterEngine
		readonly login?: RateLimiterEngine
		readonly passwordReset?: RateLimiterEngine
	}
}

/**
 * Constructs and wires the full beaver-auth dependency graph in one call.
 * Every optional block (verification, passwordReset, middleware,
 * rateLimiters) follows the same rule used throughout this package:
 * presence = opt-in. Shared instances (onSystemError, dispatcher,
 * VerificationEngine) are passed to every engine that needs them, so e.g.
 * LoginEngine.resendVerification and RegistrationEngine's initial
 * verification email are guaranteed to operate against the SAME
 * VerificationEngine/token store — constructing two separate instances by
 * hand is an easy way to accidentally break that assumption, which is the
 * main risk this factory exists to remove.
 *
 * This does not replace manual construction — every class is still
 * individually exported above for consumers who want full control (e.g.
 * different onSystemError per engine, engines constructed at different
 * times, or a subset of the graph only).
 */
export function createBeaverAuth(config: CreateBeaverAuthConfig): BeaverAuth {
	const onSystemError =
		config.onSystemError ??
		((error: unknown) => {
			console.error('[beaver-auth]', error)
		})

	const sessions = new SessionManager({
		adapter: config.adapter,
		sessionTimeoutMs: config.session?.sessionTimeoutMs,
		mfaChallengeTimeoutMs: config.session?.mfaChallengeTimeoutMs,
	})

	const verification = config.verification
		? new VerificationEngine({
				adapter: config.adapter,
				hooks: config.verification.hooks,
				dispatcher: config.verification.dispatcher ?? config.dispatcher,
				onSystemError,
				defaultTokenTimeoutMs: config.verification.defaultTokenTimeoutMs,
			})
		: undefined

	const passwordReset = config.passwordReset
		? new PasswordResetEngine({
				adapter: config.adapter,
				hooks: config.passwordReset.hooks,
				dispatcher: config.passwordReset.dispatcher ?? config.dispatcher,
				onSystemError,
				responseFloorMs: config.responseFloorMs,
				defaultTokenTimeoutMs: config.passwordReset.defaultTokenTimeoutMs,
			})
		: undefined

	const registration = new RegistrationEngine({
		adapter: config.adapter,
		verification,
		onSystemError,
		responseFloorMs: config.responseFloorMs,
		protectAgainstEnumeration: config.registration?.protectAgainstEnumeration,
		verificationGracePeriodMs: config.registration?.verificationGracePeriodMs,
		runInTransaction: config.registration?.runInTransaction,
	})

	const login = new LoginEngine({
		adapter: config.adapter,
		verification,
		sessions,
		onSystemError,
		responseFloorMs: config.responseFloorMs,
	})

	const oauth = new OAuthEngine()

	const middleware = config.middleware
		? new AuthMiddlewareEngine(
				sessions,
				{
					secret: config.middleware.jwtSecret,
					adapter: config.adapter,
					isJwtRevoked: config.middleware.isJwtRevoked,
				},
				config.middleware.cookieOptions,
			)
		: undefined

	const rateLimiters: MutableRateLimiters = {}

	if (config.rateLimiters?.registration) {
		rateLimiters.registration = new RateLimiterEngine({
			...config.rateLimiters.registration,
			onSystemError:
				config.rateLimiters.registration.onSystemError ?? onSystemError,
		})
	}
	if (config.rateLimiters?.login) {
		rateLimiters.login = new RateLimiterEngine({
			...config.rateLimiters.login,
			onSystemError: config.rateLimiters.login.onSystemError ?? onSystemError,
		})
	}
	if (config.rateLimiters?.passwordReset) {
		rateLimiters.passwordReset = new RateLimiterEngine({
			...config.rateLimiters.passwordReset,
			onSystemError:
				config.rateLimiters.passwordReset.onSystemError ?? onSystemError,
		})
	}

	Object.freeze(rateLimiters)

	const bundle: BeaverAuth = {
		registration,
		login,
		sessions,
		verification,
		passwordReset,
		middleware,
		rateLimiters,
		oauth,
	}

	return Object.freeze(bundle)
}
