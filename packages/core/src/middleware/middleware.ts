import { SessionManager } from '../session/session.js'
import { TokenEngine } from '../internal/token.js'
import { AuthRepoAdapter, User, Session } from '../../types.js'

export interface CookieOptions {
	name?: string
	path?: string
	domain?: string
	secure?: boolean
	httpOnly?: boolean
	sameSite?: 'lax' | 'strict' | 'none'
}

export interface MiddlewareResult {
	session: Session | null
	user: User | null
	cookieHeaderToBeSet: string | null
}

export interface JwtMiddlewareResult {
	valid: boolean
	user: User | null
	payload: Record<string, unknown> | null
	reason?: string
}

export interface JwtMiddlewareConfig {
	secret: string
	adapter: AuthRepoAdapter

	/**
	 * Optional revocation check, keyed by the token's `jti`. If omitted, JWT
	 * validation is purely stateless (signature + expiry only) — no database
	 * read per request, but a token can't be revoked before it naturally
	 * expires. Supply this if you need logout-before-expiry for JWT sessions;
	 * be aware it adds a database read to every JWT-authenticated request,
	 * which trades away most of the "stateless" benefit of using JWTs.
	 * @default undefined (no revocation check performed)
	 */
	isJwtRevoked?: (jti: string) => Promise<boolean>
}

export class AuthMiddlewareEngine {
	private cookieName: string
	private defaultOptions: Required<CookieOptions>
	private tokens: TokenEngine
	private jwtSecret?: string
	private adapter?: AuthRepoAdapter
	private isJwtRevoked?: (jti: string) => Promise<boolean>

	constructor(
		private sessions: SessionManager,
		jwtConfig?: JwtMiddlewareConfig,
		options?: CookieOptions,
	) {
		this.cookieName = options?.name ?? 'auth_session'
		this.defaultOptions = {
			name: this.cookieName,
			path: options?.path ?? '/',
			domain: options?.domain ?? '',
			secure: options?.secure ?? true,
			httpOnly: options?.httpOnly ?? true,
			sameSite: options?.sameSite ?? 'lax',
		}

		this.tokens = new TokenEngine({
			adapter: jwtConfig?.adapter as AuthRepoAdapter,
		})
		this.jwtSecret = jwtConfig?.secret
		this.adapter = jwtConfig?.adapter
		this.isJwtRevoked = jwtConfig?.isJwtRevoked
	}

	// ---------------------------------------------------------------------
	// Session (cookie-based) transport
	// ---------------------------------------------------------------------

	/**
	 * Parses raw cookie headers with zero external dependencies.
	 */
	public async handleRequest(
		rawCookieHeader: string | null,
	): Promise<MiddlewareResult> {
		if (!rawCookieHeader)
			return { session: null, user: null, cookieHeaderToBeSet: null }

		let token: string | null = null
		const targetKey = encodeURIComponent(this.cookieName).trim()
		const pairs = rawCookieHeader.split(';')

		for (let i = 0; i < pairs.length; i++) {
			const parts = pairs[i].split('=')
			const key = parts[0]?.trim()

			if (key === targetKey) {
				const val = parts.slice(1).join('=').trim()
				token = decodeURIComponent(val)
				break
			}
		}

		if (!token) return { session: null, user: null, cookieHeaderToBeSet: null }

		const validation = await this.sessions.validate(token)

		if (!validation) {
			return {
				session: null,
				user: null,
				cookieHeaderToBeSet: this.blankSessionCookie(),
			}
		}

		const cookieHeaderToBeSet = validation.expiryExtended
			? this.serializeCookie(token, validation.session.expiresAt)
			: null

		return {
			session: validation.session,
			user: validation.user,
			cookieHeaderToBeSet,
		}
	}

	public setSessionCookie(sessionToken: string, expiresAt: Date): string {
		return this.serializeCookie(sessionToken, expiresAt)
	}

	public blankSessionCookie(): string {
		return this.serializeCookie('', new Date(0))
	}

	private serializeCookie(value: string, expiresAt: Date): string {
		const maxAgeSeconds = Math.max(
			0,
			Math.floor((expiresAt.getTime() - Date.now()) / 1000),
		)

		const parts = [
			`${encodeURIComponent(this.cookieName)}=${encodeURIComponent(value)}`,
			`Path=${this.defaultOptions.path}`,
			`Expires=${expiresAt.toUTCString()}`,
			`Max-Age=${maxAgeSeconds}`,
			`SameSite=${this.defaultOptions.sameSite}`,
		]

		if (this.defaultOptions.httpOnly) parts.push('HttpOnly')
		if (this.defaultOptions.secure) parts.push('Secure')

		if (
			this.defaultOptions.domain &&
			this.defaultOptions.domain.trim().length > 0
		) {
			parts.push(`Domain=${this.defaultOptions.domain.trim()}`)
		}

		return parts.join('; ')
	}

	// ---------------------------------------------------------------------
	// JWT (stateless bearer token) transport
	// ---------------------------------------------------------------------

	/**
	 * Verifies a JWT from an `Authorization: Bearer <token>` header. Distinct
	 * from handleRequest() deliberately — a consumer who chose
	 * sessionType: 'jwt' at login already made that choice explicitly, so
	 * their middleware setup calls this directly rather than having both
	 * transports silently raced against each other on every request.
	 */
	public async handleJwtRequest(
		rawAuthHeader: string | null,
	): Promise<JwtMiddlewareResult> {
		if (!this.jwtSecret) {
			throw new Error(
				'AuthMiddlewareEngine.handleJwtRequest() requires jwtConfig.secret ' +
					'to be provided in the constructor.',
			)
		}

		if (!rawAuthHeader) {
			return {
				valid: false,
				user: null,
				payload: null,
				reason: 'Missing Authorization header.',
			}
		}

		const [scheme, token] = rawAuthHeader.split(' ')
		if (scheme !== 'Bearer' || !token) {
			return {
				valid: false,
				user: null,
				payload: null,
				reason: 'Expected Bearer token.',
			}
		}

		const result = this.tokens.verifyJwtToken(token, this.jwtSecret)

		if (!result.valid) {
			return { valid: false, user: null, payload: null, reason: result.reason }
		}

		// Optional revocation check — only performed if the consumer supplied
		// one. Skipped entirely otherwise, keeping the default path fully
		// stateless (no database read).
		if (this.isJwtRevoked) {
			const jti = result.payload.jti
			if (typeof jti !== 'string') {
				return {
					valid: false,
					user: null,
					payload: null,
					reason: 'Token is missing jti and cannot be checked for revocation.',
				}
			}

			const revoked = await this.isJwtRevoked(jti)
			if (revoked) {
				return {
					valid: false,
					user: null,
					payload: null,
					reason: 'Token has been revoked.',
				}
			}
		}

		// The JWT payload carries whatever LoginEngine put there at issuance
		// (email, userId, role) — it is NOT re-fetched from the database, so
		// it reflects the user's state at login time, not necessarily right
		// now. If your app needs guaranteed-fresh user data (e.g. role
		// changes to take effect immediately), look the user up via
		// payload.userId instead of trusting the payload directly for
		// anything authorization-sensitive.
		return {
			valid: true,
			user: null,
			payload: result.payload,
		}
	}

	/**
	 * Revokes a JWT by its jti. Requires the consumer to have supplied
	 * jwtConfig.isJwtRevoked (i.e. opted into revocation support) — this
	 * method only writes to the adapter; isJwtRevoked is what actually
	 * enforces the block on subsequent requests.
	 */
	public async revokeJwt(jti: string): Promise<void> {
		if (!this.adapter?.recordRevokedJti) {
			throw new Error(
				'revokeJwt() requires the adapter to implement recordRevokedJti(jti). ' +
					'If you are not using JWT revocation, this method should not be called.',
			)
		}

		await this.adapter.recordRevokedJti(jti)
	}
}
