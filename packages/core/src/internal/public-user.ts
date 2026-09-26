import { User, PublicUser } from '../../types.js'

/**
 * Strips passwordHash, mfaSecret, and lastUsedTotpStep before a User
 * crosses into any result a consumer receives (LoginResult,
 * MiddlewareResult, JwtMiddlewareResult). Every one of those call sites
 * MUST go through this — never return a raw User directly, even
 * internally-sourced ones, since a raw User carries a live, unhashed TOTP
 * secret (mfaSecret) that is otherwise trivially leaked by the single most
 * common thing a consumer does with an auth result: logging it or
 * serializing it into a response.
 */
export function toPublicUser(user: User): PublicUser {
	const { passwordHash, mfaSecret, lastUsedTotpStep, ...publicUser } = user
	return publicUser
}
