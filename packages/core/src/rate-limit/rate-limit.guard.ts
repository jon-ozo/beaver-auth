// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { RateLimiterEngine } from './rate-limit.js'
import { RateLimitResult } from './rate-limit.types.js'

export interface AuthRateLimitInput {
	email?: string
	ipAddress?: string
}

export interface AuthRateLimiterConfig {
	limiter: RateLimiterEngine

	/**
	 * Decides what identifies a "bucket" for rate-limiting purposes. Not
	 * decided by this package, since it's a real threat-model choice:
	 *
	 * - By email alone: catches distributed credential stuffing (same
	 *   account, many IPs), but a 429 is only ever returned for accounts
	 *   that exist, which is itself a subtle enumeration signal — a
	 *   nonexistent email never accumulates attempts, so it never gets
	 *   throttled, and an attacker who notices that difference learns
	 *   something. Combine with IP-based limiting elsewhere if that risk
	 *   matters for your threat model.
	 * - By IP alone: doesn't leak account existence, but distributed
	 *   attacks (many IPs, one target account) sail through untouched.
	 * - By a composite (e.g. `${ipAddress}:${email}`): the safest default
	 *   for most consumers — throttles a given IP's attempts against a
	 *   given email specifically, without the pure-email approach's
	 *   enumeration signal, though it doesn't fully stop a distributed
	 *   attack that spreads requests across many IPs either. Combine with
	 *   an IP-only limiter (often already present at the infra/gateway
	 *   layer) if you need that coverage too.
	 *
	 * Example: ({ email, ipAddress }) => `${ipAddress ?? 'unknown'}:${email ?? 'unknown'}`
	 */
	getIdentifier: (input: AuthRateLimitInput) => string
}

/**
 * Checks (and consumes, if allowed) one unit of rate-limit budget for an
 * auth-related request. Deliberately a plain function, not literal
 * framework middleware — same plain-object-in/plain-object-out shape as
 * AuthMiddlewareEngine.handleRequest and every engine's execute() method.
 * The consumer calls this from their own route handler, wraps it in
 * whatever their framework's middleware/guard shape looks like, and
 * decides what a failed check means for their response (429, a specific
 * error body, a redirect, etc.) — none of that is beaver-auth's concern.
 *
 * Entirely optional. A consumer who already has IP-based rate limiting at
 * their gateway/infra layer, or their own account-lockout logic, can skip
 * this and call LoginEngine/RegistrationEngine directly with no loss of
 * functionality — nothing in either engine depends on this having run.
 *
 * Usage:
 *   const rateLimiter = { limiter: loginLimiter, getIdentifier: (i) => `${i.ipAddress}:${i.email}` }
 *   const result = await checkAuthRateLimit(rateLimiter, { email, ipAddress: req.ip })
 *   if (!result.success) return res.status(429).json({ retryAfter: result.retryAfter })
 *   const loginResult = await loginEngine.executePasswordStage(req.body, secret)
 */
export async function checkAuthRateLimit(
	config: AuthRateLimiterConfig,
	input: AuthRateLimitInput,
): Promise<RateLimitResult> {
	const identifier = config.getIdentifier(input)
	return config.limiter.acquire(identifier)
}
