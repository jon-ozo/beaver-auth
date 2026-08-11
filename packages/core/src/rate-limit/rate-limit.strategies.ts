// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import {
	RateLimitingStrategy,
	RateLimitResult,
	RateLimitStore,
	TokenBucketConfig,
	TokenBucketState,
	SlidingWindowConfig,
	SlidingWindowLogState,
} from './rate-limit.types.js'

export class TokenBucketStrategy implements RateLimitingStrategy {
	constructor(
		private config: Omit<TokenBucketConfig, 'algorithm'>,
		private store: RateLimitStore,
	) {}

	public async consume(identifier: string): Promise<RateLimitResult> {
		const now = Date.now()
		const key = `rl:tb:${identifier}`
		const maxTokens = this.config.maxTokens
		const msPerToken = this.config.refillRateMs / this.config.refillAmount

		let success = false

		const finalState = await this.store.update<TokenBucketState>(
			key,
			(state) => {
				if (
					state &&
					(typeof state.tokens !== 'number' ||
						!Number.isFinite(state.tokens) ||
						state.tokens < 0 ||
						typeof state.lastRefilled !== 'number' ||
						!Number.isFinite(state.lastRefilled))
				) {
					state = null
				}

				let tokens = maxTokens
				let lastRefilled = now

				if (state) {
					const elapsedMs = now - state.lastRefilled
					const generatedTokens =
						elapsedMs * (this.config.refillAmount / this.config.refillRateMs)
					tokens = Math.min(maxTokens, state.tokens + generatedTokens)
					lastRefilled = state.lastRefilled
				}

				if (tokens >= 1) {
					tokens -= 1
					success = true
					lastRefilled = now
				}

				return { tokens, lastRefilled }
			},
			// TTL is the time to go from EMPTY to completely FULL, not a
			// fixed refillRateMs*2. The previous fixed TTL could evict an
			// entry well before the bucket would naturally have refilled
			// whenever maxTokens/refillAmount > 2 (a very common config
			// shape) — an idle-but-not-yet-fully-refilled identifier would
			// get treated as brand new on its next request and handed a
			// full bucket early, a real rate-limit bypass, not just an
			// efficiency quirk.
			maxTokens * msPerToken,
		)

		const floorTokens = Math.floor(finalState.tokens)
		const missingTokens = maxTokens - finalState.tokens
		const ttlMs = Math.ceil(missingTokens * msPerToken)

		const computedResetAt = now + ttlMs
		const retryAfter = success ? 0 : Math.ceil(msPerToken / 1000)

		return {
			identifier,
			success,
			remaining: floorTokens,
			limit: maxTokens,
			resetAt: Math.ceil(computedResetAt),
			retryAfter,
		}
	}
}

export class SlidingWindowStrategy implements RateLimitingStrategy {
	constructor(
		private config: Omit<SlidingWindowConfig, 'algorithm'>,
		private store: RateLimitStore,
	) {}

	public async consume(identifier: string): Promise<RateLimitResult> {
		const now = Date.now()
		const key = `rl:sw:${identifier}`
		const boundary = now - this.config.windowMs

		let success = false
		let oldestLog = now

		const finalLogs = await this.store.update<SlidingWindowLogState>(
			key,
			(timestamps) => {
				if (
					timestamps &&
					(!Array.isArray(timestamps) ||
						timestamps.some((t) => !Number.isFinite(t)))
				) {
					timestamps = null
				}

				let validLogs = timestamps
					? timestamps.filter((ts) => ts > boundary)
					: []

				if (validLogs.length < this.config.maxRequests) {
					validLogs.push(now)
					success = true
				}

				oldestLog = validLogs[0] ?? now
				return validLogs
			},
			this.config.windowMs,
		)

		const remaining = Math.max(0, this.config.maxRequests - finalLogs.length)
		const resetAt = oldestLog + this.config.windowMs
		const retryAfter = success ? 0 : Math.ceil((resetAt - now) / 1000)

		return {
			identifier,
			success,
			remaining,
			limit: this.config.maxRequests,
			resetAt,
			retryAfter,
		}
	}
}
