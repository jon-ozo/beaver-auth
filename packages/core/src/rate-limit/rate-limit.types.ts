// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

export interface RateLimitResult {
	identifier: string
	success: boolean
	remaining: number
	limit: number
	resetAt: number
	retryAfter: number
}

export interface RateLimitStore {
	update<T>(
		key: string,
		updater: (current: T | null) => T,
		ttlMs: number,
	): Promise<T>
}

export interface RateLimitingStrategy {
	consume(identifier: string): Promise<RateLimitResult>
}

export type TokenBucketConfig = {
	algorithm: 'token-bucket'
	maxTokens: number
	refillRateMs: number
	refillAmount: number
}

export type SlidingWindowConfig = {
	algorithm: 'sliding-window'
	maxRequests: number
	windowMs: number
}

export type RateLimiterConfig = (TokenBucketConfig | SlidingWindowConfig) & {
	store?: RateLimitStore

	/**
	 * Called with unexpected internal errors (e.g. a custom RateLimitStore
	 * implementation throwing) so consumers can wire their own
	 * observability, matching the pattern used everywhere else in this
	 * package.
	 * @default console.error
	 */
	onSystemError?: (error: unknown) => void
}

export interface TokenBucketState {
	tokens: number
	lastRefilled: number
}
export type SlidingWindowLogState = number[]
