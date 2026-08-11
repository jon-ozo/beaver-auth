// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { MemoryStore } from './rate-limit.store.js'
import {
	TokenBucketStrategy,
	SlidingWindowStrategy,
} from './rate-limit.strategies.js'
import {
	RateLimiterConfig,
	RateLimitingStrategy,
	RateLimitResult,
} from './rate-limit.types.js'
import { validateConfig } from './validate-config.js'

export class RateLimiterEngine {
	private strategy: RateLimitingStrategy
	private onSystemError: (error: unknown) => void

	constructor(config: RateLimiterConfig) {
		validateConfig(config)

		this.onSystemError =
			config.onSystemError ??
			((error) => {
				console.error('[beaver-auth]', error)
			})

		const store = config.store ?? new MemoryStore()

		if (config.algorithm === 'sliding-window') {
			this.strategy = new SlidingWindowStrategy(config, store)
		} else {
			this.strategy = new TokenBucketStrategy(config, store)
		}
	}

	public async acquire(identifier: string): Promise<RateLimitResult> {
		try {
			return await this.strategy.consume(identifier)
		} catch (err) {
			// A custom RateLimitStore implementation (e.g. Redis-backed)
			// throwing — network blip, connection issue, etc. Report it
			// through the same onSystemError pattern as the rest of the
			// package rather than letting it propagate raw and unobserved.
			this.onSystemError(err)
			throw err
		}
	}
}
