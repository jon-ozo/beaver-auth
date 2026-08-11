// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { RateLimiterConfig } from './rate-limit.types.js'

export function validateConfig(config: RateLimiterConfig): void {
	if (config.algorithm === 'token-bucket') {
		if (
			config.maxTokens <= 0 ||
			config.refillRateMs <= 0 ||
			config.refillAmount <= 0
		) {
			throw new Error(
				'Invalid Token Bucket configuration: parameters must be greater than zero.',
			)
		}
	} else if (config.algorithm === 'sliding-window') {
		if (config.maxRequests <= 0 || config.windowMs <= 0) {
			throw new Error(
				'Invalid Sliding Window configuration: parameters must be greater than zero.',
			)
		}
	}
}
