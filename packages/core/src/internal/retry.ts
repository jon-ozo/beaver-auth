export interface RetryOptions {
	maxRetries: number
	initialDelayMs: number
	backoffFactor: number
}

export const DEFAULT_RETRY_OPTIONS: RetryOptions = {
	maxRetries: 3,
	initialDelayMs: 1000,
	backoffFactor: 2,
}

/**
 * Retries an async operation with exponential backoff. Attempt N (1-indexed)
 * waits initialDelayMs * backoffFactor^(N-1) before retrying. Rethrows the
 * final error once maxRetries is exhausted — callers decide what "give up"
 * means for them (log, roll back, leave a record pending, etc.), this
 * utility only owns the retry loop itself.
 */
export async function retryWithBackoff<T>(
	fn: () => Promise<T>,
	options: RetryOptions,
	onRetry?: (
		attempt: number,
		maxRetries: number,
		delayMs: number,
		error: unknown,
	) => void,
): Promise<T> {
	let currentAttempt = 0

	while (true) {
		try {
			return await fn()
		} catch (error) {
			if (currentAttempt >= options.maxRetries) {
				throw error
			}

			const delayMs =
				options.initialDelayMs * Math.pow(options.backoffFactor, currentAttempt)
			currentAttempt++

			onRetry?.(currentAttempt, options.maxRetries, delayMs, error)

			await new Promise((resolve) => setTimeout(resolve, delayMs))
		}
	}
}
