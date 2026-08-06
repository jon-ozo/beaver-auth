import { TaskDispatcher } from '../../types.js'
import {
	retryWithBackoff,
	RetryOptions,
	DEFAULT_RETRY_OPTIONS,
} from '../internal/retry.js'
import { safeStringify } from '../internal/safe-stringify.js'

export interface LocalDispatcherOptions {
	maxRetries?: number
	initialDelayMs?: number
	backoffFactor?: number
	onSystemError?: (error: unknown) => void
}

export class LocalTaskDispatcher implements TaskDispatcher {
	private retryOptions: RetryOptions
	private activeTasksCount = 0
	private onSystemError: (error: unknown) => void

	constructor(options?: LocalDispatcherOptions) {
		this.retryOptions = {
			maxRetries: options?.maxRetries ?? DEFAULT_RETRY_OPTIONS.maxRetries,
			initialDelayMs:
				options?.initialDelayMs ?? DEFAULT_RETRY_OPTIONS.initialDelayMs,
			backoffFactor:
				options?.backoffFactor ?? DEFAULT_RETRY_OPTIONS.backoffFactor,
		}
		this.onSystemError =
			options?.onSystemError ??
			((error) => {
				console.error('[beaver-auth]', error)
			})
	}

	public async dispatch(
		taskName: string,
		payload: unknown,
		handler: () => Promise<void>,
		onFailure?: (error: unknown) => Promise<void> | void,
	): Promise<void> {
		this.activeTasksCount++

		setImmediate(() => {
			this.runWithRetry(taskName, payload, handler, onFailure).finally(() => {
				this.activeTasksCount--
			})
		})

		return Promise.resolve()
	}

	private async runWithRetry(
		taskName: string,
		payload: unknown,
		handler: () => Promise<void>,
		onFailure?: (error: unknown) => Promise<void> | void,
	): Promise<void> {
		try {
			await retryWithBackoff(
				handler,
				this.retryOptions,
				(attempt, max, delay, error) => {
					this.onSystemError(
						new Error(
							`[Queue Retry] Task '${taskName}' failed (attempt ${attempt}/${max}). ` +
								`Retrying in ${delay}ms. Payload: ${safeStringify(payload)}. Cause: ${
									error instanceof Error ? error.message : String(error)
								}`,
						),
					)
				},
			)
		} catch (error) {
			this.onSystemError(
				new Error(
					`[Critical Failure] Task '${taskName}' exhausted all ${this.retryOptions.maxRetries} retries. ` +
						`Payload: ${safeStringify(payload)}. Cause: ${error instanceof Error ? error.message : String(error)}`,
				),
			)

			if (onFailure) {
				try {
					await onFailure(error)
				} catch (rollbackError: unknown) {
					this.onSystemError(
						new Error(
							`[Double Fault] onFailure handler for task '${taskName}' itself threw: ` +
								`${
									rollbackError instanceof Error
										? rollbackError.message
										: String(rollbackError)
								}`,
						),
					)
				}
			}
		}
	}

	public async waitForActiveTasks(timeoutMs = 5000): Promise<boolean> {
		const startTime = Date.now()
		while (this.activeTasksCount > 0) {
			if (Date.now() - startTime > timeoutMs) return false
			await new Promise((resolve) => setTimeout(resolve, 50))
		}
		return true
	}
}
