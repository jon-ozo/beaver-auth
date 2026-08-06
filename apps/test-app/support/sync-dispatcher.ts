import type { TaskDispatcher } from '@beaver-auth/core'

/**
 * A TaskDispatcher that runs the handler immediately and awaits it, with no
 * setImmediate/retry/backoff delay. Used in tests so registration/login
 * flows that fire-and-forget verification/reset dispatch can be awaited
 * deterministically, instead of racing real timers.
 *
 * Also doubles as a regression guard: since it calls dispatch() with the
 * exact same (taskName, payload, handler, onFailure) signature real
 * TaskDispatcher implementations receive, any future argument-order
 * regression (like the payload/handler mixup found and fixed in
 * LocalTaskDispatcher) would surface immediately as "handler is not a
 * function" in any test that exercises dispatch.
 */
export class SyncTaskDispatcher implements TaskDispatcher {
	public calls: Array<{ taskName: string; payload: unknown }> = []
	public lastError: unknown

	async dispatch(
		taskName: string,
		payload: unknown,
		handler: () => Promise<void>,
		onFailure?: (error: unknown) => Promise<void> | void,
	): Promise<void> {
		this.calls.push({ taskName, payload })

		if (typeof handler !== 'function') {
			throw new TypeError(
				`SyncTaskDispatcher.dispatch: expected 'handler' to be a function, ` +
					`got ${typeof handler}. This usually means dispatch() was called ` +
					`with the wrong argument order.`,
			)
		}

		try {
			await handler()
		} catch (error) {
			this.lastError = error
			if (onFailure) {
				await onFailure(error)
			} else {
				throw error
			}
		}
	}
}
