// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { RateLimitStore } from './rate-limit.types.js'

export interface MemoryStoreOptions {
	cleanupIntervalMs?: number

	/**
	 * Soft cap on distinct keys held at once. When exceeded, the oldest
	 * entries (by Map insertion order) are evicted to make room. This is a
	 * cheap mitigation against unbounded memory growth from a large number
	 * of distinct identifiers (e.g. spoofed IPs) between cleanup passes —
	 * not a true LRU, and not a substitute for a shared store under real
	 * distributed load. See the class-level warning below.
	 * @default 100_000
	 */
	maxEntries?: number
}

/**
 * ⚠️ SINGLE-INSTANCE ONLY. This store is an in-process Map — it does not
 * share state across multiple server instances or serverless invocations.
 * In a horizontally-scaled or serverless deployment, each instance has its
 * own independent counters, so the EFFECTIVE rate limit becomes
 * (configured limit × number of running instances), not the configured
 * limit. Use this only for single-instance/bootstrap deployments. For
 * anything horizontally scaled or serverless, supply your own
 * RateLimitStore (e.g. Redis-backed, using WATCH/MULTI or a Lua script for
 * the same read-modify-write atomicity this class provides in-process) via
 * RateLimiterConfig.store.
 */
export class MemoryStore implements RateLimitStore {
	private cache = new Map<string, { value: unknown; expiresAt: number }>()
	private locks = new Map<string, Promise<void>>()
	private intervalId: NodeJS.Timeout | null = null
	private readonly cleanupIntervalMs: number
	private readonly maxEntries: number

	constructor(options?: MemoryStoreOptions) {
		this.cleanupIntervalMs = options?.cleanupIntervalMs ?? 1000 * 60 * 5
		this.maxEntries = options?.maxEntries ?? 100_000
	}

	public async update<T>(
		key: string,
		updater: (current: T | null) => T,
		ttlMs: number,
	): Promise<T> {
		const previous = this.locks.get(key) ?? Promise.resolve()

		let release!: () => void
		const current = new Promise<void>((resolve) => {
			release = resolve
		})

		const queued = previous.then(() => current)

		this.locks.set(key, queued)
		await previous

		// Captured AFTER waiting for the lock, not before. Under contention,
		// a call queued behind others could otherwise compute its
		// "invocation time" from when it ARRIVED rather than when it
		// actually RUNS — making the expiry check compare against a stale
		// timestamp, and making the entry's real lifetime shorter than
		// ttlMs from when the write actually happens.
		const invocationTime = Date.now()
		const expiresAt = invocationTime + ttlMs

		try {
			let existing = this.cache.get(key)

			if (existing && existing.expiresAt <= invocationTime) {
				this.cache.delete(key)
				existing = undefined
			}

			const state = existing ? (existing.value as T) : null
			const updated = updater(state)

			if (!this.cache.has(key)) {
				this.enforceMaxEntries()
			}

			this.cache.set(key, {
				value: updated,
				expiresAt,
			})

			if (!this.intervalId) {
				this.startTimer()
			}

			return updated
		} finally {
			release()

			if (this.locks.get(key) === queued) {
				this.locks.delete(key)
			}
		}
	}

	/**
	 * Evicts the oldest entries (Map insertion order) if adding one more key
	 * would exceed maxEntries. A cheap bound against unbounded growth from a
	 * large number of distinct identifiers — not a substitute for a shared
	 * store under real load, see the class-level warning.
	 */
	private enforceMaxEntries(): void {
		if (this.cache.size < this.maxEntries) return

		const oldestKey = this.cache.keys().next().value
		if (oldestKey !== undefined) {
			this.cache.delete(oldestKey)
		}
	}

	private startTimer(): void {
		this.intervalId = setInterval(() => {
			this.cleanupExpired()
		}, this.cleanupIntervalMs)

		if (this.intervalId && typeof this.intervalId.unref === 'function') {
			this.intervalId.unref()
		}
	}

	private stopTimer(): void {
		if (this.intervalId) {
			clearInterval(this.intervalId)
			this.intervalId = null
		}
	}

	private cleanupExpired(): void {
		const now = Date.now()

		for (const [key, item] of this.cache.entries()) {
			if (item.expiresAt <= now) {
				this.cache.delete(key)
			}
		}

		if (this.cache.size === 0) {
			this.stopTimer()
		}
	}

	public destroy(): void {
		this.stopTimer()
		this.cache.clear()
		this.locks.clear()
	}

	public size(): number {
		return this.cache.size
	}
}
