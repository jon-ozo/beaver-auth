import { afterEach, describe, expect, it, vi } from 'vitest'
import {
	RateLimiterEngine,
	MemoryStore,
	checkAuthRateLimit,
} from '@beaver-auth/core'

describe('RateLimiterEngine — token bucket', () => {
	afterEach(() => {
		vi.useRealTimers()
	})

	it('allows up to maxTokens requests, then blocks the next one', async () => {
		const limiter = new RateLimiterEngine({
			algorithm: 'token-bucket',
			maxTokens: 3,
			refillRateMs: 1000,
			refillAmount: 1,
		})

		const r1 = await limiter.acquire('user-a')
		const r2 = await limiter.acquire('user-a')
		const r3 = await limiter.acquire('user-a')
		const r4 = await limiter.acquire('user-a')

		expect([r1.success, r2.success, r3.success]).toEqual([true, true, true])
		expect(r4.success).toBe(false)
		expect(r4.remaining).toBe(0)
	})

	it('tracks separate buckets per identifier', async () => {
		const limiter = new RateLimiterEngine({
			algorithm: 'token-bucket',
			maxTokens: 1,
			refillRateMs: 1000,
			refillAmount: 1,
		})

		const a1 = await limiter.acquire('user-a')
		const b1 = await limiter.acquire('user-b')
		const a2 = await limiter.acquire('user-a')

		expect(a1.success).toBe(true)
		expect(b1.success).toBe(true) // different identifier, unaffected by user-a's bucket
		expect(a2.success).toBe(false) // user-a's single token already spent
	})

	it('refills gradually over elapsed time, not instantly to full', async () => {
		vi.useFakeTimers()
		vi.setSystemTime(0)

		const limiter = new RateLimiterEngine({
			algorithm: 'token-bucket',
			maxTokens: 10,
			refillRateMs: 1000, // 1 token per second
			refillAmount: 1,
		})

		// Drain the bucket completely.
		for (let i = 0; i < 10; i++) {
			await limiter.acquire('user-a')
		}
		const drained = await limiter.acquire('user-a')
		expect(drained.success).toBe(false)

		// 3 seconds later: ~3 tokens should have regenerated.
		vi.setSystemTime(3000)
		const afterPartialRefill = await limiter.acquire('user-a')

		expect(afterPartialRefill.success).toBe(true)
		expect(afterPartialRefill.remaining).toBe(2) // 3 generated, 1 consumed = 2
	})

	it('REGRESSION GUARD: does not reset to a full bucket before the true refill time, even past the old (buggy) fixed TTL', async () => {
		// This is the exact bug found and fixed earlier: the cache TTL passed
		// to the store used to be a fixed `refillRateMs * 2`, which could
		// evict (and thus reset-to-full) an entry well before the bucket
		// would naturally have refilled — a real rate-limit bypass whenever
		// maxTokens/refillAmount > 2. The fix uses the true empty-to-full
		// time (maxTokens * msPerToken) as the TTL instead.
		//
		// With these numbers: refillRateMs*2 = 2000ms (the OLD, buggy TTL).
		// True full refill = maxTokens * msPerToken = 10 * 1000 = 10000ms.
		// Advancing to t=3000ms is past the old buggy TTL but nowhere near
		// the true refill time — under the bug, the cache entry would have
		// been evicted and the next request would see a freshly-full bucket
		// (remaining: 9 after one consume). Under the fix, only ~3 tokens
		// should have naturally regenerated (remaining: 2 after one consume).
		vi.useFakeTimers()
		vi.setSystemTime(0)

		const limiter = new RateLimiterEngine({
			algorithm: 'token-bucket',
			maxTokens: 10,
			refillRateMs: 1000,
			refillAmount: 1,
		})

		for (let i = 0; i < 10; i++) {
			await limiter.acquire('user-a')
		}

		vi.setSystemTime(3000)
		const result = await limiter.acquire('user-a')

		expect(result.success).toBe(true)
		expect(result.remaining).toBe(2)
		expect(result.remaining).not.toBe(9) // would indicate the old bug is back
	})
})

describe('RateLimiterEngine — sliding window', () => {
	afterEach(() => {
		vi.useRealTimers()
	})

	it('allows up to maxRequests within the window, then blocks', async () => {
		const limiter = new RateLimiterEngine({
			algorithm: 'sliding-window',
			maxRequests: 3,
			windowMs: 1000,
		})

		const results = []
		for (let i = 0; i < 4; i++) {
			results.push((await limiter.acquire('user-a')).success)
		}

		expect(results).toEqual([true, true, true, false])
	})

	it('allows requests again once the window has fully elapsed', async () => {
		vi.useFakeTimers()
		vi.setSystemTime(0)

		const limiter = new RateLimiterEngine({
			algorithm: 'sliding-window',
			maxRequests: 2,
			windowMs: 1000,
		})

		await limiter.acquire('user-a')
		await limiter.acquire('user-a')
		const blocked = await limiter.acquire('user-a')
		expect(blocked.success).toBe(false)

		vi.setSystemTime(1500) // past the 1000ms window
		const afterWindow = await limiter.acquire('user-a')
		expect(afterWindow.success).toBe(true)
	})

	it('a partially-elapsed window only frees up the requests that actually aged out', async () => {
		vi.useFakeTimers()
		vi.setSystemTime(0)

		const limiter = new RateLimiterEngine({
			algorithm: 'sliding-window',
			maxRequests: 2,
			windowMs: 1000,
		})

		await limiter.acquire('user-a') // t=0
		vi.setSystemTime(600)
		await limiter.acquire('user-a') // t=600, both slots now used

		vi.setSystemTime(1050) // t=0 request has aged out (>1000ms), t=600 has not
		const result = await limiter.acquire('user-a')
		expect(result.success).toBe(true) // exactly one slot freed up

		const result2 = await limiter.acquire('user-a')
		expect(result2.success).toBe(false) // and now it's used again
	})
})

describe('RateLimiterEngine — config validation', () => {
	it('rejects a zero/negative token-bucket config', () => {
		expect(
			() =>
				new RateLimiterEngine({
					algorithm: 'token-bucket',
					maxTokens: 0,
					refillRateMs: 1000,
					refillAmount: 1,
				}),
		).toThrow()
	})

	it('rejects a zero/negative sliding-window config', () => {
		expect(
			() =>
				new RateLimiterEngine({
					algorithm: 'sliding-window',
					maxRequests: 5,
					windowMs: -1,
				}),
		).toThrow()
	})
})

describe('RateLimiterEngine — error reporting', () => {
	it('reports via onSystemError and rethrows when the underlying store throws', async () => {
		const onSystemError = vi.fn()
		const brokenStore = {
			update: vi.fn().mockRejectedValue(new Error('store unavailable')),
		}

		const limiter = new RateLimiterEngine({
			algorithm: 'token-bucket',
			maxTokens: 5,
			refillRateMs: 1000,
			refillAmount: 1,
			store: brokenStore,
			onSystemError,
		})

		await expect(limiter.acquire('user-a')).rejects.toThrow('store unavailable')
		expect(onSystemError).toHaveBeenCalledTimes(1)
	})
})

describe('checkAuthRateLimit', () => {
	it('builds the identifier via getIdentifier and delegates to the limiter', async () => {
		const limiter = new RateLimiterEngine({
			algorithm: 'token-bucket',
			maxTokens: 1,
			refillRateMs: 1000,
			refillAmount: 1,
		})

		const config = {
			limiter,
			getIdentifier: (input: { email?: string; ipAddress?: string }) =>
				`${input.ipAddress ?? 'unknown'}:${input.email ?? 'unknown'}`,
		}

		const first = await checkAuthRateLimit(config, {
			email: 'a@example.com',
			ipAddress: '1.2.3.4',
		})
		expect(first.success).toBe(true)
		expect(first.identifier).toBe('1.2.3.4:a@example.com')

		// Same composite identifier -> shares the same bucket.
		const second = await checkAuthRateLimit(config, {
			email: 'a@example.com',
			ipAddress: '1.2.3.4',
		})
		expect(second.success).toBe(false)

		// Different IP with the same email -> a DIFFERENT bucket entirely.
		const third = await checkAuthRateLimit(config, {
			email: 'a@example.com',
			ipAddress: '5.6.7.8',
		})
		expect(third.success).toBe(true)
	})
})

describe('MemoryStore', () => {
	it('serializes concurrent updates to the same key — no lost updates', async () => {
		const store = new MemoryStore()

		// Fire 20 concurrent increments at the same key. If the per-key
		// mutex has a race, some increments would be lost (read stale state,
		// overwrite each other) and the final count would be less than 20.
		const updates = Array.from({ length: 20 }, () =>
			store.update<number>('counter', (current) => (current ?? 0) + 1, 5000),
		)

		await Promise.all(updates)
		const final = await store.update<number>(
			'counter',
			(current) => current ?? 0,
			5000,
		)

		expect(final).toBe(20) // all 20 concurrent increments landed, none lost
		store.destroy()
	})

	it('keeps concurrent updates to DIFFERENT keys independent', async () => {
		const store = new MemoryStore()

		await Promise.all([
			store.update<number>('a', (c) => (c ?? 0) + 1, 5000),
			store.update<number>('b', (c) => (c ?? 0) + 1, 5000),
			store.update<number>('a', (c) => (c ?? 0) + 1, 5000),
		])

		const a = await store.update<number>('a', (c) => c ?? 0, 5000)
		const b = await store.update<number>('b', (c) => c ?? 0, 5000)

		expect(a).toBe(2) // 2 real increments to 'a'
		expect(b).toBe(1) // 1 real increment to 'b'
		store.destroy()
	})

	it('evicts the oldest entry once maxEntries is exceeded', async () => {
		const store = new MemoryStore({ maxEntries: 2 })

		await store.update('key-1', () => 'a', 60_000)
		await store.update('key-2', () => 'b', 60_000)
		expect(store.size()).toBe(2)

		await store.update('key-3', () => 'c', 60_000)
		expect(store.size()).toBe(2) // still capped

		store.destroy()
	})
})
