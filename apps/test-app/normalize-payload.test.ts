import { describe, expect, it } from 'vitest'
import {
	normalizePayload,
	PayloadPolicy,
} from '../../packages/core/src/internal/normalize-payload/normalize-payload.js'
import { NormalizerRegistry } from '../../packages/core/src/internal/normalize-payload/normalizer-registry.js'
import { NormalizationError } from '../../packages/core/src/internal/normalize-payload/normalizer-error.js'
import { normalizeJwtPayload } from '../../packages/core/src/internal/normalize-payload/normalize-jwt-payload.js'

const OPTS = { maxDepth: 20, maxNodes: 500 }

describe('normalizePayload — basic shape handling', () => {
	it('passes through strings, numbers, booleans, and null unchanged', () => {
		const result = normalizePayload(
			{ str: 'hello', num: 42, bool: true, nothing: null },
			OPTS,
		)
		expect(result).toEqual({ str: 'hello', num: 42, bool: true, nothing: null })
	})

	it('coerces NaN and Infinity to null (both in objects and arrays)', () => {
		const result = normalizePayload(
			{
				bad: NaN,
				alsoBad: Infinity,
				alsoAlsoBad: -Infinity,
				list: [NaN, 1, Infinity],
			},
			OPTS,
		)
		expect(result).toEqual({
			bad: null,
			alsoBad: null,
			alsoAlsoBad: null,
			list: [null, 1, null],
		})
	})

	it('rejects a null, array, or non-object top-level payload', () => {
		expect(() => normalizePayload(null as any, OPTS)).toThrow(
			NormalizationError,
		)
		expect(() => normalizePayload([1, 2, 3] as any, OPTS)).toThrow(
			NormalizationError,
		)
		expect(() => normalizePayload('a string' as any, OPTS)).toThrow(
			NormalizationError,
		)

		try {
			normalizePayload(null as any, OPTS)
		} catch (err) {
			expect((err as NormalizationError).code).toBe('INVALID_INPUT')
		}
	})

	it('normalizes nested objects and arrays correctly', () => {
		const result = normalizePayload(
			{ user: { name: 'Alice', tags: ['a', 'b', { nested: 1 }] } },
			OPTS,
		)
		expect(result).toEqual({
			user: { name: 'Alice', tags: ['a', 'b', { nested: 1 }] },
		})
	})
})

describe('normalizePayload — prototype pollution protection', () => {
	it('strips __proto__, constructor, and prototype keys, and does not pollute Object.prototype', () => {
		const malicious = JSON.parse(
			'{"email":"a@example.com","__proto__":{"polluted":"yes"},"constructor":{"x":1},"prototype":{"y":2}}',
		)
		const result = normalizePayload(malicious, OPTS)

		expect(result).toEqual({ email: 'a@example.com' })
		expect(({} as Record<string, unknown>).polluted).toBeUndefined()
	})

	it('strips prototype pollution keys even at nested levels', () => {
		const malicious = JSON.parse(
			'{"user":{"name":"Alice","__proto__":{"polluted":"yes"}}}',
		)
		const result = normalizePayload(malicious, OPTS)
		expect(result).toEqual({ user: { name: 'Alice' } })
	})
})

describe('normalizePayload — JWT reserved-key policy', () => {
	it('strips JWT reserved keys under PayloadPolicy.Jwt', () => {
		const result = normalizePayload(
			{ userId: 'u-1', iat: 1, exp: 2, jti: 'x', nbf: 3, iss: 'a', aud: 'b' },
			{ ...OPTS, policy: PayloadPolicy.Jwt },
		)
		expect(result).toEqual({ userId: 'u-1' })
	})

	it('does NOT strip those keys under the Standard policy (default)', () => {
		const result = normalizePayload({ userId: 'u-1', iat: 1, exp: 2 }, OPTS)
		expect(result).toEqual({ userId: 'u-1', iat: 1, exp: 2 })
	})
})

describe('normalizePayload — cycle and shared-reference handling', () => {
	it('breaks a self-referencing object cycle without infinite looping', () => {
		const obj: Record<string, unknown> = { name: 'a' }
		obj.self = obj

		const result = normalizePayload(obj, OPTS)
		expect(result.name).toBe('a')
		expect(result.self).toBeNull()
	})

	it('breaks a self-referencing array cycle', () => {
		const arr: unknown[] = [1, 2]
		arr.push(arr)
		const result = normalizePayload({ list: arr }, OPTS)
		expect(result.list).toEqual([1, 2, null])
	})

	it('treats a non-cyclic SHARED reference as if it were a cycle on its second occurrence (documented trade-off)', () => {
		const shared = { value: 1 }
		const result = normalizePayload({ a: shared, b: shared }, OPTS)
		expect(result.a).toEqual({ value: 1 })
		expect(result.b).toBeNull() // second reference to the same object nulled out
	})
})

describe('normalizePayload — resource limits', () => {
	it('throws DEPTH_EXCEEDED for a payload nested deeper than maxDepth', () => {
		let deep: Record<string, unknown> = { bottom: true }
		for (let i = 0; i < 25; i++) deep = { nested: deep }

		try {
			normalizePayload(deep, { maxDepth: 20, maxNodes: 500 })
			expect.fail('should have thrown')
		} catch (err) {
			expect(err).toBeInstanceOf(NormalizationError)
			expect((err as NormalizationError).code).toBe('DEPTH_EXCEEDED')
		}
	})

	it('throws NODE_EXCEEDED for a payload with more supported fields than maxNodes', () => {
		const wide: Record<string, number> = {}
		for (let i = 0; i < 10; i++) wide[`field${i}`] = i

		expect(() => normalizePayload(wide, { maxDepth: 20, maxNodes: 5 })).toThrow(
			NormalizationError,
		)
		try {
			normalizePayload(wide, { maxDepth: 20, maxNodes: 5 })
		} catch (err) {
			expect((err as NormalizationError).code).toBe('NODE_EXCEEDED')
		}
	})

	it('REGRESSION GUARD: unsupported-type fields also count toward the node budget', () => {
		// This is the exact bug found and fixed earlier: the object-traversal
		// branch used to skip incrementAndCheckNodes() entirely for
		// unsupported-type values (functions, symbols, etc.), letting an
		// attacker send unlimited unsupported-typed keys that bypassed
		// maxNodes completely while still costing real CPU/iteration time.
		// If this regresses, a payload built entirely from unsupported
		// values would NOT throw here, even with a tiny maxNodes.
		const wide: Record<string, () => void> = {}
		for (let i = 0; i < 10; i++) wide[`fn${i}`] = () => {}

		expect(() => normalizePayload(wide, { maxDepth: 20, maxNodes: 5 })).toThrow(
			/Maximum node allowance/,
		)
	})
})

describe('normalizePayload — unsupported/skip vs. pad semantics', () => {
	it('an unsupported-type value is SKIPPED (key omitted) in an object', () => {
		const result = normalizePayload({ a: 1, fn: () => {}, b: 2 }, OPTS)
		expect(result).toEqual({ a: 1, b: 2 })
		expect('fn' in result).toBe(false)
	})

	it('an unsupported-type value is PADDED WITH NULL (not removed) in an array', () => {
		const result = normalizePayload({ list: [1, () => {}, 2] }, OPTS)
		expect(result.list).toEqual([1, null, 2])
	})

	it('treats functions, symbols, and bigints as unsupported', () => {
		const result = normalizePayload(
			{ fn: () => {}, sym: Symbol('x'), big: BigInt(10), keep: 'yes' },
			OPTS,
		)
		expect(result).toEqual({ keep: 'yes' })
	})

	it('treats Map, Set, WeakMap, WeakSet, Promise, and Error instances as unsupported', () => {
		const result = normalizePayload(
			{
				m: new Map(),
				s: new Set(),
				wm: new WeakMap(),
				ws: new WeakSet(),
				p: Promise.resolve(),
				e: new Error('x'),
				keep: 'yes',
			},
			OPTS,
		)
		expect(result).toEqual({ keep: 'yes' })
	})

	it('treats Buffers, TypedArrays, and ArrayBuffers as unsupported', () => {
		const result = normalizePayload(
			{
				buf: Buffer.from('hello'),
				u8: new Uint8Array([1, 2, 3]),
				ab: new ArrayBuffer(8),
				keep: 'yes',
			},
			OPTS,
		)
		expect(result).toEqual({ keep: 'yes' })
	})
})

describe('normalizePayload — built-in transform strategies', () => {
	it('transforms a Date to its ISO string', () => {
		const date = new Date('2024-01-01T00:00:00.000Z')
		const result = normalizePayload({ createdAt: date }, OPTS)
		expect(result.createdAt).toBe('2024-01-01T00:00:00.000Z')
	})

	it('transforms a URL to its string form', () => {
		const url = new URL('https://example.com/path?x=1')
		const result = normalizePayload({ link: url }, OPTS)
		expect(result.link).toBe('https://example.com/path?x=1')
	})

	it('transforms a RegExp to its string form', () => {
		const result = normalizePayload({ pattern: /abc/gi }, OPTS)
		expect(result.pattern).toBe('/abc/gi')
	})

	it('REGRESSION GUARD: a throwing transform (invalid Date) fails soft instead of propagating', () => {
		// This is the bug found and fixed earlier: transform strategies
		// (e.g. Date.prototype.toISOString) were called unguarded — an
		// invalid Date throws a RangeError from toISOString(), which used to
		// propagate straight out of normalizePayload uncaught, taking down
		// the entire normalization pass over one bad field.
		const invalidDate = new Date('not a real date')
		expect(() =>
			normalizePayload({ when: invalidDate, keep: 'yes' }, OPTS),
		).not.toThrow()

		const result = normalizePayload({ when: invalidDate, keep: 'yes' }, OPTS)
		expect(result).toEqual({ keep: 'yes' }) // the bad field is skipped, not the whole call
	})
})

describe('NormalizerRegistry — direct unit tests', () => {
	it('evaluate() returns identity for null, unsupported for undefined', () => {
		const registry = new NormalizerRegistry()
		expect(registry.evaluate(null, '')).toEqual({ action: 'identity' })
		expect(registry.evaluate(undefined, '')).toEqual({ action: 'unsupported' })
	})

	it('supports registering and unregistering a custom transform strategy', () => {
		const registry = new NormalizerRegistry()
		class Money {
			constructor(public cents: number) {}
		}
		const typeTag = Object.prototype.toString.call(new Money(0))

		registry.registerStrategy(
			typeTag,
			(val) => `$${(val as Money).cents / 100}`,
		)
		const decision = registry.evaluate(new Money(500), typeTag)
		expect(decision).toEqual({ action: 'transform', value: '$5' })

		const removed = registry.unregisterStrategy(typeTag)
		expect(removed).toBe(true)
		const afterRemoval = registry.evaluate(new Money(500), typeTag)
		expect(afterRemoval.action).not.toBe('transform')
	})

	it('supports registering a custom unsupported type', () => {
		const registry = new NormalizerRegistry()
		class Secret {}
		const typeTag = Object.prototype.toString.call(new Secret())

		registry.registerUnsupportedType(typeTag)
		expect(registry.evaluate(new Secret(), typeTag)).toEqual({
			action: 'unsupported',
		})
	})

	it('a custom registry instance can be passed into normalizePayload and takes effect', () => {
		const registry = new NormalizerRegistry()
		class Money {
			constructor(public cents: number) {}
		}
		registry.registerStrategy(
			Object.prototype.toString.call(new Money(0)),
			(val) => (val as Money).cents / 100,
		)

		const result = normalizePayload({ price: new Money(1999) }, OPTS, registry)
		expect(result.price).toBe(19.99)
	})
})

describe('normalizeJwtPayload', () => {
	it('always forces the Jwt policy regardless of caller intent, stripping reserved claims', () => {
		const result = normalizeJwtPayload(
			{
				userId: 'u-1',
				role: 'admin',
				iat: 999,
				exp: 999,
				jti: 'should-be-stripped',
			},
			{ maxDepth: 10, maxNodes: 200 },
		)
		expect(result).toEqual({ userId: 'u-1', role: 'admin' })
	})

	it('still enforces maxDepth/maxNodes as passed through', () => {
		const wide: Record<string, number> = {}
		for (let i = 0; i < 10; i++) wide[`f${i}`] = i

		expect(() =>
			normalizeJwtPayload(wide, { maxDepth: 10, maxNodes: 3 }),
		).toThrow(NormalizationError)
	})

	it('protects against prototype pollution the same as the standard path', () => {
		const malicious = JSON.parse(
			'{"userId":"u-1","__proto__":{"polluted":"yes"}}',
		)
		const result = normalizeJwtPayload(malicious, {
			maxDepth: 10,
			maxNodes: 200,
		})
		expect(result).toEqual({ userId: 'u-1' })
		expect(({} as Record<string, unknown>).polluted).toBeUndefined()
	})
})
