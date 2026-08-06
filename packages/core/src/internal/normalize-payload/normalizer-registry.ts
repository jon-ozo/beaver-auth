import { isAnyArrayBuffer, isTypedArray } from 'node:util/types'

export type NormalizerAction =
	| { action: 'transform'; value: unknown }
	| { action: 'unsupported' }
	| { action: 'traverse_object' }
	| { action: 'traverse_array' }
	| { action: 'identity' }

export class NormalizerRegistry {
	private strategies = new Map<string, (val: unknown) => unknown>()
	private unsupportedTypes = new Set<string>()

	constructor() {
		// Seed framework defaults
		this.registerStrategy('[object URL]', (val) => (val as URL).toString())
		this.registerStrategy('[object Date]', (val) => (val as Date).toISOString())
		this.registerStrategy('[object RegExp]', (val) =>
			(val as RegExp).toString(),
		)

		this.registerUnsupportedType('[object Map]')
		this.registerUnsupportedType('[object Set]')
		this.registerUnsupportedType('[object WeakMap]')
		this.registerUnsupportedType('[object WeakSet]')
		this.registerUnsupportedType('[object Promise]')
		this.registerUnsupportedType('[object Error]')
	}

	public registerStrategy(
		typeString: string,
		transform: (val: unknown) => unknown,
	): void {
		this.strategies.set(typeString, transform)
	}

	public unregisterStrategy(typeString: string): boolean {
		return this.strategies.delete(typeString)
	}

	public registerUnsupportedType(typeString: string): void {
		this.unsupportedTypes.add(typeString)
	}

	/**
	 * Unifies Supported, Unsupported, and Identity evaluation in one spot.
	 * Traversal loop blindly delegates routing behavior to this contract —
	 * the loop itself decides HOW to represent 'unsupported' (skip a key vs.
	 * pad an array with null) based on which branch it's in, since that's a
	 * structural property of object-vs-array, not something this registry
	 * needs to compute or carry.
	 */
	public evaluate(value: unknown, typeString: string): NormalizerAction {
		if (value === null) return { action: 'identity' }
		if (value === undefined) {
			return { action: 'unsupported' }
		}

		const valType = typeof value
		if (
			valType === 'function' ||
			valType === 'symbol' ||
			valType === 'bigint'
		) {
			return { action: 'unsupported' }
		}

		if (isTypedArray(value) || isAnyArrayBuffer(value)) {
			return { action: 'unsupported' }
		}

		const transform = this.strategies.get(typeString)
		if (transform) {
			try {
				return { action: 'transform', value: transform(value) }
			} catch {
				// A registered transform threw (e.g. an invalid Date's
				// toISOString() call). Fail soft, the same way a failed
				// property read elsewhere in the traversal falls back to
				// null/skip, rather than letting an exception from a single
				// bad field escape the entire normalization pass.
				return { action: 'unsupported' }
			}
		}

		if (this.unsupportedTypes.has(typeString)) {
			return { action: 'unsupported' }
		}

		if (Array.isArray(value)) {
			return { action: 'traverse_array' }
		}

		if (valType === 'object') {
			return { action: 'traverse_object' }
		}

		return { action: 'identity' }
	}
}
