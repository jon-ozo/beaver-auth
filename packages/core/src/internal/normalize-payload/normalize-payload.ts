import { NormalizerRegistry } from './normalizer-registry.js'
import { NormalizationError } from './normalizer-error.js'

export interface NormalizeOptions {
	maxDepth: number
	maxNodes: number
	policy?: PayloadPolicy
}

type StackFrame =
	| {
			type: 'object'
			source: Record<string, unknown>
			target: Record<string, unknown>
			keys: string[]
			keyIndex: number
			depth: number
	  }
	| {
			type: 'array'
			source: unknown[]
			target: unknown[]
			itemIndex: number
			depth: number
	  }

export enum PayloadPolicy {
	Standard,
	Jwt,
}

export const defaultRegistry = new NormalizerRegistry()

const JWT_RESERVED_KEYS = Object.freeze({
	iat: true,
	exp: true,
	jti: true,
	nbf: true,
	iss: true,
	aud: true,
}) as Record<string, boolean>

const PROTOTYPE_POLLUTION_KEYS = Object.freeze({
	__proto__: true,
	constructor: true,
	prototype: true,
}) as Record<string, boolean>

const toString = Object.prototype.toString

export function normalizePayload(
	payload: Record<string, unknown>,
	options: NormalizeOptions,
	registry: NormalizerRegistry = defaultRegistry,
): Record<string, unknown> {
	if (
		payload === null ||
		typeof payload !== 'object' ||
		Array.isArray(payload)
	) {
		throw new NormalizationError(
			'Input payload must be a plain object.',
			'INVALID_INPUT',
		)
	}

	const { maxDepth, maxNodes, policy } = options
	const isJwtPolicy = policy === PayloadPolicy.Jwt

	let totalNodesProcessed = 0
	const visited = new WeakSet<object>()
	const rootTarget = Object.create(null)
	visited.add(payload)

	const stack: StackFrame[] = [
		{
			type: 'object',
			source: payload,
			target: rootTarget,
			keys: Object.keys(payload),
			keyIndex: 0,
			depth: 0,
		},
	]

	const incrementAndCheckNodes = () => {
		if (++totalNodesProcessed > maxNodes) {
			stack.length = 0
			throw new NormalizationError(
				`Maximum node allowance of ${maxNodes} exceeded.`,
				'NODE_EXCEEDED',
			)
		}
	}

	while (stack.length > 0) {
		const current = stack[stack.length - 1]

		if (current.depth > maxDepth) {
			stack.length = 0
			throw new NormalizationError(
				`Maximum depth allocation of ${maxDepth} exceeded.`,
				'DEPTH_EXCEEDED',
			)
		}

		// --- CASE 1: Traversing Objects ---
		if (current.type === 'object') {
			if (current.keyIndex >= current.keys.length) {
				stack.pop()
				continue
			}

			const key = current.keys[current.keyIndex++]

			if (PROTOTYPE_POLLUTION_KEYS[key]) continue
			if (isJwtPolicy && JWT_RESERVED_KEYS[key]) continue

			let value: unknown
			let valType: string
			let objectType: string

			try {
				value = current.source[key]
				valType = typeof value
				objectType =
					value !== null && valType === 'object' ? toString.call(value) : ''
			} catch {
				current.target[key] = null
				continue
			}

			// Traversal engine asks the registry for strict execution commands
			const decision = registry.evaluate(value, objectType)

			if (decision.action === 'unsupported') {
				incrementAndCheckNodes()
				continue // Object mode skips key placement entirely
			}

			incrementAndCheckNodes()

			if (decision.action === 'transform') {
				current.target[key] = decision.value
			} else if (decision.action === 'identity') {
				if (valType === 'number' && !Number.isFinite(value)) {
					current.target[key] = null
				} else {
					current.target[key] = value
				}
			} else if (decision.action === 'traverse_array') {
				if (visited.has(value as object)) {
					current.target[key] = null
					continue
				}
				const nextArray: unknown[] = []
				current.target[key] = nextArray
				visited.add(value as object)
				stack.push({
					type: 'array',
					source: value as unknown[],
					target: nextArray,
					itemIndex: 0,
					depth: current.depth + 1,
				})
			} else if (decision.action === 'traverse_object') {
				if (visited.has(value as object)) {
					current.target[key] = null
				} else {
					try {
						const keys = Object.keys(value as object)
						const nextObj = Object.create(null)
						current.target[key] = nextObj
						visited.add(value as object)
						stack.push({
							type: 'object',
							source: value as Record<string, unknown>,
							target: nextObj,
							keys,
							keyIndex: 0,
							depth: current.depth + 1,
						})
					} catch {
						current.target[key] = null
					}
				}
			}
		}
		// --- CASE 2: Traversing Arrays ---
		else {
			if (current.itemIndex >= current.source.length) {
				stack.pop()
				continue
			}

			let item: unknown
			let itemType: string
			let objectType: string

			try {
				item = current.source[current.itemIndex++]
				itemType = typeof item
				objectType =
					item !== null && itemType === 'object' ? toString.call(item) : ''
			} catch {
				current.target.push(null)
				continue
			}

			const decision = registry.evaluate(item, objectType)

			if (decision.action === 'unsupported') {
				incrementAndCheckNodes()
				current.target.push(null) // Array mode pads with null to stay proportional
				continue
			}

			incrementAndCheckNodes()

			if (decision.action === 'transform') {
				current.target.push(decision.value)
			} else if (decision.action === 'identity') {
				if (itemType === 'number' && !Number.isFinite(item)) {
					current.target.push(null)
				} else {
					current.target.push(item)
				}
			} else if (decision.action === 'traverse_array') {
				if (visited.has(item as object)) {
					current.target.push(null)
					continue
				}
				const nextArray: unknown[] = []
				current.target.push(nextArray)
				visited.add(item as object)
				stack.push({
					type: 'array',
					source: item as unknown[],
					target: nextArray,
					itemIndex: 0,
					depth: current.depth + 1,
				})
			} else if (decision.action === 'traverse_object') {
				if (visited.has(item as object)) {
					current.target.push(null)
				} else {
					try {
						const keys = Object.keys(item as object)
						const nextObj = Object.create(null)
						current.target.push(nextObj)
						visited.add(item as object)
						stack.push({
							type: 'object',
							source: item as Record<string, unknown>,
							target: nextObj,
							keys,
							keyIndex: 0,
							depth: current.depth + 1,
						})
					} catch {
						current.target.push(null)
					}
				}
			}
		}
	}
	return rootTarget
}
