export class NormalizationError extends Error {
	constructor(
		message: string,
		public readonly code: 'DEPTH_EXCEEDED' | 'NODE_EXCEEDED' | 'INVALID_INPUT',
	) {
		super(message)
		this.name = 'NormalizationError'
		Object.setPrototypeOf(this, NormalizationError.prototype)
	}
}
