// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

export class ValidationError extends Error {
	public readonly field?: string

	constructor(message: string, field?: string) {
		super(message)
		this.name = 'ValidationError'
		this.field = field

		// Maintains correct prototype chain when compiled down (needed because
		// extending built-ins like Error is finicky across some TS targets).
		Object.setPrototypeOf(this, ValidationError.prototype)
	}
}
