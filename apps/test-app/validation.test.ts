import { describe, expect, it } from 'vitest'
import { ValidationEngine, ValidationError } from '@beaver-auth/core'

describe('ValidationEngine.validateInputs', () => {
	const engine = new ValidationEngine()

	it('trims and lowercases a valid email', () => {
		const result = engine.validateInputs({
			email: '  User@Example.COM  ',
			password: 'ValidPass9',
		})
		expect(result.email).toBe('user@example.com')
	})

	it('rejects a non-string email', () => {
		expect(() => engine.validateInputs({ email: 12345 })).toThrow(ValidationError)
	})

	it('rejects a malformed email', () => {
		try {
			engine.validateInputs({ email: 'not-an-email' })
			expect.fail('should have thrown')
		} catch (err) {
			expect(err).toBeInstanceOf(ValidationError)
			expect((err as ValidationError).field).toBe('email')
		}
	})

	it('leaves password undefined if omitted entirely', () => {
		const result = engine.validateInputs({ email: 'user@example.com' })
		expect(result.password).toBeUndefined()
	})

	it.each([
		['exactly 7 chars', 'Ab1defg'.slice(0, 7).padEnd(7, '1'), false],
		['exactly 8 chars (boundary)', 'Abcdefg1', true],
		['exactly 128 chars (boundary)', 'Aa1' + 'a'.repeat(125), true],
		['129 chars (over boundary)', 'Aa1' + 'a'.repeat(126), false],
		['all letters, no digit', 'OnlyLetters', false],
		['all digits, no letter', '12345678', false],
	])('password validation: %s', (_label, password, shouldPass) => {
		if (shouldPass) {
			expect(() => engine.validateInputs({ email: 'user@example.com', password })).not.toThrow()
		} else {
			expect(() => engine.validateInputs({ email: 'user@example.com', password })).toThrow(
				ValidationError,
			)
		}
	})

	it('returns profile: undefined when no profile is given', () => {
		const result = engine.validateInputs({ email: 'user@example.com' })
		expect(result.profile).toBeUndefined()
	})

	it('trims whitespace on profile string fields and passes numbers through', () => {
		const result = engine.validateInputs({
			email: 'user@example.com',
			profile: { name: '  Alice  ', age: 30 },
		})
		expect(result.profile).toEqual({ name: 'Alice', age: 30 })
	})

	it('rejects a profile with more than 20 fields', () => {
		const profile: Record<string, string> = {}
		for (let i = 0; i < 21; i++) profile[`field${i}`] = 'value'

		expect(() => engine.validateInputs({ email: 'user@example.com', profile })).toThrow(
			/Profile object too large/,
		)
	})

	it('accepts exactly 20 profile fields', () => {
		const profile: Record<string, string> = {}
		for (let i = 0; i < 20; i++) profile[`field${i}`] = 'value'

		expect(() => engine.validateInputs({ email: 'user@example.com', profile })).not.toThrow()
	})

	it('rejects an empty or whitespace-only profile string field', () => {
		expect(() =>
			engine.validateInputs({ email: 'user@example.com', profile: { bio: '' } }),
		).toThrow(/Empty string/)
		expect(() =>
			engine.validateInputs({ email: 'user@example.com', profile: { bio: '   ' } }),
		).toThrow(/Empty string/)
	})

	it('rejects a negative profile number field', () => {
		expect(() =>
			engine.validateInputs({ email: 'user@example.com', profile: { age: -1 } }),
		).toThrow(/Negative number/)
	})

	it('a NaN profile number field is coerced to null by normalization first, so it surfaces as Invalid type', () => {
		// normalizePayload coerces non-finite numbers (NaN/Infinity) to null
		// BEFORE profileValidator ever sees the field — so this documents
		// the actual (correct) behavior rather than asserting the naive
		// expectation.
		expect(() =>
			engine.validateInputs({ email: 'user@example.com', profile: { age: NaN } }),
		).toThrow(/Invalid type/)
	})

	it('rejects profile fields that are not string or number (booleans, arrays, nested objects)', () => {
		expect(() =>
			engine.validateInputs({ email: 'user@example.com', profile: { active: true } }),
		).toThrow(/Invalid type/)
		expect(() =>
			engine.validateInputs({ email: 'user@example.com', profile: { tags: ['a', 'b'] } }),
		).toThrow(/Invalid type/)
		expect(() =>
			engine.validateInputs({
				email: 'user@example.com',
				profile: { nested: { a: 1 } },
			}),
		).toThrow(/Invalid type/)
	})

	it('does not get polluted or crash when the payload contains a __proto__ key', () => {
		const maliciousPayload = JSON.parse(
			'{"email":"user@example.com","password":"ValidPass9","__proto__":{"polluted":"yes"}}',
		)

		expect(() => engine.validateInputs(maliciousPayload)).not.toThrow()
		expect(({} as Record<string, unknown>).polluted).toBeUndefined()
	})

	it('rejects a non-object top-level payload', () => {
		expect(() => engine.validateInputs(null as unknown as Record<string, unknown>)).toThrow(
			ValidationError,
		)
	})
})

describe('ValidationEngine.validateNewPassword (standalone)', () => {
	const engine = new ValidationEngine()

	it('returns the password unchanged when valid', () => {
		expect(engine.validateNewPassword('ValidPass9')).toBe('ValidPass9')
	})

	it('rejects a non-string value', () => {
		expect(() => engine.validateNewPassword(12345678)).toThrow(ValidationError)
	})

	it('rejects a weak password', () => {
		expect(() => engine.validateNewPassword('weak')).toThrow(ValidationError)
	})
})

describe('ValidationEngine.validateMfaPayload', () => {
	const engine = new ValidationEngine()

	it('trims the challenge token and strips whitespace from the code', () => {
		const result = engine.validateMfaPayload({
			mfaChallengeToken: '  abc123  ',
			code: '123 456',
		})
		expect(result).toEqual({ mfaChallengeToken: 'abc123', code: '123456' })
	})

	it('rejects a missing or empty mfaChallengeToken', () => {
		expect(() => engine.validateMfaPayload({ code: '123456' })).toThrow(ValidationError)
		expect(() =>
			engine.validateMfaPayload({ mfaChallengeToken: '   ', code: '123456' }),
		).toThrow(ValidationError)
	})

	it('rejects a code that is not exactly 6 digits', () => {
		expect(() =>
			engine.validateMfaPayload({ mfaChallengeToken: 'abc', code: '12345' }),
		).toThrow(ValidationError)
		expect(() =>
			engine.validateMfaPayload({ mfaChallengeToken: 'abc', code: 'abcdef' }),
		).toThrow(ValidationError)
	})

	it('does not crash on a __proto__ key in the MFA payload — confirms the normalized (not raw) data is used', () => {
		const maliciousPayload = JSON.parse(
			'{"mfaChallengeToken":"abc123","code":"123456","__proto__":{"polluted":"yes"}}',
		)

		expect(() => engine.validateMfaPayload(maliciousPayload)).not.toThrow()
		expect(({} as Record<string, unknown>).polluted).toBeUndefined()
	})
})
