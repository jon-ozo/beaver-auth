import { describe, expect, it } from 'vitest'
import { MfaEngine } from '@beaver-auth/core'
import { currentTotpCode, totpForCounter, TEST_TOTP_SECRET } from './support/totp.js'

describe('MfaEngine.createTotpSecret', () => {
	const mfa = new MfaEngine()

	it('produces a base32 secret (only A-Z2-7) and a well-formed otpauth:// URI', () => {
		const { secret, uri } = mfa.createTotpSecret(32, 'user@example.com', 'BeaverAuth')

		expect(secret).toMatch(/^[A-Z2-7]+$/)
		expect(secret.length).toBe(32) // one char per random byte, default 32 bytes

		expect(uri).toMatch(/^otpauth:\/\/totp\//)
		expect(uri).toContain(`secret=${secret}`)
		expect(uri).toContain('algorithm=SHA1')
		expect(uri).toContain('digits=6')
		expect(uri).toContain('period=30')
		expect(uri).toContain(encodeURIComponent('user@example.com'))
		expect(uri).toContain(encodeURIComponent('BeaverAuth'))
	})

	it('generates a different secret on every call', () => {
		const a = mfa.createTotpSecret(32, 'a@example.com', 'Issuer')
		const b = mfa.createTotpSecret(32, 'a@example.com', 'Issuer')
		expect(a.secret).not.toBe(b.secret)
	})

	it('respects a custom byte count', () => {
		const { secret } = mfa.createTotpSecret(16, 'a@example.com', 'Issuer')
		expect(secret.length).toBe(16)
	})
})

describe('MfaEngine.verifyToken', () => {
	const mfa = new MfaEngine()

	it('validates the current correct code and reports the matched counter', () => {
		const code = currentTotpCode(TEST_TOTP_SECRET)
		const result = mfa.verifyToken(TEST_TOTP_SECRET, code)

		expect(result.valid).toBe(true)
		const expectedCounter = Math.floor(Date.now() / 1000 / 30)
		expect(result.matchedCounter).toBe(expectedCounter)
	})

	it('rejects an incorrect 6-digit code', () => {
		const currentCounter = Math.floor(Date.now() / 1000 / 30)
		const realCode = totpForCounter(TEST_TOTP_SECRET, currentCounter)
		// pick a definitely-wrong code
		const wrongCode = realCode === '000000' ? '111111' : '000000'

		const result = mfa.verifyToken(TEST_TOTP_SECRET, wrongCode)
		expect(result).toEqual({ valid: false, matchedCounter: null })
	})

	it('rejects malformed codes (wrong length, non-digits)', () => {
		expect(mfa.verifyToken(TEST_TOTP_SECRET, '12345').valid).toBe(false)
		expect(mfa.verifyToken(TEST_TOTP_SECRET, '1234567').valid).toBe(false)
		expect(mfa.verifyToken(TEST_TOTP_SECRET, 'abcdef').valid).toBe(false)
	})

	it('strips whitespace from the provided code before checking', () => {
		const code = currentTotpCode(TEST_TOTP_SECRET)
		const spaced = `${code.slice(0, 3)} ${code.slice(3)}`
		const result = mfa.verifyToken(TEST_TOTP_SECRET, spaced)
		expect(result.valid).toBe(true)
	})

	it('accepts a code from one step in the past or future (default drift window)', () => {
		const currentCounter = Math.floor(Date.now() / 1000 / 30)
		const previousStepCode = totpForCounter(TEST_TOTP_SECRET, currentCounter - 1)
		const nextStepCode = totpForCounter(TEST_TOTP_SECRET, currentCounter + 1)

		expect(mfa.verifyToken(TEST_TOTP_SECRET, previousStepCode)).toEqual({
			valid: true,
			matchedCounter: currentCounter - 1,
		})
		expect(mfa.verifyToken(TEST_TOTP_SECRET, nextStepCode)).toEqual({
			valid: true,
			matchedCounter: currentCounter + 1,
		})
	})

	it('rejects a code from two steps away — outside the default drift window', () => {
		const currentCounter = Math.floor(Date.now() / 1000 / 30)
		const twoStepsAgoCode = totpForCounter(TEST_TOTP_SECRET, currentCounter - 2)

		// Guard against the rare flake where the far-away code happens to
		// coincidentally collide with a code inside the actual window.
		const isAmbiguous = [-1, 0, 1].some(
			(i) => totpForCounter(TEST_TOTP_SECRET, currentCounter + i) === twoStepsAgoCode,
		)
		if (isAmbiguous) return

		const result = mfa.verifyToken(TEST_TOTP_SECRET, twoStepsAgoCode)
		expect(result).toEqual({ valid: false, matchedCounter: null })
	})

	it('respects a custom windowSteps value', () => {
		const currentCounter = Math.floor(Date.now() / 1000 / 30)
		const twoStepsAgoCode = totpForCounter(TEST_TOTP_SECRET, currentCounter - 2)

		expect(mfa.verifyToken(TEST_TOTP_SECRET, twoStepsAgoCode, 1).valid).toBe(false)
		expect(mfa.verifyToken(TEST_TOTP_SECRET, twoStepsAgoCode, 2).valid).toBe(true)
	})

	it('a wrong secret never validates the right code', () => {
		const code = currentTotpCode(TEST_TOTP_SECRET)
		const result = mfa.verifyToken('WRONGWRONGWRONGWRONG', code)
		expect(result.valid).toBe(false)
	})
})
