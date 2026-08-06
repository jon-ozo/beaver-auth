import { describe, expect, it } from 'vitest'
import { CryptoEngine } from '@beaver-auth/core'
import { currentTotpCode, TEST_TOTP_SECRET } from './support/totp.js'

describe('CryptoEngine.hashPassword / verifyPassword', () => {
	const crypto = new CryptoEngine()

	it('produces a self-describing scrypt$... hash with 6 $-delimited parts', async () => {
		const hash = await crypto.hashPassword('CorrectHorse9')
		const parts = hash.split('$')
		expect(parts).toHaveLength(6)
		expect(parts[0]).toBe('scrypt')
	})

	it('the correct password verifies successfully', async () => {
		const hash = await crypto.hashPassword('CorrectHorse9')
		expect(await crypto.verifyPassword('CorrectHorse9', hash)).toBe(true)
	})

	it('the wrong password fails verification', async () => {
		const hash = await crypto.hashPassword('CorrectHorse9')
		expect(await crypto.verifyPassword('WrongPassword', hash)).toBe(false)
	})

	it('two hashes of the same password are different (random salt per hash)', async () => {
		const hash1 = await crypto.hashPassword('CorrectHorse9')
		const hash2 = await crypto.hashPassword('CorrectHorse9')
		expect(hash1).not.toBe(hash2)
		expect(await crypto.verifyPassword('CorrectHorse9', hash1)).toBe(true)
		expect(await crypto.verifyPassword('CorrectHorse9', hash2)).toBe(true)
	})

	it('REGRESSION GUARD: a password at/over the old 128-char truncation boundary hashes and verifies correctly', async () => {
		// This is the bug found and fixed earlier: verifyPassword used to
		// silently truncate any password over 128 characters before
		// hashing, while hashPassword did not — so a legitimate long
		// password would hash correctly at registration but ALWAYS fail to
		// verify at login. That truncation code is gone entirely now; this
		// test confirms a 140-character password round-trips correctly.
		const longPassword = 'Aa1' + 'x'.repeat(137) // 140 chars total
		const hash = await crypto.hashPassword(longPassword)
		expect(await crypto.verifyPassword(longPassword, hash)).toBe(true)

		// A single-character difference at the very end must still fail —
		// proves the full password is actually being hashed, not silently
		// truncated to a shorter prefix that would make this pass by
		// accident.
		const almostSame = longPassword.slice(0, -1) + 'y'
		expect(await crypto.verifyPassword(almostSame, hash)).toBe(false)
	})

	it('returns false (not throws) for an empty password', async () => {
		const hash = await crypto.hashPassword('CorrectHorse9')
		await expect(crypto.verifyPassword('', hash)).resolves.toBe(false)
	})

	it('returns false (not throws) for a malformed/foreign stored hash', async () => {
		await expect(crypto.verifyPassword('anything', 'not-a-real-hash')).resolves.toBe(false)
		await expect(crypto.verifyPassword('anything', 'bcrypt$10$abc')).resolves.toBe(false)
		await expect(crypto.verifyPassword('anything', '')).resolves.toBe(false)
	})

	it('returns false (not throws) for a stored hash with the wrong number of $-delimited parts', async () => {
		await expect(crypto.verifyPassword('anything', 'scrypt$16384$8')).resolves.toBe(false)
	})

	it('returns false (not throws) for a stored hash with corrupted hex data', async () => {
		await expect(
			crypto.verifyPassword('anything', 'scrypt$16384$8$1$zzzz$not-valid-hex-either'),
		).resolves.toBe(false)
	})
})

describe('CryptoEngine.verifyTotpCode', () => {
	const crypto = new CryptoEngine()

	it('returns false with a null secret', () => {
		expect(crypto.verifyTotpCode('123456', null)).toEqual({
			valid: false,
			matchedCounter: null,
		})
	})

	it('validates a correct TOTP code for a real secret', () => {
		const code = currentTotpCode(TEST_TOTP_SECRET)
		const result = crypto.verifyTotpCode(code, TEST_TOTP_SECRET)
		expect(result.valid).toBe(true)
		expect(result.matchedCounter).not.toBeNull()
	})

	it('rejects an incorrect code', () => {
		const result = crypto.verifyTotpCode('000000', TEST_TOTP_SECRET)
		expect(result).toEqual({ valid: false, matchedCounter: null })
	})
})
