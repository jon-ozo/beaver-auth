// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

export type TotpSecretResult = { secret: string; uri: string }

export class MfaEngine {
	private readonly alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

	/**
	 * Generates a high-entropy, unbiased base32 encoded secret string standard TOTP configuration URI.
	 */
	public createTotpSecret(
		numOfRandomBytes = 32,
		accountName: string,
		issuer: string,
	): TotpSecretResult {
		const bytes = randomBytes(numOfRandomBytes)
		let secret = ''

		for (let i = 0; i < bytes.length; i++) {
			secret += this.alphabet[bytes[i] & 31]
		}

		const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`
		const params = new URLSearchParams({
			secret,
			issuer: issuer,
			algorithm: 'SHA1',
			digits: '6',
			period: '30',
		})

		const uri = `otpauth://totp/${label}?${params.toString()}`

		return { secret, uri }
	}

	/**
	 * Validates code accuracy while defending against timing attacks and clock drift.
	 */
	public verifyToken(
		secret: string,
		token: string,
		windowSteps = 1,
	): { valid: boolean; matchedCounter: number | null } {
		const cleanToken = token.replace(/\s+/g, '')
		if (!/^\d{6}$/.test(cleanToken))
			return { valid: false, matchedCounter: null }

		const currentCounter = Math.floor(Date.now() / 1000 / 30)
		const secretBuffer = this.decodeBase32(secret)
		const cleanTokenBuffer = Buffer.from(cleanToken, 'utf8')

		let matchedCounter: number | null = null

		for (let i = -windowSteps; i <= windowSteps; i++) {
			const counter = currentCounter + i
			const generated = this.generateTotpForCounter(secretBuffer, counter)
			const generatedBuffer = Buffer.from(generated, 'utf8')

			// Still checked for every offset, unconditionally — no early exit —
			// to avoid leaking which offset matched via timing.
			if (timingSafeEqual(generatedBuffer, cleanTokenBuffer)) {
				matchedCounter = counter
			}
		}

		return { valid: matchedCounter !== null, matchedCounter }
	}

	/**
	 * Optimized base32 decoding logic using bit-shifting.
	 */
	private decodeBase32(secret: string): Buffer {
		if (!secret)
			throw new Error('Missing argument. Provide the missing secret.')

		const cleanSecret = secret.toUpperCase().replace(/=+$/, '')
		const length = cleanSecret.length
		const buffer = Buffer.alloc(Math.floor((length * 5) / 8))

		let bits = 0
		let value = 0
		let index = 0

		for (let i = 0; i < length; i++) {
			const idx = this.alphabet.indexOf(cleanSecret[i])
			if (idx === -1) throw new Error('Invalid base32 character')

			value = (value << 5) | idx
			bits += 5

			if (bits >= 8) {
				buffer[index++] = (value >> (bits - 8)) & 255
				bits -= 8
			}
		}

		return buffer
	}

	/**
	 * Computes the 6-digit TOTP string token for a specific time step counter.
	 */
	private generateTotpForCounter(
		secretBuffer: Buffer,
		counter: number,
	): string {
		const buffer = Buffer.alloc(8)

		// Write 64-bit integer counter to buffer safely using BigInt
		buffer.writeBigUInt64BE(BigInt(counter), 0)

		const hmac = createHmac('sha1', secretBuffer).update(buffer).digest()
		const offset = hmac[hmac.length - 1] & 0xf

		const binary =
			((hmac[offset] & 0x7f) << 24) |
			((hmac[offset + 1] & 0xff) << 16) |
			((hmac[offset + 2] & 0xff) << 8) |
			(hmac[offset + 3] & 0xff)

		return (binary % 1000000).toString().padStart(6, '0')
	}
}
