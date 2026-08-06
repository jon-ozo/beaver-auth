import { createHmac } from 'node:crypto'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function decodeBase32(secret: string): Buffer {
	const clean = secret.toUpperCase().replace(/=+$/, '')
	const bytes: number[] = []
	let bits = 0
	let value = 0

	for (const char of clean) {
		const idx = ALPHABET.indexOf(char)
		if (idx === -1) throw new Error(`Invalid base32 character: ${char}`)
		value = (value << 5) | idx
		bits += 5
		if (bits >= 8) {
			bytes.push((value >> (bits - 8)) & 255)
			bits -= 8
		}
	}

	return Buffer.from(bytes)
}

/** Computes the current 6-digit RFC 6238 TOTP code for a base32 secret. */
export function currentTotpCode(secret: string, atMs: number = Date.now()): string {
	const counter = Math.floor(atMs / 1000 / 30)
	return totpForCounter(secret, counter)
}

export function totpForCounter(secret: string, counter: number): string {
	const secretBuffer = decodeBase32(secret)
	const counterBuffer = Buffer.alloc(8)
	counterBuffer.writeBigUInt64BE(BigInt(counter), 0)

	const hmac = createHmac('sha1', secretBuffer).update(counterBuffer).digest()
	const offset = hmac[hmac.length - 1] & 0xf

	const binary =
		((hmac[offset] & 0x7f) << 24) |
		((hmac[offset + 1] & 0xff) << 16) |
		((hmac[offset + 2] & 0xff) << 8) |
		(hmac[offset + 3] & 0xff)

	return (binary % 1000000).toString().padStart(6, '0')
}

/** A valid-shaped base32 secret for test use. */
export const TEST_TOTP_SECRET = 'JBSWY3DPEHPK3PXP'
