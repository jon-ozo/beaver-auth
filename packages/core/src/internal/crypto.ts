import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'
import { MfaEngine } from '../mfa/mfa.js'

const scryptAsync = promisify(
	(
		password: string | Buffer,
		salt: string | Buffer,
		keylen: number,
		options: any,
		callback: any,
	) => scrypt(password, salt, keylen, options, callback),
)

export class CryptoEngine {
	private readonly KEY_LENGTH = 64
	private readonly COST = 16384
	private readonly BLOCK_SIZE = 8
	private readonly PARALLELIZATION = 1
	private readonly staticDummyHash: string
	private readonly dummySalt: string
	private readonly mfaEngine: MfaEngine = new MfaEngine()

	constructor() {
		this.staticDummyHash = 'scrypt$16384$8$1$73616c74$64756d6d7968617368'
		this.dummySalt = '73616c74'
	}

	/**
	 * Hashes a password string utilizing native, fast runtime scrypt configurations.
	 */
	public async hashPassword(password: string): Promise<string> {
		const salt = randomBytes(16).toString('hex')
		const testKey = (await scryptAsync(password, salt, this.KEY_LENGTH, {
			cost: this.COST,
			blockSize: this.BLOCK_SIZE,
			parallelization: this.PARALLELIZATION,
		})) as Buffer

		return `scrypt$${this.COST}$${this.BLOCK_SIZE}$${this.PARALLELIZATION}$${salt}$${testKey.toString('hex')}`
	}

	/**
	 * Validates plain-text password inputs using an absolute timing-isolated processing layout.
	 */
	public async verifyPassword(
		password: string,
		storedHash: string,
	): Promise<boolean> {
		if (!password) {
			await this.executeFallbackVerification()

			return false
		}

		if (
			!storedHash ||
			typeof storedHash !== 'string' ||
			!storedHash.startsWith('scrypt$')
		) {
			await this.executeFallbackVerification()

			return false
		}

		try {
			const parts = storedHash.split('$')
			if (parts.length !== 6) {
				await this.executeFallbackVerification()

				return false
			}

			const [_, costStr, blockSizeStr, parallelStr, salt, hashHex] = parts

			const customOptions = {
				cost: parseInt(costStr, 10),
				blockSize: parseInt(blockSizeStr, 10),
				parallelization: parseInt(parallelStr, 10),
			}

			const targetKey = Buffer.from(hashHex, 'hex')
			const testKey = (await scryptAsync(
				password,
				salt,
				this.KEY_LENGTH,
				customOptions,
			)) as Buffer

			if (targetKey.length !== testKey.length) {
				// Enforce fallback cycles to keep the latency profile constant
				await this.executeFallbackVerification()

				return false
			}

			return timingSafeEqual(targetKey, testKey)
		} catch {
			await this.executeFallbackVerification()

			return false
		}
	}

	/**
	 * Consumes exact CPU execution cycles to match valid hash validation durations.
	 */
	private async executeFallbackVerification(): Promise<void> {
		const fakeKey = (await scryptAsync(
			this.staticDummyHash,
			this.dummySalt,
			this.KEY_LENGTH,
			{
				cost: this.COST,
				blockSize: this.BLOCK_SIZE,
				parallelization: this.PARALLELIZATION,
			},
		)) as Buffer
		const arbitraryTarget = Buffer.alloc(this.KEY_LENGTH)
		timingSafeEqual(arbitraryTarget, fakeKey)
	}

	/**
	 * Verifies a 6-digit TOTP pin using constant-time evaluation and clock drift windows.
	 */
	public verifyTotpCode(
		providedCode: string,
		mfaSecret: string | null,
	): { valid: boolean; matchedCounter: number | null } {
		if (!mfaSecret) return { valid: false, matchedCounter: null }
		return this.mfaEngine.verifyToken(mfaSecret, providedCode ?? '')
	}
}
