// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { createHmac, timingSafeEqual } from 'node:crypto'
import { AuthRepoAdapter } from '../../types.js'
import { normalizeJwtPayload } from './normalize-payload/normalize-jwt-payload.js'
import {
	generateSecureToken,
	hashSecureToken,
} from '../internal/secure-token.js'

export interface TokenGeneratorConfig {
	adapter: AuthRepoAdapter
}

export type TokenPurpose =
	| 'email-verification'
	| 'magic-link'
	| 'password-reset'

export type JwtVerifyResult =
	| { valid: true; payload: Record<string, unknown> }
	| { valid: false; reason: string }

export class TokenEngine {
	private adapter: AuthRepoAdapter
	private readonly DEFAULT_TOKEN_TIMEOUT_MS = 1000 * 60 * 15 // 15 minutes default
	private static readonly JWT_HASH_ALG = 'sha256'
	private static readonly JWT_ALG = 'HS256'
	private static readonly JWT_TYP = 'JWT'
	private static readonly BYTE_SIZE = 32
	private static readonly ENCODING_UTF8 = 'utf8'
	private static readonly ENCODING_HEX = 'hex'
	private static readonly ENCODING_64_URL = 'base64url'

	constructor(config: TokenGeneratorConfig) {
		this.adapter = config.adapter
	}

	/**
	 * Generates a high-entropy token, hashes it for safety, and preserves it.
	 */
	public async create(
		email: string,
		purpose: TokenPurpose,
		timeoutMs?: number,
		txAdapter?: AuthRepoAdapter,
	): Promise<{ token: string; expiresAt: Date }> {
		const token = generateSecureToken()
		const expiresAt = new Date(
			Date.now() + (timeoutMs ?? this.DEFAULT_TOKEN_TIMEOUT_MS),
		)
		const identifier = `${purpose}:${email.toLowerCase().trim()}`

		// Standard SHA-256 prevents leaks if the database layer is compromised
		const tokenHash = hashSecureToken(token)

		const repo = txAdapter ?? this.adapter

		try {
			await repo.setVerificationToken({
				identifier,
				tokenHash,
				expiresAt,
			})

			return { token, expiresAt }
		} catch (err: any) {
			throw new Error(`Failed to set verification code: ${err}`)
		}
	}

	public createJwtToken(
		payload: Record<string, unknown>,
		expiresInSeconds: number,
		secret: string,
	): string {
		try {
			const secretSize = Buffer.byteLength(secret, TokenEngine.ENCODING_UTF8)
			const jti = generateSecureToken()

			if (!secret || secretSize < TokenEngine.BYTE_SIZE)
				throw new Error(
					`JWT secret must be at least ${TokenEngine.BYTE_SIZE} bytes long.`,
				)

			const normalizedJwtPayload = normalizeJwtPayload(payload, {
				maxDepth: 10,
				maxNodes: 200,
			})

			const header = { alg: TokenEngine.JWT_ALG, typ: TokenEngine.JWT_TYP }

			const issuedAt = Math.floor(Date.now() / 1000)
			const jwtPayload = Object.assign({}, normalizedJwtPayload, {
				jti,
				iat: issuedAt,
				exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
			})

			const toBase64Url = (obj: Record<string, unknown>) =>
				Buffer.from(JSON.stringify(obj)).toString(TokenEngine.ENCODING_64_URL)

			const encodedHeader = toBase64Url(header)
			const encodedPayload = toBase64Url(jwtPayload)
			const signature = createHmac(TokenEngine.JWT_HASH_ALG, secret)
				.update(`${encodedHeader}.${encodedPayload}`)
				.digest(TokenEngine.ENCODING_64_URL)

			return `${encodedHeader}.${encodedPayload}.${signature}`
		} catch (err: unknown) {
			if (err instanceof Error) {
				throw err
			}
			throw new Error('Token creation unsuccessful.')
		}
	}

	public verifyJwtToken(token: string, secret: string): JwtVerifyResult {
		try {
			if (!token || !secret) throw new Error(`Missing parameters.`)

			const parts = token.split('.')
			if (parts.length !== 3) throw new Error(`Invalid token format.`)

			const [headerStr, payloadStr, signatureStr] = parts

			const decodedHeader = JSON.parse(
				Buffer.from(headerStr, TokenEngine.ENCODING_64_URL).toString(),
			)

			if (decodedHeader.alg !== TokenEngine.JWT_ALG) {
				throw new Error(`Unsupported token algorithm.`)
			}

			const expectedSignature = createHmac(TokenEngine.JWT_HASH_ALG, secret)
				.update(`${headerStr}.${payloadStr}`)
				.digest(TokenEngine.ENCODING_64_URL)

			const sigBuffer = Buffer.from(signatureStr)
			const expectedBuffer = Buffer.from(expectedSignature)

			if (sigBuffer.length !== expectedBuffer.length) {
				throw new Error(`Invalid token.`)
			}

			const isValid = timingSafeEqual(sigBuffer, expectedBuffer)
			if (!isValid) throw new Error(`Invalid token.`)

			const decodedPayload = JSON.parse(
				Buffer.from(payloadStr, TokenEngine.ENCODING_64_URL).toString(),
			)

			if (
				typeof decodedPayload !== 'object' ||
				decodedPayload === null ||
				Array.isArray(decodedPayload)
			) {
				throw new Error(`Invalid token payload.`)
			}

			if (Date.now() / 1000 > decodedPayload.exp) {
				throw new Error(`Token expired.`)
			}

			return { valid: true, payload: decodedPayload }
		} catch (err: unknown) {
			return {
				valid: false,
				reason: `${err instanceof Error ? err.message : 'Invalid JWT token.'}`,
			}
		}
	}

	/**
	 * Validates an incoming clear token. Purges records immediately upon read
	 * to prevent distributed replay race conditions (Single-Use enforcement).
	 */
	public async consume(
		email: string,
		token: string,
		purpose: TokenPurpose,
	): Promise<boolean> {
		const identifier = `${purpose}:${email.toLowerCase().trim()}`

		// 1. Fetch the existing token context record from storage
		const record = await this.adapter.getVerificationToken(identifier)
		if (!record) return false

		// Revoke the token record from the database IMMEDIATELY on read.
		// This atomic step guarantees that overlapping parallel request attacks hit a null row
		// on the second thread, completely neutralizing replay race conditions.
		await this.adapter.deleteVerificationToken(identifier)

		// 2. Evaluate expiration boundaries post-deletion
		if (Date.now() > record.expiresAt.getTime()) {
			return false // Token successfully consumed but flagged as dead due to timeout constraints
		}

		const inputHash = hashSecureToken(token)

		const inputBuffer = Buffer.from(inputHash, TokenEngine.ENCODING_HEX)
		const recordBuffer = Buffer.from(record.tokenHash, TokenEngine.ENCODING_HEX)

		// 3. Enforce strict constant-time evaluations over matched length instances
		if (inputBuffer.length !== recordBuffer.length) {
			return false
		}

		return timingSafeEqual(inputBuffer, recordBuffer)
	}
}
