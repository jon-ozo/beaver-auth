// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import {
	AuthRepoAdapter,
	AuthSessionAdapter,
	RegistrationResult,
} from '../../types.js'
import { CryptoEngine } from '../internal/crypto.js'
import {
	StandardRegistrationOutput,
	ValidationEngine,
} from '../internal/validation.js'
import { ValidationError } from '../internal/error.js'
import { holdToFloor } from '../internal/hold-to-floor.js'
import { VerificationEngine } from '../verification/verification.js'

export interface RegistrationEngineConfig {
	adapter: AuthRepoAdapter & AuthSessionAdapter
	verification?: VerificationEngine
	responseFloorMs?: number
	verificationGracePeriodMs?: number
	runInTransaction?: <T>(
		work: (txAdapter: AuthRepoAdapter & AuthSessionAdapter) => Promise<T>,
	) => Promise<T>
	protectAgainstEnumeration?: boolean
	onSystemError?: (error: unknown) => void
}

export class RegistrationEngine<TProfile = Record<string, unknown>> {
	private adapter: AuthRepoAdapter & AuthSessionAdapter
	private readonly crypto: CryptoEngine
	private readonly validation: ValidationEngine
	private readonly verification?: VerificationEngine
	private runInTransaction?: <T>(
		work: (txAdapter: AuthRepoAdapter & AuthSessionAdapter) => Promise<T>,
	) => Promise<T>
	private readonly protectAgainstEnumeration: boolean
	private readonly onSystemError: (error: unknown) => void
	private readonly responseFloorMs: number
	private readonly verificationGracePeriodMs: number

	private static readonly DEFAULT_ROLE = 'user'
	private static readonly DEFAULT_RESPONSE_FLOOR_MS = 150
	private static readonly DEFAULT_VERIFICATION_GRACE_PERIOD_MS =
		1000 * 60 * 60 * 48

	private static readonly ENUMERATION_DUMMY_PASSWORD =
		'x-do-not-use-real-secret-placeholder-x'

	constructor(config: RegistrationEngineConfig) {
		this.adapter = config.adapter
		this.crypto = new CryptoEngine()
		this.validation = new ValidationEngine()
		this.verification = config.verification
		this.runInTransaction = config.runInTransaction
		this.protectAgainstEnumeration = config.protectAgainstEnumeration ?? true
		this.onSystemError =
			config.onSystemError ??
			((error) => {
				console.error('[beaver-auth]', error)
			})
		this.responseFloorMs =
			config.responseFloorMs ?? RegistrationEngine.DEFAULT_RESPONSE_FLOOR_MS
		this.verificationGracePeriodMs =
			config.verificationGracePeriodMs ??
			RegistrationEngine.DEFAULT_VERIFICATION_GRACE_PERIOD_MS
	}

	public async execute(
		rawInput: Record<string, unknown>,
		options?: {
			tokenTimeoutMs?: number
			role?: string
		},
	): Promise<RegistrationResult> {
		let sanitized: StandardRegistrationOutput<TProfile>

		try {
			sanitized = this.validation.validateInputs<TProfile>(rawInput)
		} catch (validationError: unknown) {
			const message =
				validationError instanceof ValidationError
					? validationError.message
					: 'Invalid registration input.'
			return { status: 'validation-error', message }
		}

		const start = Date.now()

		try {
			const result = this.runInTransaction
				? await this.runInTransaction(async (txAdapter) =>
						this.performRegistration(txAdapter, sanitized, options),
					)
				: await this.performRegistration(this.adapter, sanitized, options)

			await holdToFloor(this.responseFloorMs, start)
			return result
		} catch (systemError: unknown) {
			this.onSystemError(systemError)
			await holdToFloor(this.responseFloorMs, start)
			return {
				status: 'system-error',
				message:
					'An unexpected internal core auth engine processing exception was securely handled.',
			}
		}
	}

	public async purgeExpiredRegistrations(): Promise<{ purgedCount: number }> {
		if (typeof this.adapter.deleteExpiredUnverifiedUsers !== 'function') {
			const err = new Error(
				'purgeExpiredRegistrations() requires the adapter to implement ' +
					'deleteExpiredUnverifiedUsers(cutoff: Date).',
			)
			this.onSystemError(err)
			throw err
		}

		const verificationGracePeriodValue = this.verificationGracePeriodMs
		const cutoff = new Date(Date.now() - verificationGracePeriodValue)

		try {
			const purgedCount =
				await this.adapter.deleteExpiredUnverifiedUsers(cutoff)
			return { purgedCount }
		} catch (err) {
			this.onSystemError(err)
			throw err
		}
	}

	private async performRegistration(
		txAdapter: AuthRepoAdapter & AuthSessionAdapter,
		sanitized: StandardRegistrationOutput<TProfile>,
		options?: { tokenTimeoutMs?: number; role?: string },
	): Promise<RegistrationResult> {
		const requiresVerification = this.verification !== undefined
		const existingUser = await txAdapter.findUserByEmail(sanitized.email)

		if (existingUser) {
			if (this.protectAgainstEnumeration) {
				await this.crypto.hashPassword(
					sanitized.password ?? RegistrationEngine.ENUMERATION_DUMMY_PASSWORD,
				)
				return requiresVerification
					? { status: 'success-pending-verification' }
					: { status: 'success' }
			}
			return { status: 'email-already-exists' }
		}

		let passwordHash: string | null = null
		if (sanitized.password) {
			passwordHash = await this.crypto.hashPassword(sanitized.password)
		}

		const user = await txAdapter.createUser({
			email: sanitized.email,
			passwordHash,
			role: options?.role ?? RegistrationEngine.DEFAULT_ROLE,
			profile: sanitized.profile as Record<string, unknown>,
			verificationStatus: requiresVerification ? 'pending' : 'verified',
		})

		if (requiresVerification) {
			void this.verification
				.createAndDispatch({
					email: user.email,
					userId: user.id,
					timeoutMs: options?.tokenTimeoutMs,
				})
				.catch((err) => {
					this.onSystemError(err)
				})
		}

		return requiresVerification
			? { status: 'success-pending-verification' }
			: { status: 'success' }
	}
}
