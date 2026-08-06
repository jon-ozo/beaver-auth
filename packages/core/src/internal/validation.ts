import { normalizePayload } from './normalize-payload/normalize-payload.js'
import { ValidationError } from './error.js'

export interface StandardRegistrationOutput<
	TProfile = Record<string, unknown>,
> {
	email: string
	password?: string
	profile?: TProfile
}

export interface MfaPayloadOutput {
	mfaChallengeToken: string
	code: string
}

export class ValidationEngine {
	private emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
	private passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,128}$/

	public validateInputs<TProfile = Record<string, unknown>>(
		data: Record<string, unknown>,
	): StandardRegistrationOutput<TProfile> {
		let normalizedData: unknown
		try {
			normalizedData = normalizePayload(data, {
				maxDepth: 20,
				maxNodes: 500,
			})
		} catch (err: unknown) {
			// normalizePayload throws its own internal, unexported
			// NormalizationError (invalid top-level input, maxDepth/maxNodes
			// exceeded). ValidationEngine's public contract is to only ever
			// throw ValidationError, so any consumer relying on
			// `instanceof ValidationError` isn't broken by an error type
			// they have no way to reference.
			throw new ValidationError(
				err instanceof Error
					? err.message
					: 'Invalid request payload form structural template.',
			)
		}
		if (!normalizedData || typeof normalizedData !== 'object') {
			throw new ValidationError(
				'Invalid request payload form structural template.',
			)
		}

		const payload = normalizedData as Record<string, unknown>

		if (typeof payload.email !== 'string') {
			throw new ValidationError(
				"Field 'email' must be a valid email format.",
				'email',
			)
		}
		const cleanEmail = payload.email.trim().toLowerCase()
		if (!this.emailRegex.test(cleanEmail)) {
			throw new ValidationError(
				'Provided email does not conform to RFC distribution standards.',
				'email',
			)
		}

		const validatedPassword =
			payload.password === undefined
				? undefined
				: this.validateNewPassword(payload.password)

		if (!payload.profile) {
			return {
				email: cleanEmail,
				password: validatedPassword,
				profile: undefined,
			}
		} else {
			const rawProfile = payload.profile as Record<string, unknown>
			const cleanProfile = this.profileValidator(rawProfile)

			return {
				email: cleanEmail,
				password: validatedPassword,
				profile: cleanProfile as TProfile,
			}
		}
	}

	/**
	 * Validates a standalone new password (no email context) — used both
	 * internally by validateInputs and externally by password-reset flows,
	 * so the format rule lives in exactly one place.
	 */
	public validateNewPassword(password: unknown): string {
		if (typeof password !== 'string' || !this.passwordRegex.test(password)) {
			throw new ValidationError(
				'Password attribute requires a string length of at least 8 characters.',
				'password',
			)
		}
		return password
	}

	private profileValidator(
		profile: Record<string, unknown>,
	): Record<string, unknown> {
		const keys = Object.keys(profile)
		const len = keys.length
		const MAX_LENGTH = 20
		const validatedProfile: Record<string, unknown> = {}

		if (len > MAX_LENGTH) {
			throw new ValidationError('Profile object too large.', 'profile')
		}

		for (let i = 0; i < len; i++) {
			const key = keys[i]
			const value = profile[key]
			const valType = typeof value
			const fieldPath = `profile.${key}`

			if (valType === 'string') {
				const strValue = value as string
				const valLen = strValue.length
				if (valLen === 0) {
					throw new ValidationError('Empty string.', fieldPath)
				}

				let start = 0
				let end = valLen - 1

				while (start <= end && strValue.charCodeAt(start) <= 32) start++
				while (end >= start && strValue.charCodeAt(end) <= 32) end--

				if (start > end) {
					throw new ValidationError('Empty string.', fieldPath)
				}

				validatedProfile[key] =
					start === 0 && end === valLen - 1
						? strValue
						: strValue.slice(start, end + 1)

				continue
			}

			if (valType === 'number') {
				const numValue = value as number
				if (numValue < 0 || Number.isNaN(numValue)) {
					throw new ValidationError('Negative number.', fieldPath)
				}
				validatedProfile[key] = numValue

				continue
			}

			throw new ValidationError('Invalid type.', fieldPath)
		}

		return validatedProfile
	}

	/**
	 * Parses, validates, and trims multi-factor transaction payloads.
	 */
	public validateMfaPayload(data: Record<string, unknown>): MfaPayloadOutput {
		let normalizedData: unknown
		try {
			normalizedData = normalizePayload(data, {
				maxDepth: 20,
				maxNodes: 500,
			})
		} catch (err: unknown) {
			throw new ValidationError(
				err instanceof Error
					? err.message
					: 'Invalid MFA request payload form template.',
			)
		}

		if (!normalizedData || typeof normalizedData !== 'object') {
			throw new ValidationError('Invalid MFA request payload form template.')
		}

		const payload = normalizedData as Record<string, unknown>

		if (
			typeof payload.mfaChallengeToken !== 'string' ||
			!payload.mfaChallengeToken.trim()
		) {
			throw new ValidationError(
				"Field 'mfaChallengeToken' must be a valid non-empty string identifier.",
				'mfaChallengeToken',
			)
		}

		if (
			typeof payload.code !== 'string' ||
			!/^\d{6}$/.test(payload.code.replace(/\s+/g, ''))
		) {
			throw new ValidationError(
				"Field 'code' must be a valid 6-digit text string entry.",
				'code',
			)
		}

		return {
			mfaChallengeToken: payload.mfaChallengeToken.trim(),
			code: payload.code.replace(/\s+/g, ''),
		}
	}
}
