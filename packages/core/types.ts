export interface User {
	id: string
	profile: Record<string, unknown>
	email: string
	passwordHash: string | null
	role: string
	mfaSecret: string | null
	mfaEnabled: boolean
	createdAt: Date
	verificationStatus: 'pending' | 'verified'
	lastUsedTotpStep?: number
}

export interface Session {
	tokenHash: string
	userId: string
	expiresAt: Date
	userAgent?: string
	ipAddress?: string
}

export type LoginResult =
	| { status: 'success-session'; user: User; session: Session; token: string }
	| {
			status: 'success-jwt'
			user: User
			accessToken: string
			refreshToken: string
			familyId: string
	  }
	| { status: 'mfa-required'; userId: string; mfaChallengeToken: string }
	| { status: 'invalid-credentials' }
	| { status: 'invalid-mfa-code' }
	| { status: 'invalid-mfa-token' }
	| { status: 'unverified'; userId: string }
	| { status: 'refresh-token-reused'; userId: string }
	| { status: 'system-error'; message: string }

export interface LoginInput {
	email: string
	password?: string
}

export interface RegistrationSuccess {
	status: 'success-pending-verification' | 'success'
}

export interface RegistrationEmailExistsError {
	status: 'email-already-exists'
}

export interface RegistrationValidationError {
	status: 'validation-error'
	message: string
}

export interface RegistrationSystemError {
	status: 'system-error'
	message: string
}

export type RegistrationResult =
	| RegistrationSuccess
	| RegistrationEmailExistsError
	| RegistrationValidationError
	| RegistrationSystemError

export type VerifyEmailResult =
	| { status: 'success'; userId: string }
	| { status: 'invalid-token' }
	| { status: 'system-error'; message: string }

export interface VerificationHooks {
	onVerificationRequired: (context: {
		email: string
		userId: string
		token: string
		expiresAt: Date
	}) => Promise<void> | void
}

export type ResendVerificationResult =
	| { status: 'resent' }
	| { status: 'already-verified' }
	| { status: 'invalid-credentials' }
	| { status: 'system-error'; message: string }

export interface VerificationHookPayload {
	email: string
	userId: string
	token: string
	expiresAt: Date
}

export interface VerificationToken {
	identifier: string
	tokenHash: string
	expiresAt: Date
}

export interface TaskDispatcher {
	dispatch(
		taskName: string,
		payload: unknown,
		handler: () => Promise<void>,
		onFailure?: (error: unknown) => Promise<void> | void,
	): Promise<void>
}

export interface AuthRepoAdapter {
	createRefreshToken(record: {
		tokenHash: string
		userId: string
		familyId: string
		status: 'active' | 'used'
		expiresAt: Date
	}): Promise<void>
	createUser(data: {
		email: string
		passwordHash: string | null
		role: string
		profile: Record<string, unknown>
		verificationStatus: 'pending' | 'verified'
	}): Promise<User>
	findUserByEmail(email: string): Promise<User | null>
	deleteExpiredUnverifiedUsers(date: Date): Promise<number>
	deleteExpiredRefreshTokens(cutoff: Date): Promise<number>
	deleteVerificationToken(identifier: string): Promise<void>
	deleteUserById(id: string): Promise<void>
	findRefreshTokenByHash(tokenHash: string): Promise<{
		userId: string
		familyId: string
		status: 'active' | 'used'
		expiresAt: Date
	} | null>
	findUserById(id: string): Promise<User | null>
	getVerificationToken(identifier: string): Promise<VerificationToken | null>
	markRefreshTokenUsed(tokenHash: string): Promise<void>
	// Flips a user from 'pending' to 'verified'. Separate from updateUser
	// rather than folded into its generic field-patch shape, since this is a
	// specific, security-relevant state transition (drives the enumeration-
	// safe registration flow and the lenient-unverified-session design) worth
	// its own explicit, narrow adapter contract rather than an easy-to-misuse
	// generic patch.
	markUserVerified(id: string): Promise<void>
	recordRevokedJti(jti: string): Promise<void>
	revokeRefreshTokenFamily(familyId: string): Promise<void>
	revokeAllRefreshTokensForUser(userId: string): Promise<void>
	setVerificationToken(token: VerificationToken): Promise<void>
	updateLastUsedTotpStep(userId: string, step: number): Promise<void>
	updateUser(
		id: string,
		data: Partial<Pick<User, 'passwordHash' | 'mfaSecret' | 'mfaEnabled'>>,
	): Promise<User>
}

export interface AuthSessionAdapter {
	createMfaChallengeToken(options: {
		tokenHash: string
		userId: string
		expiresAt: Date
	}): Promise<TemporaryMfaToken>
	createSession(data: {
		tokenHash: string
		userId: string
		expiresAt: Date
		userAgent?: string
		ipAddress?: string
	}): Promise<Session>
	deleteExpiredMfaChallengeTokens(date: Date): Promise<number>
	deleteMfaChallengeTokenByHash(tokenHash: string): Promise<void>
	deleteSessionByTokenHash(tokenHash: string): Promise<void>
	deleteUserSessions(userId: string): Promise<void>
	findMfaChallengeTokenByHash(
		tokenHash: string,
	): Promise<{ userId: string; expiresAt: Date } | null>
	findSessionByTokenHash(
		hash: string,
	): Promise<(Session & { user: User }) | null>
	updateSessionExpiry(tokenHash: string, date: Date): Promise<void>
}

export interface TemporaryMfaToken {
	tokenHash: string
	userId: string
	expiresAt: Date
}

export interface PasswordResetHookPayload {
	email: string
	userId: string
	token: string
	expiresAt: Date
}

export interface PasswordResetHooks {
	onPasswordResetRequested: (
		payload: PasswordResetHookPayload,
	) => Promise<void> | void
}

export type RequestPasswordResetResult =
	| { status: 'request-processed' }
	| { status: 'validation-error'; message: string }
	| { status: 'system-error'; message: string }

export type CompletePasswordResetResult =
	| { status: 'success'; userId: string }
	| { status: 'invalid-token' }
	| { status: 'validation-error'; message: string }
	| { status: 'system-error'; message: string }
