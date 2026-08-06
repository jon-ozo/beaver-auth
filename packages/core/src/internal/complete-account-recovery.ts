import { AuthRepoAdapter, AuthSessionAdapter } from '../../types.js'

/**
 * Shared "recovery completed" step for any account-recovery method (password
 * reset today; SMS/backup-codes/etc. later). Sets the new password hash and
 * revokes every existing session and refresh token for the account — a
 * successful recovery is a strong signal the old credential, and anything
 * authenticated under it, should no longer be trusted, regardless of which
 * channel was used to re-prove identity.
 *
 * The password WAS already changed by the time this runs its revocation
 * step — a failure revoking sessions/refresh tokens must not be treated as
 * a failure of the recovery itself. It's reported via onSystemError and
 * swallowed here; the caller should still report success to the user.
 */
export async function completeAccountRecovery(
	adapter: AuthRepoAdapter & AuthSessionAdapter,
	userId: string,
	newPasswordHash: string,
	onSystemError: (error: unknown) => void,
): Promise<void> {
	await adapter.updateUser(userId, { passwordHash: newPasswordHash })

	try {
		await adapter.deleteUserSessions(userId)
		await adapter.revokeAllRefreshTokensForUser(userId)
	} catch (err) {
		onSystemError(
			new Error(
				`Recovery succeeded for user ${userId} but revoking sessions/` +
					`refresh tokens failed. Cause: ${
						err instanceof Error ? err.message : String(err)
					}`,
			),
		)
	}
}
