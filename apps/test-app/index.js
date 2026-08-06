import { createBeaverAuth } from '@beaver-auth/core'

const memoryDb = { users: new Map() }

const mockAdapter = {
	async findUserByEmail(email) {
		return memoryDb.users.get(email) || null
	},
	async createSession(d) {
		return { id: d.id, userId: d.userId, expiresAt: d.expiresAt }
	},
}

async function runSimulation() {
	console.log('🚀 Testing Unified Secure Login Processing Engine...')
	const auth = createBeaverAuth({ adapter: mockAdapter })

	// Seed a standard password-secured test user context profile row
	const secureHash = auth.crypto.hashPassword('correctPassword123!')
	memoryDb.users.set('user@test.com', {
		id: 'u_948',
		email: 'user@test.com',
		passwordHash: secureHash,
		mfaEnabled: false,
	})

	// Seed a second user with active MFA multi-factor credentials properties configured
	memoryDb.users.set('mfa-user@test.com', {
		id: 'u_551',
		email: 'mfa-user@test.com',
		passwordHash: secureHash,
		mfaEnabled: true,
	})

	// --- Case 1: Standard Clean Successful Authentication ---
	const attempt1 = await auth.login.execute({
		email: 'user@test.com',
		password: 'correctPassword123!',
	})
	console.log(`\n[Login Attempt 1] Status Output: ${attempt1.status}`)
	if (attempt1.status === 'success')
		console.log(` -> Session Established Token: ${attempt1.session.id}`)

	// --- Case 2: MFA Interception Challenge Trigger ---
	const attempt2 = await auth.login.execute({
		email: 'mfa-user@test.com',
		password: 'correctPassword123!',
	})
	console.log(`\n[Login Attempt 2] Status Output: ${attempt2.status}`)
	if (attempt2.status === 'mfa-required')
		console.log(
			` -> Redirecting User ID [${attempt2.userId}] to 6-Digit input view.`,
		)

	// --- Case 3: Failed Password Credentials / Unknown Identity Probes ---
	const attempt3 = await auth.login.execute({
		email: 'scammer@harvest.com',
		password: 'guessedPassword',
	})
	console.log(`\n[Login Attempt 3] Status Output: ${attempt3.status}`)
}

runSimulation().catch(console.error)
