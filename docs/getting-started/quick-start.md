# Quick Start

Beaver-Auth is designed around a simple idea:

> **You configure the authentication system. Beaver-Auth handles the security-critical workflow.**

You provide the persistence adapter and the application-specific integrations you control. Beaver-Auth provides the authentication engines, session management, token handling, verification workflows, password hashing, validation, and security-oriented behavior around those operations.

There are two ways to work with Beaver-Auth:

1. **Use `createBeaverAuth()`** — recommended for most applications.
2. **Construct the individual engines yourself** — useful when you need finer-grained control.

This guide uses the factory.

---

## 1. Install Beaver-Auth

```bash
pnpm add @beaver-auth/core
```

Or:

```bash
npm install @beaver-auth/core
```

Or:

```bash
yarn add @beaver-auth/core
```

Beaver-Auth is distributed as both ESM and CommonJS, with TypeScript declarations included.

---

## 2. Create Your Persistence Adapter

Beaver-Auth deliberately does not own your database.

Instead, it defines an adapter contract that connects the authentication engines to your application's persistence layer.

That means your existing database architecture remains yours.

For example, whether your application uses PostgreSQL directly, Prisma, Drizzle, MongoDB, or another persistence implementation, Beaver-Auth interacts with it through the adapter.

```ts
import type { AuthRepoAdapter, AuthSessionAdapter } from '@beaver-auth/core'

const adapter: AuthRepoAdapter & AuthSessionAdapter = {
	// User persistence
	findUserByEmail: async (email) => {
		// Query your database
	},

	findUserById: async (id) => {
		// Query your database
	},

	createUser: async (data) => {
		// Insert user into your database
	},

	updateUser: async (id, data) => {
		// Update user
	},

	deleteUserById: async (id) => {
		// Delete user
	},

	markUserVerified: async (id) => {
		// Mark the user as verified
	},

	// Session persistence
	createSession: async (data) => {
		// Persist session
	},

	findSessionByTokenHash: async (hash) => {
		// Find session
	},

	deleteSessionByTokenHash: async (hash) => {
		// Delete session
	},

	deleteUserSessions: async (userId) => {
		// Delete all sessions belonging to a user
	},

	updateSessionExpiry: async (tokenHash, date) => {
		// Extend session expiry
	},

	// ...implement the remaining adapter methods
}
```

The adapter is the boundary between Beaver-Auth and your application's data layer.

You do **not** replace your database layer to use Beaver-Auth.

---

## 3. Create the Authentication System

Once the adapter exists, create the Beaver-Auth instance.

```ts
import { createBeaverAuth } from '@beaver-auth/core'

const auth = createBeaverAuth({
	adapter,
})
```

That's the core setup.

The factory creates and wires the authentication components for you:

```ts
auth.registration
auth.login
auth.sessions
```

Optional capabilities become available when you configure them.

For example:

```ts
auth.verification
auth.passwordReset
auth.middleware
auth.rateLimiters
```

The factory uses an **opt-in configuration model**: optional capabilities are created when their corresponding configuration is supplied.

---

## 4. Register a User

Registration is handled by the registration engine.

```ts
const result = await auth.registration.execute({
	email: 'alice@example.com',
	password: 'SecurePassword123',
	profile: {
		firstName: 'Alice',
		lastName: 'Johnson',
	},
})
```

Beaver-Auth validates and normalizes the input before the registration workflow proceeds.

A successful registration without email verification produces:

```ts
{
	status: 'success'
}
```

If email verification is configured, the result becomes:

```ts
{
	status: 'success-pending-verification'
}
```

The application does not need to hash the password itself. Password hashing is part of the registration workflow.

---

## 5. Log the User In

Password authentication is handled through the login engine.

```ts
const result = await auth.login.executePasswordStage(
	{
		email: 'alice@example.com',
		password: 'SecurePassword123',
	},
	'',
	undefined,
	{
		sessionType: 'session',
	},
)
```

For a successful session-based login:

```ts
if (result.status === 'success-session') {
	console.log(result.token)
	console.log(result.session)
	console.log(result.user)
}
```

The login engine also handles important intermediate states.

For example:

```ts
if (result.status === 'invalid-credentials') {
	// Authentication failed
}

if (result.status === 'unverified') {
	// User must complete verification
}

if (result.status === 'mfa-required') {
	// Continue with the MFA stage
}
```

You don't have to build those authentication states into every route yourself.

---

## 6. Choose JWT Authentication Instead

Beaver-Auth supports both server-side sessions and JWT-based authentication.

To use JWTs, change the session type and provide your signing secret:

```ts
const result = await auth.login.executePasswordStage(
	{
		email: 'alice@example.com',
		password: 'SecurePassword123',
	},
	process.env.JWT_SECRET!,
	undefined,
	{
		sessionType: 'jwt',
	},
)
```

A successful JWT authentication returns:

```ts
if (result.status === 'success-jwt') {
	console.log(result.accessToken)
	console.log(result.refreshToken)
}
```

Beaver-Auth also provides refresh-token rotation through the login engine.

```ts
const refreshed = await auth.login.refreshAccessToken(
	refreshToken,
	process.env.JWT_SECRET!,
)
```

The important distinction is that **you choose the transport**.

```text
Session
    ↓
Server-side session state
    ↓
Session token

JWT
    ↓
Signed access token
    +
Refresh-token lifecycle
```

---

## 7. Add Email Verification

Email verification is opt-in.

Provide the verification hooks when creating the authentication system:

```ts
const auth = createBeaverAuth({
	adapter,

	verification: {
		hooks: {
			async onVerificationRequired({ email, userId, token, expiresAt }) {
				await sendVerificationEmail({
					email,
					userId,
					token,
					expiresAt,
				})
			},
		},
	},
})
```

Beaver-Auth handles the authentication side of the verification workflow.

Your application handles the delivery mechanism.

That separation is intentional.

```text
Beaver-Auth
    │
    ├── creates verification token
    ├── persists token
    ├── determines expiration
    └── dispatches verification hook
                │
                ▼
        Your email provider
```

Your hook can therefore use whatever email infrastructure your application already has.

---

## 8. Add Password Recovery

Password recovery follows the same integration model.

Enable it through the factory:

```ts
const auth = createBeaverAuth({
	adapter,

	passwordReset: {
		hooks: {
			async onPasswordResetRequested({ email, userId, token, expiresAt }) {
				await sendPasswordResetEmail({
					email,
					userId,
					token,
					expiresAt,
				})
			},
		},
	},
})
```

The password-reset engine handles the security-sensitive token lifecycle.

Your application remains responsible for delivering the recovery message.

---

## 9. Add Application-Level Error Logging

Beaver-Auth does not force your application to adopt a particular logging system.

You can provide `onSystemError` once at the factory level:

```ts
const auth = createBeaverAuth({
	adapter,

	onSystemError(error) {
		logger.error(error)
	},
})
```

That handler becomes the shared system-error sink for the engines created by the factory unless an individual configuration overrides it.

For example, you could connect it to:

- Pino
- Winston
- Sentry
- Datadog
- OpenTelemetry
- Your own logging infrastructure

Beaver-Auth therefore handles the authentication failure internally while giving your application control over **where operational errors are observed**.

---

## 10. Protect Authentication Routes with Rate Limiting

Rate limiting is also opt-in.

For example:

```ts
const auth = createBeaverAuth({
	adapter,

	rateLimiters: {
		login: {
			// rate limiter configuration
		},

		registration: {
			// rate limiter configuration
		},
	},
})
```

The factory gives the resulting limiters back to you:

```ts
auth.rateLimiters.login
auth.rateLimiters.registration
```

You then decide how the limiter is applied to your application's routes.

This is deliberate.

Beaver-Auth does not automatically assume whether your rate-limit identifier should be:

```text
IP address
email address
user ID
IP + email
```

That decision belongs to your application's threat model and deployment environment.

---

## 11. Connect Beaver-Auth to Your HTTP Layer

Beaver-Auth does not require Express, Fastify, NestJS, Hono, Next.js, or another particular framework.

Your route handler calls the Beaver-Auth engine and translates the result into your framework's response format.

For example:

```ts
const result = await auth.login.executePasswordStage(
	{
		email: request.body.email,
		password: request.body.password,
	},
	'',
	{
		userAgent: request.headers['user-agent'],
		ipAddress: request.ip,
	},
	{
		sessionType: 'session',
	},
)

if (result.status === 'success-session') {
	// Set the session cookie and return the authenticated user
}

if (result.status === 'invalid-credentials') {
	// Return an authentication failure
}

if (result.status === 'mfa-required') {
	// Continue to the MFA flow
}
```

The framework only handles the HTTP boundary.

Beaver-Auth handles the authentication workflow.

---

## 12. You Can Also Construct Engines Directly

The factory is the fastest way to get started, but it is not the only API.

Every major engine is exported individually.

```ts
import {
	RegistrationEngine,
	LoginEngine,
	SessionManager,
	VerificationEngine,
} from '@beaver-auth/core'
```

You can therefore construct and wire the components yourself when your application requires more control.

```ts
const sessions = new SessionManager({
	adapter,
})

const registration = new RegistrationEngine({
	adapter,
})

const login = new LoginEngine({
	adapter,
	sessions,
})
```

This is useful when you want to:

- construct only the engines you need
- control dependency wiring yourself
- provide different configuration to individual engines
- integrate Beaver-Auth into an existing dependency-injection architecture

The factory does not replace this API.

It simply removes the repetitive dependency-wiring work for the common case.

---

# The Mental Model

If you remember only one thing from this guide, remember this:

```text
Your Application
      │
      ├── Database
      ├── Email provider
      ├── HTTP framework
      ├── Logger
      └── Other infrastructure
              │
              ▼
        Your Adapter / Hooks
              │
              ▼
        ┌───────────────┐
        │  Beaver-Auth  │
        │               │
        │ Registration  │
        │ Login         │
        │ Sessions      │
        │ Verification  │
        │ Password Reset│
        │ MFA           │
        │ Tokens        │
        │ Rate Limiting │
        └───────────────┘
```

**Your infrastructure remains yours.**

**The authentication workflow becomes Beaver-Auth's responsibility.**

For most applications, start with `createBeaverAuth()`. Move to direct engine construction only when you need the additional control.

The next guide, [Core Concepts](./core-concepts.md), understand the design before writing the integration code.
