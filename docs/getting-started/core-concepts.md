# Core Concepts

Beaver-Auth is easiest to understand when you stop thinking of it as an authentication framework and start thinking of it as an **authentication system that you compose into your application**.

It owns the authentication workflows.

Your application owns the environment those workflows operate in.

That distinction drives almost every design decision in Beaver-Auth.

---

## The Mental Model

At a high level:

```text
                    YOUR APPLICATION
                          │
             ┌────────────┴────────────┐
             │                         │
        HTTP / Framework          Application Code
             │                         │
             └────────────┬────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │ Beaver-Auth │
                   │             │
                   │  Engines    │
                   │  Security   │
                   │  Workflows  │
                   └──────┬──────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
        Your Persistence         Your Services
          Adapter                    Hooks
```

Beaver-Auth does not attempt to own your HTTP framework, database, ORM, email provider, logging infrastructure, or application architecture.

Instead, it establishes explicit boundaries around the authentication system.

There are four concepts you should understand first:

1. **Engines**
2. **Adapters**
3. **Hooks and dispatchers**
4. **Composition**

Once those are clear, the rest of Beaver-Auth becomes much easier to reason about.

---

# 1. Engines

An **engine** owns an authentication capability or workflow.

Examples include:

```text
RegistrationEngine
LoginEngine
VerificationEngine
PasswordResetEngine
SessionManager
RefreshTokenEngine
AuthMiddlewareEngine
OAuthEngine
MfaEngine
RateLimiterEngine
TokenEngine
CryptoEngine
ValidationEngine
```

Each engine has a focused responsibility.

For example:

```text
RegistrationEngine
        │
        ├── validate registration input
        ├── protect against enumeration
        ├── hash credentials
        ├── create the user
        └── optionally initiate verification
```

While:

```text
SessionManager
        │
        ├── create sessions
        ├── validate sessions
        ├── extend sessions
        └── invalidate sessions
```

And:

```text
VerificationEngine
        │
        ├── create verification tokens
        ├── dispatch verification work
        └── consume verification tokens
```

The engines are deliberately separated because authentication is not one operation.

It is a collection of related security workflows.

---

# 2. Engines Own Workflows, Not Your Application

An engine determines **how an authentication workflow is executed**.

It does not determine how your application is structured around that workflow.

For example, Beaver-Auth can determine that registration should:

```text
Validate
   ↓
Find existing user
   ↓
Protect against enumeration
   ↓
Hash password
   ↓
Create user
   ↓
Create verification token
   ↓
Dispatch verification work
```

But it does not decide whether the registration request came from:

```text
Express
NestJS
Fastify
Next.js
Hono
A custom Node HTTP server
```

Nor does it decide whether the user is stored using:

```text
Prisma
Drizzle
MongoDB
PostgreSQL
MySQL
A custom repository
```

That separation is intentional.

---

# 3. Adapters

The **adapter is the persistence boundary between Beaver-Auth and your application**.

Beaver-Auth defines what authentication needs from persistence.

Your application implements those operations.

The central contracts are:

```ts
AuthRepoAdapter
AuthSessionAdapter
```

For example, Beaver-Auth can ask your application for a user:

```ts
const user = await adapter.findUserByEmail(email)
```

It does not care how that function finds the user.

Your implementation might use Prisma:

```ts
async function findUserByEmail(email: string) {
	return prisma.user.findUnique({
		where: { email },
	})
}
```

Or Drizzle:

```ts
async function findUserByEmail(email: string) {
	// Drizzle query
}
```

Or a manually written SQL repository:

```ts
async function findUserByEmail(email: string) {
	// SQL query
}
```

The authentication workflow remains the same.

The adapter is where the persistence implementation lives.

---

# Why Beaver-Auth Does Not Provide Database Models

This is an important architectural decision.

Beaver-Auth needs users, sessions, tokens, refresh tokens, MFA state, and other persistence records.

It could have provided its own database schema.

It deliberately does not.

Your application already owns its data model.

For example, your `User` may contain:

```text
id
email
passwordHash
role
profile
mfaSecret
mfaEnabled
createdAt
verificationStatus
```

Beaver-Auth works against the adapter contract rather than forcing that model into a particular ORM.

This means the authentication system remains independent from your persistence technology.

---

# 4. The Adapter Is More Than a User Repository

The adapter boundary covers the persistence required by the authentication workflows.

Depending on the capabilities you use, Beaver-Auth may need operations for:

### Users

```ts
findUserByEmail()
findUserById()
createUser()
updateUser()
deleteUserById()
markUserVerified()
deleteExpiredUnverifiedUsers()
```

### Verification and recovery tokens

```ts
setVerificationToken()
getVerificationToken()
deleteVerificationToken()
```

### Sessions

```ts
createSession()
findSessionByTokenHash()
deleteSessionByTokenHash()
updateSessionExpiry()
deleteUserSessions()
```

### MFA challenges

```ts
createMfaChallengeToken()
findMfaChallengeTokenByHash()
deleteMfaChallengeTokenByHash()
deleteExpiredMfaChallengeTokens()
```

### Refresh tokens

```ts
createRefreshToken()
findRefreshTokenByHash()
markRefreshTokenUsed()
revokeRefreshTokenFamily()
revokeAllRefreshTokensForUser()
deleteExpiredRefreshTokens()
```

The adapter therefore becomes the persistence boundary for the authentication subsystem.

---

# 5. Hooks

Some authentication workflows need to cause something to happen outside Beaver-Auth.

Email delivery is a good example.

Beaver-Auth can create a verification token.

It should not become an email provider.

Instead, it exposes a hook.

```ts
const verification = new VerificationEngine({
	adapter,

	hooks: {
		async onVerificationRequired(payload) {
			await emailProvider.sendVerificationEmail({
				email: payload.email,
				token: payload.token,
				expiresAt: payload.expiresAt,
			})
		},
	},
})
```

Beaver-Auth owns:

```text
token generation
token storage
token expiration
token consumption
```

Your application owns:

```text
email delivery
email templates
email provider
```

The same pattern is used for password recovery.

```ts
const passwordReset = new PasswordResetEngine({
	adapter,

	hooks: {
		async onPasswordResetRequested(payload) {
			await emailProvider.sendPasswordResetEmail(payload)
		},
	},
})
```

Hooks are therefore an **outbound application boundary**.

---

# 6. Hooks vs Adapters

The distinction is simple:

```text
Adapter
   ↓
Beaver-Auth needs something from your application.

Hook
   ↓
Your application needs something to happen because Beaver-Auth
completed or initiated part of a workflow.
```

For example:

```text
                    Beaver-Auth
                         │
             ┌───────────┴───────────┐
             │                       │
             ▼                       ▼
         Adapter                   Hook
             │                       │
             ▼                       ▼
       "Give me the user"      "Send this email"
```

This separation prevents Beaver-Auth from becoming tightly coupled to your infrastructure.

---

# 7. Task Dispatching

Hooks sometimes perform work that should not remain on the request path.

Verification email delivery is one example.

Beaver-Auth therefore separates token creation from hook execution.

Conceptually:

```text
Registration
     │
     ▼
Create verification token
     │
     ▼
Dispatch task
     │
     ▼
Execute hook
     │
     ▼
Retry on failure
```

The dispatcher is represented by:

```ts
TaskDispatcher
```

Beaver-Auth provides:

```ts
LocalTaskDispatcher
```

as its default implementation.

You can provide your own dispatcher when your infrastructure requires something more durable or distributed.

---

# 8. Optional Capabilities Are Enabled by Presence

One of the most important conventions in Beaver-Auth is:

> **Presence means opt-in.**

You do not configure every possible authentication capability just to use Beaver-Auth.

For example:

```ts
const verification = new VerificationEngine({
	adapter,
	hooks,
})

const registration = new RegistrationEngine({
	adapter,
	requireVerification: verification,
})
```

Verification is now part of registration.

If you omit it:

```ts
const registration = new RegistrationEngine({
	adapter,
})
```

registration does not require email verification.

The same idea appears throughout the factory API.

```ts
createBeaverAuth({
	adapter,

	verification: {
		hooks,
	},

	passwordReset: {
		hooks,
	},

	middleware: {
		jwtSecret,
	},

	rateLimiters: {
		login: {
			// ...
		},
	},
})
```

Each optional block enables a capability.

This keeps the base configuration small.

---

# 9. Two Ways to Work With Beaver-Auth

Beaver-Auth supports two composition styles.

## Direct Engine Construction

Every engine is individually exported.

You can construct exactly what you need:

```ts
import {
	RegistrationEngine,
	LoginEngine,
	SessionManager,
	VerificationEngine,
} from 'beaver-auth'
```

Then wire the dependencies yourself:

```ts
const sessions = new SessionManager({
	adapter,
})

const verification = new VerificationEngine({
	adapter,
	hooks,
})

const registration = new RegistrationEngine({
	adapter,
	requireVerification: verification,
})

const login = new LoginEngine({
	adapter,
	sessions,
	verification,
})
```

This approach provides maximum control.

It is useful when:

- you only need a subset of Beaver-Auth
- different engines need different configuration
- you want explicit dependency composition
- you are integrating Beaver-Auth into an existing architecture

---

## Factory Composition

You can alternatively use:

```ts
import { createBeaverAuth } from 'beaver-auth'
```

and allow Beaver-Auth to construct and wire the authentication graph.

```ts
const auth = createBeaverAuth({
	adapter,

	verification: {
		hooks,
	},

	passwordReset: {
		hooks,
	},

	middleware: {
		jwtSecret,
	},
})
```

You then receive the composed engines:

```ts
auth.registration
auth.login
auth.sessions
auth.verification
auth.passwordReset
auth.middleware
auth.oauth
auth.rateLimiters
```

The factory exists primarily to reduce composition work and prevent configuration mistakes when multiple engines depend on one another.

---

# 10. Shared Dependencies Matter

Some engines are related.

For example:

```text
                 VerificationEngine
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
      RegistrationEngine     LoginEngine
```

Registration can use the verification engine when creating an account.

Login can use that **same verification engine** when resending verification.

Constructing the graph manually means you are responsible for maintaining that relationship.

The factory handles it for you.

```ts
const auth = createBeaverAuth({
	adapter,

	verification: {
		hooks,
	},
})
```

Both registration and login receive the same `VerificationEngine` instance.

This is one of the practical reasons the factory exists.

---

# 11. `onSystemError`

Authentication systems inevitably encounter infrastructure failures.

A database may be unavailable.

A queue may fail.

An email provider may time out.

A custom adapter may throw.

Beaver-Auth exposes:

```ts
onSystemError?: (error: unknown) => void
```

This is an **observability boundary**.

For example:

```ts
const auth = createBeaverAuth({
	adapter,

	onSystemError(error) {
		logger.error(error)
	},
})
```

You can connect it to your existing:

- logger
- monitoring system
- error tracker
- alerting infrastructure
- structured logging pipeline

Beaver-Auth provides a default handler using `console.error`, so configuration is optional.

The important distinction is:

```text
Beaver-Auth detects the system failure.

Your application decides where that failure is observed.
```

---

# 12. Authentication Results Are Explicit

Beaver-Auth does not require consumers to interpret exceptions as normal authentication outcomes.

Engines return structured results.

For example, login can return:

```ts
{
	status: ('success-session', user, session, token)
}
```

or:

```ts
{
	status: ('mfa-required', userId, mfaChallengeToken)
}
```

or:

```ts
{
	status: 'invalid-credentials'
}
```

or:

```ts
{
	status: ('unverified', userId)
}
```

or:

```ts
{
	status: ('system-error', message)
}
```

This gives your HTTP layer a clean translation boundary.

For example:

```text
Beaver-Auth result
       │
       ▼
Your route/controller
       │
       ▼
HTTP response
```

Beaver-Auth does not need to know whether your application uses:

```text
HTTP 200
HTTP 401
HTTP 403
HTTP 422
HTTP 500
```

That decision belongs to your application's API contract.

---

# 13. Authentication Is Separate From HTTP

This is one of Beaver-Auth's core architectural boundaries.

A login engine does not need an Express `Request`.

It does not need a NestJS `ExecutionContext`.

It does not need a Next.js server action.

It receives authentication data and returns an authentication result.

For example:

```ts
const result = await auth.login.executePasswordStage(
	{
		email,
		password,
	},
	jwtSecret,
)
```

Your framework layer translates that into whatever response mechanism the application uses.

This is how Beaver-Auth avoids becoming a framework-specific authentication implementation.

---

# 14. Sessions and JWTs Are Different Authentication Transports

Beaver-Auth supports both session-based and JWT-based authentication.

They are not treated as the same mechanism.

## Session Authentication

A session is persisted server-side.

Conceptually:

```text
Client
  │
  │ session token
  ▼
Application
  │
  ▼
SessionManager
  │
  ▼
Database
```

The raw session token is not stored directly.

Beaver-Auth hashes it before persistence.

Sessions can also be extended when they pass the halfway point of their lifetime.

---

## JWT Authentication

JWT authentication is primarily stateless.

```text
Client
  │
  │ Authorization: Bearer <JWT>
  ▼
Application
  │
  ▼
JWT verification
```

The default verification path does not require a database read.

Optional JWT revocation can be enabled:

```ts
middleware: {
  jwtSecret,

  isJwtRevoked: async (jti) => {
    return revokedTokens.has(jti)
  },
}
```

This adds a persistence lookup, intentionally trading some statelessness for revocation capability.

---

# 15. JWTs Do Not Automatically Represent Current User State

A JWT contains the state placed into it when the token was issued.

Beaver-Auth's login flow currently places values such as:

```ts
{
	;(email, userId, role)
}
```

into the JWT.

That means:

```text
Database role
      │
      │ login
      ▼
JWT role
```

If the user's role changes later:

```text
Database: admin
JWT:      user
```

the existing JWT does not automatically change.

For authorization-sensitive decisions requiring current state, your application should retrieve current user information using the user ID rather than blindly trusting stale claims.

This distinction is especially important when designing authorization on top of Beaver-Auth.

---

# 16. Refresh Tokens Are Stateful

JWT access tokens can be short-lived while refresh tokens maintain the longer authentication lifecycle.

Beaver-Auth uses **refresh-token families**.

Conceptually:

```text
Login
  │
  ▼
Refresh Token A
  │
  │ rotation
  ▼
Refresh Token B
  │
  │ rotation
  ▼
Refresh Token C
```

The tokens belong to one family.

If an already-used refresh token is presented again:

```text
Replay detected
      │
      ▼
Revoke entire family
      │
      ▼
Require full authentication
```

This allows Beaver-Auth to detect refresh-token reuse rather than treating every refresh token as an isolated credential.

---

# 17. Single-Use Tokens

Verification and password-reset tokens follow a different lifecycle.

When a token is consumed, Beaver-Auth removes its stored record before completing validation.

Conceptually:

```text
Token presented
      │
      ▼
Retrieve token record
      │
      ▼
Delete token record
      │
      ▼
Validate expiration
      │
      ▼
Validate token hash
```

This is deliberate.

A second simultaneous request should not be able to successfully replay the same single-use token.

The same token infrastructure supports purposes such as:

```text
email-verification
magic-link
password-reset
```

---

# 18. Security Controls Are Part of the Workflow

Beaver-Auth does not treat security as a collection of unrelated utility functions.

Security controls are integrated into the workflows.

Examples include:

### Enumeration protection

Login and registration use defensive behavior around account existence.

### Password hashing

Credentials are hashed using Beaver-Auth's cryptographic layer.

### Timing-safe comparisons

Security-sensitive comparisons use constant-time comparison where appropriate.

### Response floors

Authentication responses can be held to a minimum duration to reduce timing differences.

### Token hashing

Persisted bearer tokens are stored as hashes rather than raw secrets.

### Replay protection

Refresh-token reuse and TOTP replay are detected.

### Token expiration

Verification, recovery, MFA, session, JWT, and refresh-token lifetimes are enforced by their respective engines.

The goal is to make secure behavior part of the workflow rather than something developers have to remember to add afterward.

---

# 19. Rate Limiting Is Deliberately Separate

Rate limiting is available through:

```ts
RateLimiterEngine
```

but Beaver-Auth does not automatically decide what should be rate-limited or what identifier should represent a caller.

That is intentional.

For example, an application may want to rate-limit login by:

```text
IP address
```

another application may prefer:

```text
email address
```

and another may use:

```text
IP + email
```

Those decisions depend on the application's threat model.

Beaver-Auth therefore provides the mechanism while leaving the policy to the application.

```ts
const result = await auth.rateLimiters.login?.acquire(identifier)
```

The engine supports different strategies and stores without forcing one infrastructure choice.

---

# 20. OAuth Is a Protocol Engine, Not a User Database

`OAuthEngine` handles the protocol-level pieces of an OAuth authorization-code flow.

It provides functionality for:

```text
authorization URL generation
        ↓
state generation
        ↓
PKCE code verifier
        ↓
authorization-code validation
        ↓
token exchange
        ↓
provider profile retrieval
        ↓
profile mapping
```

The provider-specific application logic remains yours.

For example, Beaver-Auth can retrieve a provider profile and pass the raw provider response to your mapper.

```ts
const profile = await oauth.fetchProfile(accessToken, profileUrl, (raw) => ({
	providerId: String(raw.id),
	email: String(raw.email),
}))
```

The application decides how that external identity maps onto its own user model.

---

# 21. MFA Is a Workflow Stage

MFA is not simply:

```text
verify a TOTP code
```

In Beaver-Auth, password authentication and MFA are separate stages.

Conceptually:

```text
Password Stage
      │
      ▼
Password valid?
      │
      ▼
MFA enabled?
   ┌──┴──┐
  No    Yes
   │      │
   │      ▼
   │   MFA challenge
   │      │
   │      ▼
   │   Verify TOTP
   │      │
   └──────┴──────► Create authenticated state
```

The first stage can return:

```ts
{
	status: ('mfa-required', userId, mfaChallengeToken)
}
```

The application then submits the challenge and TOTP code to the MFA stage.

Only after the second stage succeeds does Beaver-Auth create the authenticated session or JWT.

---

# 22. The Factory Is Composition, Not Magic

`createBeaverAuth()` does not introduce a different authentication system.

It constructs the same engines you can construct manually.

Conceptually:

```text
createBeaverAuth()
       │
       ├── SessionManager
       ├── VerificationEngine?
       ├── PasswordResetEngine?
       ├── RegistrationEngine
       ├── LoginEngine
       ├── OAuthEngine
       ├── AuthMiddlewareEngine?
       └── RateLimiterEngine?
```

The question mark means the capability is only constructed when its configuration is supplied.

This makes the factory useful as an application-level composition root.

---

# 23. The Composition Boundary

The overall architecture can therefore be understood as:

```text
                    Application
                         │
              ┌──────────┴──────────┐
              │                     │
         Request Layer          Services
              │                     │
              └──────────┬──────────┘
                         │
                         ▼
                  Beaver-Auth
                         │
       ┌─────────────────┼──────────────────┐
       │                 │                  │
       ▼                 ▼                  ▼
   Adapters            Hooks            Dispatchers
       │                 │                  │
       ▼                 ▼                  ▼
    Database        Email/SMS/etc.       Queue/Worker
```

Beaver-Auth sits in the middle.

It coordinates the authentication workflows without taking ownership of the surrounding systems.

---

# 24. What Beaver-Auth Owns

Beaver-Auth owns the implementation of authentication workflows and their security-sensitive mechanics.

That includes things such as:

```text
Registration
Login
Verification
Password recovery
Sessions
JWT creation and verification
Refresh-token rotation
MFA/TOTP
OAuth protocol operations
Rate limiting
Token generation
Cryptographic operations
Validation
Security-sensitive workflow behavior
```

---

# 25. What Your Application Owns

Your application remains responsible for:

```text
HTTP
Framework integration
Database
ORM
User schema
Database transactions
Email provider
SMS provider
Queues
Background workers
Logging
Monitoring
Infrastructure
Authorization policy
Application-specific business rules
```

This is the boundary that makes Beaver-Auth useful inside an existing architecture rather than requiring the architecture to be redesigned around the authentication package.

---

# The Principle Behind Beaver-Auth

The easiest way to remember the architecture is:

> **Beaver-Auth owns the authentication workflow. Your application owns everything around it.**

That means Beaver-Auth does not try to replace your architecture.

It gives the authentication subsystem a well-defined place inside it.

```text
             YOUR ARCHITECTURE
                    │
                    │
        ┌───────────▼───────────┐
        │       Beaver-Auth     │
        │                       │
        │ Authentication        │
        │ Security Workflows    │
        │ Token Lifecycle       │
        │ Session Lifecycle     │
        │ MFA / OAuth / Recovery│
        └───────────┬───────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
   Your Database           Your Services
```

Once this model is understood, the individual guides become much easier to follow.

The next step is to see the architecture. [Architectural Design](./architecture.md).
