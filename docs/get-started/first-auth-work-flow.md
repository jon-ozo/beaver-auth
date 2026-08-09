# First Authentication Workflow

This guide walks through the first complete authentication flow with Beaver-Auth.

The goal is not to explain every feature. It is to show how the pieces fit together when building a real application:

```text
Application
    │
    ├── Create Beaver-Auth
    │
    ├── Register user
    │       │
    │       └── Optional email verification
    │
    ├── Login
    │       │
    │       ├── Password authentication
    │       ├── Verification check
    │       ├── Optional MFA
    │       └── Session or JWT
    │
    └── Protect authenticated routes
```

By the end of this guide, you should understand where Beaver-Auth ends and where your application begins.

---

## 1. Start with Your Application's Data Layer

Beaver-Auth does not own your database.

Instead, you provide an adapter that tells Beaver-Auth how your application stores and retrieves authentication data.

That means Beaver-Auth can work with your existing database layer rather than requiring you to adopt a particular ORM, schema, or persistence strategy.

A simplified adapter might look like this:

```ts
const adapter = {
	async findUserByEmail(email) {
		// Query your database
	},

	async findUserById(id) {
		// Query your database
	},

	async createUser(data) {
		// Insert into your database
	},

	async updateUser(id, data) {
		// Update your database
	},

	// ...other methods required by the flows you enable
}
```

The important boundary is:

```text
Your application
      │
      │  AuthRepoAdapter
      ▼
Beaver-Auth
      │
      ▼
Authentication logic
```

Beaver-Auth owns the authentication process.

You own the persistence implementation.

---

# 2. Create Beaver-Auth

There are two ways to work with Beaver-Auth.

### Factory composition

For most applications, start with `createBeaverAuth()`.

The factory constructs and wires the engines that belong together:

```ts
import { createBeaverAuth } from 'beaver-auth'

const auth = createBeaverAuth({
	adapter,

	onSystemError(error) {
		logger.error(error)
	},
})
```

The factory gives you a single authentication object:

```ts
auth.registration
auth.login
auth.sessions
auth.oauth
auth.verification
auth.passwordReset
auth.middleware
auth.rateLimiters
```

Optional capabilities are enabled by configuration.

For example, verification is enabled by providing the `verification` configuration:

```ts
const auth = createBeaverAuth({
	adapter,

	verification: {
		hooks: {
			async onVerificationRequired(payload) {
				// Send your verification email
			},
		},
	},
})
```

The same factory can also share infrastructure such as your dispatcher and system-error handler across the engines.

This is one of the primary reasons the factory exists: it removes the wiring burden without removing control.

---

## 3. Manual Composition

The factory is not mandatory.

Every major engine is also exported individually:

```ts
import {
	RegistrationEngine,
	LoginEngine,
	SessionManager,
	VerificationEngine,
} from 'beaver-auth'
```

You can therefore construct the authentication system yourself when you need more explicit control over the dependency graph.

For example:

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

The two approaches are therefore:

```text
Factory
createBeaverAuth()
       │
       └── Beaver-Auth wires the graph


Manual
RegistrationEngine
LoginEngine
SessionManager
VerificationEngine
       │
       └── You wire the graph
```

Use the factory when you want Beaver-Auth to handle composition.

Use the individual exports when you want to control composition yourself.

---

# 4. Registration

Once Beaver-Auth has been created, registration begins with:

```ts
const result = await auth.registration.execute({
	email,
	password,
	profile,
})
```

The registration engine validates the input before performing the registration operation.

It then checks whether the account already exists.

When enumeration protection is enabled, Beaver-Auth deliberately avoids immediately revealing that an email address already belongs to an account.

If the account does not exist, Beaver-Auth hashes the supplied password and passes the resulting user data to your adapter for persistence.

The important architectural boundary is:

```text
HTTP request
    │
    ▼
Your route handler
    │
    ▼
auth.registration.execute()
    │
    ├── Validate input
    ├── Check existing user
    ├── Hash password
    ├── Create user through adapter
    │
    └── Optional verification
```

Your route handler does not need to implement password hashing, enumeration handling, or verification orchestration itself.

---

# 5. Email Verification

Email verification is optional.

If you configure:

```ts
verification: {
  hooks: {
    async onVerificationRequired(payload) {
      // Send email
    },
  },
}
```

the registration engine can use the shared `VerificationEngine`.

The registration flow becomes:

```text
Registration
    │
    ▼
Create user
    │
    ├── verification disabled
    │       └── User becomes verified
    │
    └── verification enabled
            │
            ├── User becomes pending
            │
            └── VerificationEngine
                    │
                    ├── Create token
                    └── Dispatch verification hook
```

The verification engine owns the token lifecycle.

Your hook owns the delivery mechanism.

For example:

```ts
verification: {
  hooks: {
    async onVerificationRequired({
      email,
      token,
      expiresAt,
    }) {
      await emailService.send({
        to: email,
        template: 'verify-email',
        data: {
          token,
          expiresAt,
        },
      })
    },
  },
}
```

Beaver-Auth does not require a particular email provider.

Your hook is the integration boundary.

---

# 6. Completing Verification

Your application receives the verification request and passes the submitted credentials to the verification engine.

Conceptually:

```ts
const result = await auth.verification?.verifyEmail(email, token)
```

The verification engine:

1. validates the token through its token engine,
2. consumes the token,
3. finds the associated user,
4. marks the user as verified.

A successful result contains the authenticated user's ID.

```ts
if (result?.status === 'success') {
	// User is now verified
}
```

The important distinction is that your application controls the HTTP layer while Beaver-Auth controls the authentication state transition.

---

# 7. Login

Once the account is ready, authentication begins with the login engine.

```ts
const result = await auth.login.executePasswordStage(
	{
		email,
		password,
	},
	JWT_SECRET,
)
```

The password stage performs the authentication checks in a deliberate order.

Conceptually:

```text
Login request
    │
    ▼
Validate credentials
    │
    ▼
Find user
    │
    ▼
Verify password
    │
    ├── Invalid ───────────────► invalid-credentials
    │
    ▼
Check verification
    │
    ├── Pending ───────────────► unverified
    │
    ▼
Check MFA
    │
    ├── Enabled ───────────────► mfa-required
    │
    ▼
Create authentication state
    │
    ├── Session
    │
    └── JWT + refresh token
```

The login engine also performs a dummy password verification when the user does not exist or has no password hash. This keeps the password-verification path from trivially revealing whether an account exists.

---

# 8. When the User Has Not Verified Their Account

If verification is enabled and the user's account is still pending, password authentication succeeds but the login flow stops at verification.

The result is:

```ts
{
  status: 'unverified',
  userId: '...'
}
```

The application can then direct the user toward verification.

Beaver-Auth does not automatically send the user through your application's UI.

That remains your responsibility.

---

# 9. Resending Verification

A user can request another verification email through:

```ts
await auth.login.resendVerification({
	email,
	password,
})
```

This operation intentionally requires the correct password before revealing that the account is pending.

That ordering matters.

Without it, a public "resend verification" endpoint could become another account-enumeration channel and a mechanism for targeting real users with unwanted email.

The flow is therefore:

```text
Email + password
       │
       ▼
Verify password
       │
       ├── Invalid ──► invalid-credentials
       │
       ▼
Check verification state
       │
       ├── Already verified
       │
       └── Pending
              │
              ▼
       VerificationEngine
              │
              └── Dispatch new email
```

---

# 10. MFA

If the account has MFA enabled, successful password authentication does not immediately create the final authentication state.

Instead, Beaver-Auth creates a temporary MFA challenge:

```ts
{
  status: 'mfa-required',
  userId,
  mfaChallengeToken,
}
```

The application collects the MFA code and submits it to the second authentication stage.

```ts
const result = await auth.login.executeMfaStage(
	{
		mfaChallengeToken,
		code,
	},
	JWT_SECRET,
)
```

The MFA stage:

```text
MFA challenge
      │
      ▼
Validate temporary challenge
      │
      ▼
Load user
      │
      ▼
Verify TOTP
      │
      ▼
Reject replayed code
      │
      ▼
Create final authentication state
```

Beaver-Auth also tracks the last-used TOTP step and rejects replayed TOTP codes.

---

# 11. Choose Your Authentication State

After successful authentication, Beaver-Auth supports two session styles:

```text
session
JWT
```

The default login session type is the server-side session.

### Server-side session

```ts
const result = await auth.login.executePasswordStage(
	{
		email,
		password,
	},
	JWT_SECRET,
	{
		sessionType: 'session',
	},
)
```

The session manager creates the session and returns the session token and session information.

### JWT

```ts
const result = await auth.login.executePasswordStage(
	{
		email,
		password,
	},
	JWT_SECRET,
	{
		sessionType: 'jwt',
	},
)
```

For JWT authentication, Beaver-Auth creates:

```text
Access token
     +
Refresh token
```

The access token contains the user's email, ID, and role, while the refresh-token system manages the refresh-token lifecycle.

---

# 12. Refreshing a JWT

When the access token expires, the application can use the refresh token:

```ts
const result = await auth.login.refreshAccessToken(refreshToken, JWT_SECRET)
```

Beaver-Auth rotates the refresh token rather than simply issuing a new access token from the same long-lived refresh credential.

The flow is:

```text
Refresh token
      │
      ▼
Rotate refresh token
      │
      ├── Invalid / expired
      │
      ├── Reuse detected
      │       └── Token family revoked
      │
      └── Valid
              │
              ▼
          Load user
              │
              ▼
       Create new access token
              │
              ▼
       Return rotated refresh token
```

If refresh-token reuse is detected, Beaver-Auth can revoke the affected token family.

---

# 13. Protecting Authenticated Routes

Authentication is not complete when a user logs in.

Your application must also establish whether subsequent requests are authenticated.

When middleware is enabled through the factory:

```ts
const auth = createBeaverAuth({
	adapter,

	middleware: {
		jwtSecret: JWT_SECRET,
	},
})
```

the resulting authentication middleware engine becomes available as:

```ts
auth.middleware
```

Your framework-specific route layer remains responsible for extracting the request information and connecting it to Beaver-Auth.

This is intentional.

Beaver-Auth does not require Express, Fastify, NestJS, Hono, or another particular HTTP framework.

The boundary remains:

```text
Framework
    │
    │ request
    ▼
Your route/controller
    │
    ▼
Beaver-Auth
    │
    └── authentication decision
```

---

# 14. Add Rate Limiting at the Application Boundary

Rate limiting is also independently configurable.

For example:

```ts
const auth = createBeaverAuth({
	adapter,

	rateLimiters: {
		login: {
			// rate-limit configuration
		},
	},
})
```

The factory returns the configured limiter:

```ts
auth.rateLimiters.login
```

The important design decision is that Beaver-Auth does not automatically invoke the limiter inside `LoginEngine`.

Your application decides where and how to apply the limiter.

That allows you to choose the identifier appropriate for your threat model:

```text
IP
Email
User ID
IP + email
Other application-specific identity
```

This keeps rate limiting useful without assuming that every application should defend every authentication endpoint in exactly the same way.

---

# 15. System Errors and Observability

Authentication failures should not disappear into a console.

Beaver-Auth allows you to provide a shared `onSystemError` handler:

```ts
const auth = createBeaverAuth({
	adapter,

	onSystemError(error) {
		logger.error(error)
	},
})
```

The factory passes this shared handler into the engines it constructs unless an individual configuration overrides it.

That means an application can connect Beaver-Auth to its existing observability infrastructure without replacing Beaver-Auth's authentication logic.

For example:

```text
Beaver-Auth
    │
    ├── Registration
    ├── Login
    ├── Verification
    ├── Password reset
    └── Rate limiting
             │
             ▼
       onSystemError()
             │
             ▼
      Your logger / APM
```

The default behavior is `console.error`, but production applications can provide their own logging sink.

---

# 16. The Complete Flow

Putting everything together:

```text
                         ┌──────────────────────┐
                         │   Your Application   │
                         └──────────┬───────────┘
                                    │
                              createBeaverAuth
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │     Beaver-Auth      │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    │               │                │
                    ▼               ▼                ▼
              Registration        Login          Sessions
                    │               │
                    ▼               ▼
              Create user      Verify password
                    │               │
                    ▼               ▼
              Verification?    Verified?
                    │               │
              ┌─────┴─────┐    ┌────┴─────┐
              │           │    │          │
             No          Yes  No         Yes
              │           │    │          │
              │           ▼    │          ▼
              │      Verify email         MFA?
              │                │          │
              │                │      ┌───┴───┐
              │                │     No      Yes
              │                │      │       │
              │                │      │       ▼
              │                │      │    Verify MFA
              │                │      │       │
              └────────────────┴──────┴───────┘
                                           │
                                           ▼
                                ┌───────────────────┐
                                │ Authentication    │
                                │ State             │
                                ├───────────────────┤
                                │ Session           │
                                │ or                │
                                │ JWT + Refresh     │
                                └─────────┬─────────┘
                                          │
                                          ▼
                                  Protected routes
```

This is the central idea behind Beaver-Auth:

**your application controls the edges; Beaver-Auth controls the authentication machinery in the middle.**

You decide:

- how requests enter the system,
- how data is persisted,
- how emails are delivered,
- how your framework handles responses,
- how users are presented with authentication states,
- how authentication results map to your application's routes.

Beaver-Auth handles the security-sensitive authentication mechanics between those boundaries.

---

# 17. What You Actually Own

A useful way to think about Beaver-Auth is to separate **application responsibilities** from **authentication-engine responsibilities**.

### Your application owns

```text
Database
    │
    ├── User persistence
    ├── Session persistence
    ├── Token persistence
    └── Authentication-related records

HTTP framework
    │
    ├── Routes
    ├── Requests
    ├── Responses
    └── Cookies / headers

Infrastructure
    │
    ├── Email provider
    ├── Logging
    ├── Deployment
    └── External services

Application UX
    │
    ├── Login page
    ├── Registration page
    ├── Verification page
    └── MFA page
```

### Beaver-Auth owns

```text
Authentication logic
    │
    ├── Validation
    ├── Password hashing / verification
    ├── Enumeration defenses
    ├── Verification tokens
    ├── Session lifecycle
    ├── JWT lifecycle
    ├── Refresh-token rotation
    ├── MFA verification
    ├── OAuth engine
    └── Authentication security controls
```

This separation is what allows Beaver-Auth to remain useful across different application architectures without forcing your application to reorganize itself around the package.

---

## Where to Go Next

Now that you have seen the complete authentication lifecycle, continue with the individual guides:

- **[How It Works](./how-it-works.md)** — understand the internal mechanics behind each authentication stage.
- **[Architecture](./architecture.md)** — understand how Beaver-Auth's engines, adapters, hooks, and infrastructure fit together.
- **[Core Concepts](./core-concepts.md)** — understand the design principles behind the API.
- **[Installation](./installation.md)** — configure Beaver-Auth in a new project.
- **[Quick Start](./quick-start.md)** — build the smallest useful integration.
