# How Beaver-Auth Works

Beaver-Auth is built around a simple idea:

> **Your application owns the infrastructure. Beaver-Auth owns the authentication logic.**

It does not attempt to become your web framework, ORM, database, email provider, or application server.

Instead, Beaver-Auth provides a collection of authentication engines that execute security-sensitive workflows while your application supplies the infrastructure those workflows need.

At runtime, the relationship looks roughly like this:

```text
                    Your Application
                           │
                           ▼
                  ┌─────────────────┐
                  │  Route / Handler │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │   Beaver-Auth   │
                  │     Engine      │
                  └────────┬────────┘
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
        Validation      Crypto       Workflow
             │             │             │
             └─────────────┼─────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │    Adapter(s)   │
                  └────────┬────────┘
                           │
                           ▼
                    Your Database
```

The important distinction is that Beaver-Auth is not a collection of middleware functions that your framework must understand.

It is a **workflow engine**.

---

## 1. The Application Owns the Boundary

Beaver-Auth deliberately does not own your HTTP request/response lifecycle.

Your application receives the request, extracts the information Beaver-Auth needs, invokes an engine, and decides how the result should become an HTTP response.

For example:

```text
HTTP Request
     │
     ▼
Your Route Handler
     │
     │  extract email/password
     ▼
LoginEngine
     │
     ├── validate input
     ├── retrieve user
     ├── verify password
     ├── check verification
     ├── check MFA
     └── establish authentication
     │
     ▼
LoginResult
     │
     ▼
Your Route Handler
     │
     ▼
HTTP Response
```

This boundary is intentional.

Beaver-Auth does not need to know whether the caller is:

- Express
- Fastify
- NestJS
- Hono
- a serverless function
- a custom Node HTTP server
- or another JavaScript runtime architecture

The application remains responsible for translating its transport layer into Beaver-Auth's API.

---

# 2. Two Ways to Construct Beaver-Auth

Beaver-Auth supports two styles of construction.

### The factory

For most applications, `createBeaverAuth()` is the simplest entry point.

The factory constructs and wires the dependency graph for you:

```ts
const auth = createBeaverAuth({
	adapter,
	verification: {
		hooks: verificationHooks,
	},
	passwordReset: {
		hooks: passwordResetHooks,
	},
	middleware: {
		jwtSecret,
	},
})
```

The factory creates the shared objects and connects them where necessary.

For example, the same `VerificationEngine` is supplied to both registration and login. This means registration can initiate verification and login can later resend verification through the same verification subsystem.

The factory also propagates shared configuration such as `onSystemError`, the default task dispatcher, and response-floor settings.

Optional capabilities are enabled by configuration presence.

```text
createBeaverAuth()
       │
       ├── RegistrationEngine
       ├── LoginEngine
       ├── SessionManager
       ├── OAuthEngine
       │
       ├── VerificationEngine      ← optional
       ├── PasswordResetEngine     ← optional
       ├── AuthMiddlewareEngine    ← optional
       │
       └── RateLimiterEngine(s)    ← optional
```

This is the **convenience path**.

### Individual engines

The factory does not hide the underlying architecture.

Every major engine is also exported individually:

```ts
import {
	RegistrationEngine,
	LoginEngine,
	VerificationEngine,
	SessionManager,
	RateLimiterEngine,
} from 'beaver-auth'
```

This allows applications to construct only what they need or control the dependency graph themselves.

The two approaches therefore represent different levels of control:

```text
Factory
  ↓
Less wiring
Less configuration
Faster setup

Individual engines
  ↓
More wiring
More control
More customization
```

The underlying engines remain the same.

---

# 3. The Adapter Is the Infrastructure Boundary

Beaver-Auth does not create a database model for your application.

Instead, authentication engines communicate with your persistence layer through adapters.

Conceptually:

```text
Beaver-Auth
     │
     │ AuthRepoAdapter
     ▼
Your Repository / Data Access Layer
     │
     ▼
Prisma / Drizzle / SQL / MongoDB / etc.
     │
     ▼
Your Database
```

The important consequence is that the authentication workflow does not need to know how your data is stored.

For example, a login operation needs to find a user by email.

Beaver-Auth asks the adapter for that operation.

Your application decides whether that operation is implemented using Prisma, Drizzle, handwritten SQL, a repository class, or something else.

This keeps the authentication workflow independent from the persistence technology.

It also means an ORM migration primarily affects your adapter/repository layer rather than the authentication workflow itself.

---

# 4. Engines Own Workflows

Beaver-Auth divides authentication into explicit engines rather than putting everything into one large authentication service.

The major public engines include:

| Engine                 | Responsibility                                          |
| ---------------------- | ------------------------------------------------------- |
| `RegistrationEngine`   | User registration                                       |
| `LoginEngine`          | Credential authentication and login stages              |
| `VerificationEngine`   | Verification-token lifecycle                            |
| `PasswordResetEngine`  | Account-recovery workflow                               |
| `SessionManager`       | Application sessions and temporary authentication state |
| `AuthMiddlewareEngine` | Authentication enforcement at the application boundary  |
| `OAuthEngine`          | OAuth functionality                                     |
| `MfaEngine`            | Multi-factor authentication                             |
| `RateLimiterEngine`    | Rate-limiting behavior                                  |
| `TokenEngine`          | Token creation and validation                           |
| `RefreshTokenEngine`   | Refresh-token lifecycle                                 |
| `CryptoEngine`         | Cryptographic operations                                |
| `ValidationEngine`     | Input validation                                        |

The engines are not independent islands.

They collaborate where a workflow requires it.

---

# 5. Registration

Registration starts with your application passing user input to `RegistrationEngine`.

The engine first validates and normalizes the input.

```text
Registration Request
        │
        ▼
ValidationEngine
        │
        ▼
Find existing user
        │
        ├── Existing
        │      │
        │      └── enumeration protection
        │
        └── New
               │
               ▼
          Hash password
               │
               ▼
           Create user
               │
               ▼
       Verification required?
          │             │
         yes            no
          │             │
          ▼             ▼
      pending         verified
          │
          ▼
 VerificationEngine
```

If verification is required, the user is created with a pending verification state.

The verification workflow is then handed to `VerificationEngine`.

The verification work is deliberately dispatched asynchronously rather than making the registration response wait for the email-delivery hook.

This gives registration a clear separation between:

1. creating the account, and
2. delivering the verification message.

---

# 6. Verification Is Its Own Workflow

`VerificationEngine` owns the lifecycle of verification tokens.

It is not simply an email helper.

Its responsibilities include:

```text
Create verification token
        │
        ▼
Retry token creation if necessary
        │
        ▼
Build verification hook payload
        │
        ▼
TaskDispatcher
        │
        ▼
onVerificationRequired()
```

The dispatcher is responsible for the execution/retry behavior of the hook.

This means token creation and message delivery are separate concerns.

The verification engine can also consume a presented token:

```text
Verification Request
        │
        ▼
VerificationEngine.verifyEmail()
        │
        ▼
Consume token
        │
        ├── invalid → invalid-token
        │
        ▼
Find user
        │
        ▼
Mark user verified
        │
        ▼
success
```

The same verification engine can therefore be reused by different authentication workflows.

For example, registration can use it to send the initial verification message, while login can use it to resend verification to an unverified account.

---

# 7. Login Is a Multi-Stage Workflow

Login is not treated as one monolithic operation.

`LoginEngine` explicitly models authentication as stages.

The password stage performs the initial credential verification:

```text
Email + Password
       │
       ▼
Validation
       │
       ▼
Find User
       │
       ▼
Verify Password
       │
       ├── invalid
       │
       └── valid
              │
              ▼
       Verification Status
              │
              ├── pending
              │
              └── verified
                     │
                     ▼
                 MFA enabled?
                  │       │
                 yes      no
                  │       │
                  ▼       ▼
              MFA step   Establish
                         authentication
```

This is important because authentication is not complete merely because a password is correct.

Beaver-Auth continues through the account's configured security state.

If MFA is enabled, the password stage creates a temporary MFA challenge rather than immediately establishing the authenticated session.

If MFA is not required, the engine proceeds to establish authentication.

---

# 8. Authentication Can End in Two Ways

After successful authentication, Beaver-Auth supports two session strategies through the login workflow:

```text
                  Authentication
                        │
             ┌──────────┴──────────┐
             │                     │
             ▼                     ▼
          Session                 JWT
             │                     │
             ▼                     ▼
      SessionManager          Access Token
             │                     │
             ▼                     ▼
       Session + Token        Refresh Token
```

### Server-side session

With the session strategy, `SessionManager` creates the session and returns the session token.

The application can then use that token according to its own transport mechanism.

### JWT

With the JWT strategy, `LoginEngine` creates an access token containing the authenticated user's relevant claims and also issues a refresh token.

The current login implementation creates the JWT from the user's email, ID, and role and pairs it with a refresh token.

The application therefore chooses the authentication representation rather than Beaver-Auth forcing one model.

---

# 9. Refresh Tokens Have Their Own Lifecycle

JWT access tokens are intentionally short-lived.

When the access token needs to be renewed, the application passes the refresh token back to `LoginEngine`.

The refresh workflow is:

```text
Refresh Token
      │
      ▼
RefreshTokenEngine.rotate()
      │
      ├── invalid / expired
      │
      ├── reused
      │       │
      │       └── revoke token family
      │
      └── valid
             │
             ▼
          Find user
             │
             ▼
       Create new JWT
             │
             ▼
       Return new tokens
```

Refresh-token rotation is therefore not simply “decode a token and issue another JWT.”

The refresh-token subsystem maintains its own lifecycle and can detect reuse.

The login engine also exposes JWT-session logout by revoking the refresh-token family.

---

# 10. MFA Is a Second Authentication Stage

When a user has MFA enabled, Beaver-Auth does not treat the password as the final authentication event.

Instead:

```text
Password verified
      │
      ▼
Temporary MFA token
      │
      ▼
Client submits MFA code
      │
      ▼
Verify temporary challenge
      │
      ▼
Revoke temporary challenge
      │
      ▼
Find user
      │
      ▼
Verify TOTP
      │
      ▼
Check replay protection
      │
      ▼
Establish session / JWT
```

The temporary challenge is revoked before the authentication continues.

For TOTP, Beaver-Auth also tracks the matched TOTP counter and rejects a code whose counter has already been used.

This makes MFA part of the authentication state machine rather than an unrelated utility that developers have to manually bolt onto login.

---

# 11. Verification Resend Is Also Security-Sensitive

Resending a verification email might appear trivial.

It is not.

Beaver-Auth deliberately requires the caller to prove account ownership with the correct password before revealing that the account is pending verification or sending another verification message.

The ordering is:

```text
Email + Password
       │
       ▼
Find user
       │
       ▼
Verify password
       │
       ├── invalid → generic failure
       │
       ▼
Check verification status
       │
       ├── already verified
       │
       └── pending
              │
              ▼
       VerificationEngine
              │
              ▼
       Create + dispatch token
```

This prevents the resend endpoint from becoming an independent account-enumeration or email-spam side channel.

---

# 12. Response Timing Is Part of the Workflow

Several authentication operations use a response floor.

The purpose is to prevent obviously different processing times from unnecessarily revealing information about the authentication state.

For example, login uses a configured response floor while handling invalid credentials, successful authentication, MFA challenges, and system errors.

Conceptually:

```text
Authentication operation
        │
        ▼
Actual processing time
        │
        ▼
Compare against response floor
        │
        ├── already long enough
        │
        └── too short
                │
                ▼
             wait
                │
                ▼
          return result
```

The goal is not to make every request take exactly the same amount of time.

The goal is to establish a minimum response duration for relevant authentication paths.

---

# 13. Errors Have Two Destinations

Beaver-Auth separates the result returned to the application from the error information available for observability.

An engine can return a controlled result such as:

```ts
{
  status: 'system-error',
  message: 'An unexpected internal core auth engine processing exception was securely handled.'
}
```

while the underlying error is passed to `onSystemError`.

By default, Beaver-Auth uses `console.error`, but applications can provide their own handler.

```ts
const auth = createBeaverAuth({
	adapter,

	onSystemError(error) {
		logger.error(error)
	},
})
```

This creates a useful boundary:

```text
Internal failure
      │
      ├──────────────► onSystemError()
      │                    │
      │                    ▼
      │                 Logging
      │                 Monitoring
      │                 Alerting
      │
      ▼
Safe application result
```

The authentication API therefore does not require your observability system to be Beaver-Auth-specific.

---

# 14. Asynchronous Work Is Dispatched

Some authentication operations should not block the request lifecycle unnecessarily.

Verification and password-reset workflows use a `TaskDispatcher` abstraction for this purpose.

The architecture is:

```text
Authentication Engine
        │
        ▼
Create security artifact
        │
        ▼
TaskDispatcher
        │
        ▼
Hook
        │
        ▼
Your application
        │
        └── email / notification / external action
```

The default dispatcher is local, but developers can provide their own dispatcher.

This means the authentication workflow does not have to know whether the application uses:

- an in-process queue,
- a worker,
- a message broker,
- a cloud queue,
- or another background execution mechanism.

The engine only knows that a task can be dispatched.

---

# 15. Rate Limiting Stays Outside the Authentication Workflow

Beaver-Auth provides rate-limiting engines, but the factory does not silently insert them into registration, login, or password-reset operations.

Instead, configured rate limiters are returned to the application:

```ts
const auth = createBeaverAuth({
	adapter,

	rateLimiters: {
		login: {
			// configuration
		},
	},
})
```

The application then decides where and how to apply the limiter.

Conceptually:

```text
Request
   │
   ▼
Rate-limit guard
   │
   ├── rejected
   │
   └── allowed
          │
          ▼
      Auth engine
```

This is deliberate.

The correct rate-limit identifier is application- and threat-model-dependent.

For example, a system may need to rate-limit based on:

```text
IP
Email
User ID
IP + Email
Other application-specific identity
```

Beaver-Auth therefore provides the mechanism without pretending it can know the correct policy for every application.

---

# 16. The Factory Is a Dependency Graph

The factory is best understood as a composition root.

It does not implement authentication itself.

It constructs the objects that implement authentication and connects their dependencies.

For example:

```text
                         createBeaverAuth()
                                │
             ┌──────────────────┼──────────────────┐
             │                  │                  │
             ▼                  ▼                  ▼
      SessionManager      VerificationEngine    OAuthEngine
             │                  │
             │                  ▼
             │             TaskDispatcher
             │
             ├───────────────┐
             │               │
             ▼               ▼
       LoginEngine     MiddlewareEngine
             │
             ├── CryptoEngine
             ├── TokenEngine
             ├── RefreshTokenEngine
             ├── ValidationEngine
             └── VerificationEngine

      RegistrationEngine
             │
             ├── CryptoEngine
             ├── ValidationEngine
             └── VerificationEngine
```

This is why the factory is valuable.

It removes repetitive dependency wiring without removing the underlying architecture.

---

# 17. What Beaver-Auth Does Not Own

A useful way to understand Beaver-Auth is to look at what remains outside it.

```text
                    Your Application
┌─────────────────────────────────────────────────────┐
│                                                     │
│  HTTP framework                                     │
│  Routes                                             │
│  Controllers / handlers                             │
│  Database                                           │
│  ORM / query builder                                │
│  Email provider                                     │
│  Queue infrastructure                               │
│  Logging / monitoring                               │
│  Environment configuration                          │
│                                                     │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
                 ┌─────────────┐
                 │ Beaver-Auth │
                 │             │
                 │ Workflows   │
                 │ Security    │
                 │ State       │
                 │ Tokens      │
                 │ Sessions    │
                 │ Validation  │
                 └─────────────┘
```

This boundary is fundamental to the design.

Beaver-Auth handles the security-sensitive workflow logic.

Your application remains in control of the infrastructure surrounding that logic.

---

# 18. The Mental Model

If you remember only one thing about Beaver-Auth's architecture, remember this:

```text
              APPLICATION
                   │
                   ▼
             AUTH ENGINE
                   │
          ┌────────┼────────┐
          ▼        ▼        ▼
       Validate  Secure   Decide
          │        │        │
          └────────┼────────┘
                   ▼
               ADAPTER
                   │
                   ▼
              YOUR DATA
```

The engines answer:

> **What should happen during an authentication workflow?**

The adapters answer:

> **How does this application access its data?**

The hooks answer:

> **What should happen when Beaver-Auth needs the application to perform an external action?**

The dispatcher answers:

> **How should asynchronous work be executed?**

The application answers:

> **How does all of this connect to my HTTP framework and infrastructure?**

That separation is the foundation of Beaver-Auth.

It is what allows the package to provide a substantial authentication system without requiring your application to surrender ownership of its architecture.
