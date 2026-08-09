# Architecture

Beaver-Auth is designed around a simple architectural boundary:

> **Beaver-Auth owns authentication logic. Your application owns infrastructure.**

Your application owns the database, framework, HTTP layer, email provider, queues, logging infrastructure, and other external concerns.

Beaver-Auth owns the security-sensitive workflows that sit between those systems.

This separation is what allows Beaver-Auth to reduce the implementation burden of authentication without forcing your application into a particular framework, ORM, database, or infrastructure provider.

---

## The Architectural Model

At a high level, Beaver-Auth sits between your application and the infrastructure it depends on:

```text
┌─────────────────────────────────────────────────────────────┐
│                         Your Application                    │
│                                                             │
│  Express / Fastify / NestJS / Hono / Next.js / etc.        │
│                                                             │
│  Route handlers · Controllers · Middleware · Services      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ Beaver-Auth API
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                         Beaver-Auth                         │
│                                                             │
│  RegistrationEngine     LoginEngine      SessionManager    │
│  VerificationEngine     PasswordReset    MfaEngine         │
│  OAuthEngine             TokenEngine     CryptoEngine      │
│  RateLimiterEngine       Middleware      Validation        │
│                                                             │
│              Authentication & Security Logic                │
└──────────────────────────────┬──────────────────────────────┘
                               │
                    Developer-defined adapters
                    and application callbacks
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
┌────────────────────┐ ┌──────────────┐ ┌────────────────────┐
│      Database      │ │ Email / Queue│ │ Application Infra  │
│                    │ │              │ │                    │
│ Prisma             │ │ Resend       │ │ Logging            │
│ Drizzle            │ │ SES          │ │ Monitoring         │
│ PostgreSQL         │ │ SendGrid     │ │ HTTP framework     │
│ MongoDB            │ │ Custom queue │ │ etc.               │
└────────────────────┘ └──────────────┘ └────────────────────┘
```

Beaver-Auth does not need to know what infrastructure exists on the other side of its boundaries.

It needs to know **what it can ask that infrastructure to do**.

That is the purpose of its adapters and hooks.

---

# The Core Boundary

The most important architectural decision in Beaver-Auth is the separation between **authentication logic** and **infrastructure implementation**.

For example, a login flow needs to find a user.

Beaver-Auth does not implement:

```ts
prisma.user.findUnique(...)
```

or:

```ts
db.query.users.findFirst(...)
```

Instead, the authentication engine works through the adapter contract:

```ts
const user = await adapter.findUserByEmail(email)
```

Your application provides the implementation.

This means Beaver-Auth can perform the security-sensitive part of authentication without owning your persistence technology.

The same principle applies to sessions, verification, password recovery, and other infrastructure boundaries.

---

# Engines: Where Authentication Logic Lives

Beaver-Auth organizes its functionality into focused engines.

The public package exports the individual engines directly:

```ts
import {
	RegistrationEngine,
	LoginEngine,
	VerificationEngine,
	PasswordResetEngine,
	SessionManager,
	MfaEngine,
	OAuthEngine,
	TokenEngine,
	CryptoEngine,
	ValidationEngine,
	RateLimiterEngine,
} from 'beaver-auth'
```

Each engine owns a particular area of the authentication system.

| Engine                 | Responsibility                                                 |
| ---------------------- | -------------------------------------------------------------- |
| `RegistrationEngine`   | User registration and verification-aware registration          |
| `LoginEngine`          | Credential authentication and authentication-stage transitions |
| `VerificationEngine`   | Email-verification token lifecycle                             |
| `PasswordResetEngine`  | Account recovery / password-reset lifecycle                    |
| `SessionManager`       | Server-side session lifecycle                                  |
| `MfaEngine`            | Multi-factor authentication operations                         |
| `OAuthEngine`          | OAuth functionality                                            |
| `TokenEngine`          | Token creation and consumption                                 |
| `RefreshTokenEngine`   | Refresh-token lifecycle                                        |
| `CryptoEngine`         | Cryptographic operations                                       |
| `ValidationEngine`     | Input validation and normalization                             |
| `RateLimiterEngine`    | Rate-limiting behaviour                                        |
| `AuthMiddlewareEngine` | Authentication middleware operations                           |

The engines are deliberately separate.

This gives Beaver-Auth two important properties:

- developers can use the complete authentication system without manually assembling every component;
- developers who need more control can construct individual engines themselves.

---

# Two Ways to Work With Beaver-Auth

Beaver-Auth intentionally supports two entry points.

## 1. Manual Composition

Every major engine is exported from the package.

You can construct and wire the components yourself:

```ts
import { RegistrationEngine, LoginEngine, SessionManager } from 'beaver-auth'

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

Manual composition is useful when you want complete control over the dependency graph.

For example, you may want:

- different configuration between engines;
- different error handlers;
- only a subset of Beaver-Auth;
- engines created at different points in your application;
- custom dependency wiring.

The public exports are therefore not merely implementation details.

They are part of the API.

---

# 2. Factory Composition

For most applications, manually constructing the entire dependency graph is unnecessary.

Beaver-Auth provides:

```ts
createBeaverAuth()
```

The factory constructs and wires the authentication system in one call.

```ts
import { createBeaverAuth } from 'beaver-auth'

const auth = createBeaverAuth({
	adapter,
})
```

The returned object provides the configured engines:

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

The factory therefore acts as a **composition root**.

It is responsible for constructing the objects and connecting their dependencies.

It does not replace the engines.

---

# Optional Features Are Opt-In

The factory follows a consistent architectural rule:

> **Presence enables a capability.**

For example, verification is enabled by providing the `verification` configuration:

```ts
const auth = createBeaverAuth({
	adapter,

	verification: {
		hooks: {
			onVerificationRequired: async (payload) => {
				// send verification email
			},
		},
	},
})
```

Without that configuration:

```ts
auth.verification
```

is not constructed.

The same pattern is used for:

- email verification;
- password recovery;
- authentication middleware;
- registration rate limiting;
- login rate limiting;
- password-reset rate limiting.

This keeps the default authentication graph small while allowing the factory to construct a complete system when required.

---

# The Factory as a Dependency Graph

The factory is valuable because authentication components are not independent objects.

Some engines depend on other engines.

For example:

```text
                         createBeaverAuth()
                                │
             ┌──────────────────┼──────────────────┐
             │                  │                  │
             ▼                  ▼                  ▼
       SessionManager     VerificationEngine    OAuthEngine
             │                  │
             │                  │
             ▼                  ▼
        LoginEngine      RegistrationEngine
             │
             ▼
        authentication
```

The factory creates these relationships for you.

One particularly important example is verification.

When verification is configured, the factory creates **one `VerificationEngine` instance** and passes that same instance to both:

```text
             VerificationEngine
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
 RegistrationEngine       LoginEngine
          │                   │
          │                   │
   initial verification   resend verification
```

This matters because both operations should participate in the same verification-token lifecycle.

Constructing separate verification engines manually could unintentionally produce separate internal state or token-storage relationships.

The factory removes that wiring responsibility.

---

# Shared Configuration and Observability

The factory also establishes shared infrastructure configuration.

One important example is:

```ts
onSystemError
```

You can provide a single error handler:

```ts
const auth = createBeaverAuth({
	adapter,

	onSystemError: (error) => {
		logger.error(error)
	},
})
```

That handler becomes the shared default for the engines constructed by the factory.

This creates a single observability boundary for Beaver-Auth:

```text
                     onSystemError
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
     Registration       Login          Verification
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                     Your logger
```

Beaver-Auth therefore does not require you to adopt a particular logging or monitoring system.

You decide what happens when the callback is invoked.

Individual sub-configurations can still override the shared handler where required.

---

# Adapters: Infrastructure at the Boundary

Beaver-Auth deliberately avoids owning your database models.

Instead, application infrastructure implements the adapter contracts.

Conceptually:

```text
Beaver-Auth

    "Find this user"
          │
          ▼
    AuthRepoAdapter
          │
          ▼
┌─────────────────────────┐
│ Your implementation     │
│                         │
│ Prisma / Drizzle / SQL  │
│ MongoDB / etc.          │
└─────────────────────────┘
```

This is an important distinction.

Beaver-Auth is not an ORM abstraction.

It does not attempt to hide your database technology behind a second database API.

It defines the **small set of persistence operations authentication requires**.

Your application translates those operations into whatever persistence technology it already uses.

This keeps the authentication engine independent from the persistence implementation.

---

# Hooks: Infrastructure Beyond Persistence

Adapters are primarily concerned with application data.

Hooks handle events where Beaver-Auth needs your application to perform an external operation.

For example, verification can produce a hook payload that your application uses to send an email.

```text
Beaver-Auth
     │
     │ verification required
     ▼
VerificationEngine
     │
     ▼
TaskDispatcher
     │
     ▼
VerificationHook
     │
     ▼
Your email infrastructure
```

Beaver-Auth creates and manages the verification token.

Your application decides how the verification message is actually delivered.

This separation prevents the authentication core from becoming coupled to a particular email provider, queue, or messaging system.

---

# Task Dispatching

Some operations should not block the authentication response path.

Beaver-Auth therefore supports a `TaskDispatcher`.

The factory can provide a shared dispatcher:

```ts
createBeaverAuth({
	adapter,

	dispatcher,

	verification: {
		hooks: {
			onVerificationRequired: async (payload) => {
				// send email
			},
		},
	},
})
```

The dispatcher can then be shared by capabilities that require asynchronous work.

The default implementation is `LocalTaskDispatcher`.

Applications with more sophisticated infrastructure can provide their own `TaskDispatcher`.

This follows the same architectural principle as the database adapter:

> Beaver-Auth defines the contract. The application decides the infrastructure.

---

# Sessions and JWTs

Beaver-Auth separates authentication from the mechanism used to maintain authenticated state.

The authentication process can ultimately result in a server-side session or JWT-based authentication.

Conceptually:

```text
                    Authentication
                          │
                          ▼
                   LoginEngine
                     /       \
                    /         \
                   ▼           ▼
             SessionManager   TokenEngine
                   │           │
                   ▼           ▼
            Server Session     JWT
```

This means the application does not need to rewrite its credential-verification logic simply because it chooses a different authentication-state mechanism.

The security workflow remains inside the authentication engine.

The state mechanism remains a separate concern.

---

# Rate Limiting Is Deliberately Not Automatic

Rate limiting is another important architectural boundary.

The factory can construct independent rate limiters:

```ts
createBeaverAuth({
  adapter,

  rateLimiters: {
    registration: {...},
    login: {...},
    passwordReset: {...},
  },
})
```

But Beaver-Auth does **not** automatically invoke them inside registration, login, or password-reset operations.

Instead, the configured limiter is returned to the application:

```ts
auth.rateLimiters.login
```

and can be used with:

```ts
checkAuthRateLimit(...)
```

This is deliberate.

The correct rate-limit identifier is dependent on the application's threat model.

For example, an application may choose:

```text
IP address
```

or:

```text
email address
```

or:

```text
IP + email
```

or another composite identifier.

Beaver-Auth therefore provides the security mechanism without pretending it knows the application's deployment and threat model.

---

# The HTTP Boundary

Beaver-Auth does not own the application's HTTP framework.

Your route handler remains responsible for receiving the request and producing the response.

Conceptually:

```text
HTTP Request
     │
     ▼
Your Framework
     │
     ▼
Route Handler
     │
     │ Beaver-Auth call
     ▼
Authentication Engine
     │
     ▼
Authentication Result
     │
     ▼
Your Framework
     │
     ▼
HTTP Response
```

`AuthMiddlewareEngine` can be used when middleware-level authentication is appropriate, but it remains an optional component.

This keeps Beaver-Auth's core authentication logic independent from the HTTP framework surrounding it.

---

# Why the Architecture Looks This Way

The architecture is built around one central principle:

> **Beaver-Auth should remove authentication complexity without taking ownership of application infrastructure.**

That leads to several deliberate boundaries.

| Concern                      | Beaver-Auth owns | Application owns |
| ---------------------------- | ---------------- | ---------------- |
| Authentication workflows     | ✓                |                  |
| Password security            | ✓                |                  |
| Token lifecycle              | ✓                |                  |
| Session lifecycle            | ✓                |                  |
| MFA operations               | ✓                |                  |
| Input validation             | ✓                |                  |
| Authentication rate limiting | ✓                |                  |
| Database technology          |                  | ✓                |
| Database models              |                  | ✓                |
| HTTP framework               |                  | ✓                |
| Email provider               |                  | ✓                |
| Queue infrastructure         |                  | ✓                |
| Logging system               |                  | ✓                |
| Application routing          |                  | ✓                |
| Deployment infrastructure    |                  | ✓                |

The result is not an authentication framework that attempts to become your entire backend.

It is a **security-focused application component** that provides the difficult authentication machinery while leaving infrastructure decisions where they belong: in your application.

---

# Architecture in One Picture

Putting the pieces together:

```text
                         YOUR APPLICATION
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Framework / Routes / Controllers / Services                 │
│                                                              │
│              ┌──────────────────────────┐                    │
│              │     Beaver-Auth API      │                    │
│              └────────────┬─────────────┘                    │
└───────────────────────────┼──────────────────────────────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │   Composition Root   │
                 │ createBeaverAuth()   │
                 └──────────┬───────────┘
                            │
          ┌─────────────────┼──────────────────┐
          │                 │                  │
          ▼                 ▼                  ▼
    Registration          Login           SessionManager
          │                 │                  │
          │          ┌──────┴──────┐           │
          │          ▼             ▼           │
          │       Crypto        Token          │
          │          │             │           │
          └──────────┼─────────────┘           │
                     │                         │
          ┌──────────┼───────────┐             │
          ▼          ▼           ▼             ▼
     Verification   MFA      Password       Sessions
                                Reset
          │
          ▼
    TaskDispatcher
          │
          ▼
    Application Hooks

                            │
                            ▼
                  ┌─────────────────────┐
                  │   Adapter Boundary  │
                  └──────────┬──────────┘
                             │
                             ▼
                    Your Infrastructure
                             │
             ┌───────────────┼────────────────┐
             ▼               ▼                ▼
          Database          Email            Logging
       Prisma/Drizzle      Provider        Monitoring
       SQL/etc.            /Queue           etc.
```

And when more control is required, the composition root can be replaced with manual construction:

```text
             Manual Composition
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   LoginEngine   Session     Verification
        │           │           │
        └───────────┼───────────┘
                    │
              Your adapters
                    │
                    ▼
             Your infrastructure
```

**The factory gives you convenience.**

**The individual exports give you control.**

Both are first-class ways of using Beaver-Auth.

The next step is to see an actual authentication workflow. [Authentication Workflow](./first-auth-workflow.md).
