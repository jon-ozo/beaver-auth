# Beaver-Auth

### Production-grade authentication workflows without building the security architecture yourself.

Beaver-Auth is a framework-agnostic authentication engine for JavaScript and Node.js applications.

It provides the security workflows that are difficult, repetitive, and easy to get subtly wrong—while leaving your application's architecture, database, framework, and infrastructure under your control.

**You bring the architecture. Beaver-Auth brings the authentication system.**

---

## The Problem

Authentication is rarely difficult because of `bcrypt.hash()` or creating a login endpoint.

The difficulty is everything around them.

A production authentication system has to coordinate:

* password handling
* validation
* account enumeration protection
* email verification
* token lifecycle
* sessions
* refresh tokens
* multi-factor authentication
* rate limiting
* account recovery
* OAuth
* retries and asynchronous work
* database transactions
* security-sensitive error handling
* timing behavior
* persistence boundaries

And these concerns don't exist independently.

A seemingly simple registration flow can become:

```text
Validate
   ↓
Find existing account
   ↓
Protect against enumeration
   ↓
Hash credentials
   ↓
Create account
   ↓
Create verification token
   ↓
Dispatch verification workflow
   ↓
Handle retries
   ↓
Handle failures
   ↓
Maintain a consistent response
```

The problem isn't that developers can't implement these things.

**The problem is that they shouldn't have to repeatedly design and maintain this security architecture for every application.**

---

# What Beaver-Auth Does

Beaver-Auth provides the authentication workflows while allowing your application to retain ownership of everything around them.

```text
┌─────────────────────────────────────────────┐
│                 Your Application             │
│                                             │
│  Framework    Database    Infrastructure    │
│     │             │              │           │
│     └─────────────┼──────────────┘           │
│                   │                          │
│            Your Adapters / Hooks             │
└───────────────────┼─────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│                 Beaver-Auth                 │
│                                             │
│  Registration   Login   Sessions   Tokens   │
│  Verification   MFA     Recovery   OAuth   │
│  Crypto         Validation   Rate Limits   │
│  Security Workflows & Policies              │
└─────────────────────────────────────────────┘
```

Beaver-Auth deliberately stops at the application boundary.

It does **not** require you to adopt:

* a particular web framework
* a particular ORM
* a particular database
* a particular application architecture
* a particular infrastructure provider

Your application owns those decisions.

Beaver-Auth owns the authentication workflows.

---

# Why This Is Different

Framework agnosticism is useful, but it isn't the main value.

Clean Architecture already gives applications a way to isolate framework-specific infrastructure.

The harder problem is **implementing the security workflows correctly inside that architecture.**

Beaver-Auth is designed to reduce that implementation burden.

Instead of repeatedly building:

```text
Controller
    ↓
Validation
    ↓
Authentication policy
    ↓
Credential handling
    ↓
Token management
    ↓
Session management
    ↓
MFA
    ↓
Persistence
    ↓
Background work
    ↓
Security/error handling
```

you configure the boundaries and let Beaver-Auth execute the workflow.

---

# Your Architecture Stays Yours

Beaver-Auth does not own your database model.

It does not own your HTTP layer.

It does not decide how your application is structured.

Instead, it communicates with your application through explicit boundaries.

For example:

```ts
const auth = new RegistrationEngine({
  adapter: {
    findUserByEmail,
    createUser,
    // ...
  },

  requireVerification: verification,
})
```

Your persistence implementation remains yours.

```ts
const findUserByEmail = async (email: string) => {
  return db.user.findUnique({
    where: { email },
  })
}
```

If the application later moves from Prisma to Drizzle, the authentication workflow does not need to be redesigned.

The adapter implementation changes.

The authentication policy does not.

That distinction is important.

---

# Start in Minutes

Install Beaver-Auth:

```bash
npm install beaver-auth
```

or 

```bash
pnpm add beaver-auth
```

or

```bash
yarn add beaver-auth
```

Then choose how you want to initialize it.

---

### Direct imports

Use the engines directly when you want explicit control over composition.

```ts
import {
  RegistrationEngine,
  LoginEngine,
} from "beaver-auth"
```

### Factory API

Use the factory when you want Beaver-Auth to provide the application-level composition for you.

```ts
import { createAuth } from "beaver-auth"

const auth = createAuth({
  // configuration
})
```

Both approaches use the same underlying authentication capabilities.

---

# Registration

A registration workflow can include account enumeration protection, credential hashing, persistence, verification-token creation, and asynchronous verification dispatch.

```ts
const result = await registration.execute({
  email,
  password,
  profile,
})
```

The engine owns the workflow.

Your application owns persistence.

For example, verification can be enabled simply by supplying the verification engine:

```ts
const registration = new RegistrationEngine({
  adapter,
  requireVerification: verification,
})
```

Without it, registration does not require verification.

This keeps the default configuration small while allowing security requirements to become explicit when needed.

---

# Login Is a Workflow, Not a Function

Authentication becomes significantly more complicated once multiple authentication factors and session mechanisms are involved.

Beaver-Auth treats login as a workflow.

Conceptually:

```text
                Login
                  │
                  ▼
             Validate input
                  │
                  ▼
          Find authentication
               subject
                  │
                  ▼
          Verify credentials
                  │
                  ▼
        ┌─────────┴─────────┐
        │                   │
      MFA?                No MFA
        │                   │
        ▼                   ▼
  MFA challenge         Create session
        │
        ▼
   Verify factor
        │
        ▼
   Create session
```

This lets the application deal with the result rather than reconstructing the state machine itself.

---

# Multiple Authentication Mechanisms

Beaver-Auth is designed around authentication workflows rather than a single authentication implementation.

The system can support:

* password authentication
* TOTP
* email verification
* magic links
* account recovery
* OAuth
* session authentication
* JWT-based authentication
* refresh-token flows
* multi-factor authentication

The important part is not simply having these features.

It is having them **coexist within one authentication architecture.**

---

# Sessions and Tokens

Beaver-Auth separates authentication from the mechanism used to maintain authenticated state.

Depending on your application, authentication can result in mechanisms such as:

```text
Authentication
      │
      ├── Session
      │
      └── JWT
            │
            └── Refresh Token
```

For refresh-token authentication, Beaver-Auth can manage token families and reuse detection rather than treating refresh tokens as independent bearer strings.

That distinction matters.

A stolen refresh token should not simply become a permanently renewable credential.

---

# Security Is Part of the Workflow

Security controls are not exposed as an afterthought.

They are incorporated into the engines themselves.

For example, registration can protect against account enumeration:

```ts
const registration = new RegistrationEngine({
  adapter,
  protectAgainstEnumeration: true,
})
```

Timing behavior can also be controlled through a response floor:

```ts
const registration = new RegistrationEngine({
  adapter,
  responseFloorMs: 150,
})
```

The goal is not to make developers configure dozens of security switches.

The goal is to provide sensible security behavior while exposing the controls that genuinely belong to the application.

---

# Your Database. Your ORM.

Beaver-Auth intentionally does not ship with a database model.

Instead, you provide the persistence boundary.

```text
Beaver-Auth
     │
     ▼
AuthRepoAdapter
     │
     ├── Prisma
     ├── Drizzle
     ├── PostgreSQL
     ├── MongoDB
     ├── MySQL
     └── Your own persistence layer
```

This is not a limitation hidden behind marketing.

It is an architectural decision.

Beaver-Auth should not force its internal representation of a user onto your application's data model.

Your application already has one.

Beaver-Auth integrates with it.

---

# Transactions Are Yours Too

Authentication workflows often involve multiple writes.

Beaver-Auth therefore allows the application to provide its own transaction boundary:

```ts
const registration = new RegistrationEngine({
  adapter,

  runInTransaction: async (work) => {
    return db.transaction(async (tx) => {
      return work(createTransactionAdapter(tx))
    })
  },
})
```

Beaver-Auth defines the workflow.

Your database determines how that workflow becomes atomic.

---

# Verification Without Owning Your Email Provider

Beaver-Auth creates and manages verification tokens.

It does not require you to adopt a particular email provider.

Instead, verification dispatches through a hook.

```ts
const verification = new VerificationEngine({
  adapter,

  hooks: {
    async onVerificationRequired(payload) {
      await emailProvider.send({
        to: payload.email,
        token: payload.token,
        expiresAt: payload.expiresAt,
      })
    },
  },
})
```

Your email infrastructure remains yours.

Beaver-Auth handles the security-sensitive token lifecycle.

---

# Background Work and Reliability

Some authentication operations should not block the user's request.

Verification delivery is one example.

Beaver-Auth separates:

```text
Token creation
      ↓
Task dispatch
      ↓
Hook execution
      ↓
Retry / backoff
      ↓
Failure reporting
```

Token creation and hook dispatch have separate retry responsibilities.

This means a temporary email-provider failure does not require the registration request itself to remain open.

---

# System Errors Are Observable

Beaver-Auth does not force developers to use a particular logging or monitoring system.

Engines can accept an `onSystemError` callback:

```ts
const registration = new RegistrationEngine({
  adapter,

  onSystemError(error) {
    logger.error(error)
  },
})
```

This gives applications a clean integration point for:

* application logging
* structured logs
* monitoring
* error tracking
* alerting
* observability platforms

Beaver-Auth handles the authentication failure.

**Your infrastructure decides where that failure goes.**

---

# Zero Runtime Dependencies

Beaver-Auth is intentionally dependency-free.

Cryptographic primitives are built on Node.js's native capabilities rather than relying on third-party authentication packages.

The goal is straightforward:

```text
Your Application
       │
       ▼
 Beaver-Auth
       │
       ▼
Node.js
```

rather than:

```text
Your Application
       │
       ▼
 Beaver-Auth
       │
       ├── package A
       │     ├── package B
       │     └── package C
       │
       ├── package D
       │     └── package E
       │
       └── package F
```

Fewer dependencies do not automatically make software secure.

But they do reduce the amount of third-party code your authentication boundary depends on and the dependency surface you have to maintain.

---

# Designed for Developers Who Want to Build, Not Rebuild Auth

Beaver-Auth is particularly useful when you already understand application architecture but don't want every new product to require rebuilding its authentication subsystem.

You still decide:

* how your application is structured
* how users are persisted
* how HTTP requests are handled
* how sessions are exposed to the application
* which infrastructure you use
* which email provider you use
* which OAuth providers you support
* how your application logs and monitors failures

Beaver-Auth handles the authentication machinery underneath those decisions.

---

# What Beaver-Auth Does Not Try to Do

Beaver-Auth is intentionally not:

* a web framework
* an ORM
* a database abstraction that hides your database
* an email provider
* an SMS provider
* an application-wide authorization framework
* a replacement for your application's architecture

It is an **authentication engine**.

That boundary is deliberate.

---

# Core Capabilities

| Capability                | Beaver-Auth |
| ------------------------- | ----------- |
| Registration              | ✓           |
| Password authentication   | ✓           |
| Email verification        | ✓           |
| Magic links               | ✓           |
| Account recovery          | ✓           |
| Session management        | ✓           |
| JWT authentication        | ✓           |
| Refresh tokens            | ✓           |
| MFA / TOTP                | ✓           |
| OAuth                     | ✓           |
| Rate limiting             | ✓           |
| Cryptographic primitives  | ✓           |
| Framework independent     | ✓           |
| ORM independent           | ✓           |
| Database independent      | ✓           |
| Zero runtime dependencies | ✓           |

---

# The Architectural Idea

The central idea behind Beaver-Auth can be summarized as:

> **Don't outsource your architecture. Outsource the authentication complexity.**

Your application remains the system of record.

Your database remains your database.

Your framework remains your framework.

Your infrastructure remains your infrastructure.

Beaver-Auth sits between those pieces and provides the security workflows that would otherwise have to be designed, implemented, tested, and maintained repeatedly.

```text
                 YOUR APPLICATION

       ┌──────────────────────────────┐
       │       Framework / HTTP       │
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │          Beaver-Auth         │
       │                              │
       │ Registration                 │
       │ Login                        │
       │ Verification                 │
       │ MFA                          │
       │ Sessions                     │
       │ Tokens                       │
       │ Recovery                     │
       │ OAuth                        │
       │ Rate Limiting                │
       └──────────────┬───────────────┘
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
       Database                Services
       Adapter                  Hooks
```

The result is not an authentication framework that takes over your application.

It is an authentication subsystem that fits into the architecture you already have.

---

# Get Started

Start with the [Installation](./docs/installation.md) guide, then follow the [Quick Start](./docs/quick-start.md).

For the architectural model behind Beaver-Auth, see [Core Concepts](./docs/core-concepts.md).

---

## License

MIT
