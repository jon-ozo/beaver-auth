# Installation

Beaver-Auth is designed to sit inside your application rather than around it.

You install the core package, connect it to your application's persistence layer through an adapter, and then choose how much of the authentication system you want Beaver-Auth to construct for you.

## Install

Install the core package using your package manager:

```bash
npm install @beaver-auth/core
```

```bash
pnpm add @beaver-auth/core
```

```bash
yarn add @beaver-auth/core
```

Beaver-Auth exposes its public API from the package root, so application code does not need to import internal modules.

---

## Two Ways to Start

Beaver-Auth gives you two ways to build your authentication system.

### 1. Use the factory

For most applications, `createBeaverAuth()` is the simplest starting point.

The factory constructs and wires the Beaver-Auth engines into a single authentication object:

```ts
import { createBeaverAuth } from '@beaver-auth/core'

const auth = createBeaverAuth({
	adapter,
})
```

You then work with the capabilities exposed by the returned object:

```ts
auth.registration
auth.login
auth.sessions
```

Optional capabilities can be enabled through the factory configuration:

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

	passwordReset: {
		hooks: {
			onPasswordResetRequired: async (payload) => {
				// send password-reset email
			},
		},
	},

	middleware: {
		jwtSecret: process.env.JWT_SECRET!,
	},
})
```

The factory is particularly useful when you want Beaver-Auth to manage the relationships between its internal engines for you.

For example, when verification is enabled, the same `VerificationEngine` is shared between registration and login.

---

### 2. Construct the engines yourself

The factory is not mandatory.

Every major engine is also exported from the package root:

```ts
import {
	RegistrationEngine,
	LoginEngine,
	SessionManager,
	VerificationEngine,
	PasswordResetEngine,
	MfaEngine,
	OAuthEngine,
	RateLimiterEngine,
	CryptoEngine,
} from '@beaver-auth/core'
```

You can therefore construct only the pieces your application needs:

```ts
const sessions = new SessionManager({
	adapter,
})

const login = new LoginEngine({
	adapter,
	sessions,
})
```

This approach gives you finer control over the dependency graph and lifecycle of individual engines.

Use the **factory** when you want Beaver-Auth to handle the wiring.

Use **direct construction** when you need explicit control over that wiring.

Both approaches use the same underlying Beaver-Auth engines.

---

## What Beaver-Auth Needs From Your Application

Beaver-Auth does not own your application's database or ORM.

Instead, it communicates with your persistence layer through an adapter.

Conceptually:

```text
Your Application
      │
      │
      ▼
┌─────────────────┐
│   Beaver-Auth   │
│                 │
│ Registration    │
│ Login           │
│ Sessions        │
│ Verification    │
│ MFA             │
│ Tokens          │
└────────┬────────┘
         │
         │ Adapter
         ▼
┌─────────────────┐
│ Your Data Layer │
│                 │
│ Prisma          │
│ Drizzle         │
│ PostgreSQL      │
│ MongoDB          │
│ MySQL           │
│ Custom ORM      │
└─────────────────┘
```

The adapter is the boundary between Beaver-Auth's authentication logic and your application's data storage.

This means Beaver-Auth does not require you to replace your existing database or ORM.

Your application remains responsible for implementing the adapter against whatever persistence technology it already uses.

The exact adapter contract is defined by Beaver-Auth's exported types.

---

## Configure Application Logging

Authentication failures and internal processing errors should be observable in production.

Beaver-Auth therefore provides an optional `onSystemError` hook.

If you do nothing, Beaver-Auth falls back to `console.error`:

```ts
const auth = createBeaverAuth({
	adapter,
})
```

If your application already has a logging or observability system, provide it:

```ts
const auth = createBeaverAuth({
	adapter,

	onSystemError(error) {
		logger.error(error)
	},
})
```

The factory uses this handler as the shared error sink for the engines it constructs, while individual engine configurations can still override it when necessary.

This keeps Beaver-Auth independent of any particular logging provider.

---

## Optional Capabilities Are Opt-In

The factory does not construct every possible subsystem automatically.

Optional capabilities are enabled by including their configuration.

For example:

```ts
const auth = createBeaverAuth({
	adapter,

	verification: {
		hooks: {
			onVerificationRequired: async (payload) => {
				// send verification message
			},
		},
	},
})
```

Without the `verification` configuration, no `VerificationEngine` is created.

The same principle applies to:

- password recovery
- authentication middleware
- registration rate limiting
- login rate limiting
- password-reset rate limiting

This keeps the initial configuration proportional to the features your application actually uses.

---

## What Happens After Installation?

Once Beaver-Auth is installed, the next step is connecting your application's data layer through an adapter.

From there, you can either:

**Start with the factory**

```ts
const auth = createBeaverAuth({
	adapter,
})
```

or **construct the individual engines yourself**.

The next guide, [Quick Start](./quick-start.md), takes the first route and walks through a complete authentication flow.

If you want to understand the design before writing the integration code, continue with [Core Concepts](./core-concepts.md).
