# Contributing to beaver-auth

Thanks for considering a contribution — Beaver-Auth is a TypeScript auth package built on Node's built-in crypto (no third-party cryptographic dependencies), and it stays useful only if the community around it keeps it honest. Bug reports, design pushback, docs fixes, and new adapters are all genuinely welcome.

Because this package handles authentication, a slightly higher bar applies here than on a typical open-source project — see [Security-sensitive contributions](#security-sensitive-contributions) below before you start on anything touching crypto, tokens, or sessions.

## Getting started

```bash
git clone https://github.com/jon-ozo/beaver-auth.git
cd beaver-auth
npm install -g pnpm   # if you don't already have it
pnpm install
```

This is a pnpm workspace. The core package lives at `packages/core`.

### Running tests

```bash
pnpm test          # run the full suite once
pnpm test:watch    # watch mode
```

Tests live in `apps/test-app/` and run against source via a Vitest alias (`@beaver-auth/core` → `packages/core/index.ts`), so you don't need to build before testing.

### Verifying the actual build

The test suite aliases to source, which means it won't catch packaging issues. Before opening a PR that touches build config, exports, or `index.ts`, also run:

```bash
pnpm --filter @beaver-auth/core run build
node scripts/build-smoke-test.mjs
```

This runs a real end-to-end flow against the built `dist/` output — the thing an actual npm-installed consumer gets — not the source alias.

### Typechecking

```bash
cd packages/core
npx tsc --noEmit -p tsconfig.json
```

CI runs this, tests, and the build on every PR. All three need to be green before merge.

## Before you open a PR

1. **Search existing issues first.** If you're fixing a bug, check whether it's already reported or being worked on.
2. **For anything nontrivial, open an issue before the PR.** A quick description of the problem and your proposed approach saves everyone time if the direction needs to change — especially for anything touching the token/session/crypto layers, where a fix in one place often has ripple effects (see the design notes below).
3. **One logical change per PR.** A PR that fixes a bug and reformats unrelated files is hard to review and hard to revert if something's wrong.

## What makes a good PR here

- **Tests for anything behavioral.** If you fix a bug, add a test that would have failed before your fix and passes after. If you add a feature, cover the happy path and at least one realistic failure path (validation error, adapter throwing, etc.).
- **Match the existing patterns rather than introducing new ones.** A few conventions worth knowing before you write code:
  - Every engine takes an optional `onSystemError` callback (defaulting to `console.error`) for unexpected failures — never let an engine swallow an error silently or throw raw past its public boundary.
  - Optional dependencies follow "presence = opt-in" — e.g. `RegistrationEngine` only requires email verification if you pass it a `VerificationEngine`; there's no separate boolean flag that could drift out of sync with it.
  - Enumeration-sensitive endpoints (registration, login, password reset) return the _same response shape_ regardless of whether an account exists, and are held to a minimum response floor (`responseFloorMs`) so timing doesn't leak it either. If you touch one of these flows, both properties need to hold for every new branch you add.
  - Tokens (sessions, refresh tokens, verification tokens, MFA challenge tokens) are always stored **hashed**, never in plaintext, and looked up by hash. The raw value only ever exists in memory long enough to hand back to the caller.
- **Update types alongside behavior.** `types.ts` is the single source of truth for public result shapes — if you add a new outcome to a flow, add the variant there, not a locally-declared duplicate elsewhere in the file that touches it.
- **Small, focused diffs beat sweeping refactors.** If you spot something worth refactoring while working on something else, mention it in a comment or a separate issue rather than folding it into an unrelated PR.

## Security-sensitive contributions

If your change touches password hashing, token generation/verification, session handling, MFA, or OAuth:

- Explain _why_ the change is safe, not just what it does, in the PR description. "This still prevents timing-based enumeration because X" is the kind of note that speeds up review a lot.
- Expect more scrutiny and more back-and-forth than a typical PR. This isn't personal — it's the nature of the code.
- **Do not include real secrets, tokens, or credentials in test fixtures**, even fake-looking ones that resemble a real format too closely.
- If you believe you've found a security vulnerability (as opposed to a regular bug), please **do not open a public issue**. See [SECURITY.md](./SECURITY.md) for how to report it privately instead.

## Adding a new adapter implementation

beaver-auth is backend-agnostic by design — the engines only ever talk to the `AuthRepoAdapter` / `AuthSessionAdapter` interfaces in `types.ts`. If you build and want to contribute an adapter (Postgres, MongoDB, Prisma, etc.):

- It doesn't need to live in this repo — a separate, linked repository is completely fine and often preferable, since it lets the adapter version independently of core.
- If you do want it included here, open an issue first to discuss where it should live in the workspace.
- Whichever way you go, please implement every method in both interfaces — a partial adapter is a footgun for whoever installs it. `apps/test-app/support/mock-adapter.ts` is a complete in-memory reference implementation worth reading before you start.

## Reporting bugs

Please include:

- beaver-auth version
- Node version
- A minimal reproduction — even a rough one-file script is far more useful than a description of the symptom
- What you expected vs. what happened

## Code style

- TypeScript, strict mode. `noUnusedLocals`/`noUnusedParameters` are on — an unused import or parameter will fail the build, not just lint.
- Tabs for indentation, matching the existing files.
- No new runtime dependencies without discussion first — the zero-third-party-crypto-dependency stance is a deliberate design choice, not an oversight, and extends to a general bias against adding dependencies anywhere in the package.

## Questions

Open a [Discussion](../../discussions) or a regular issue tagged `question`. There's no such thing as a bad question about the auth flows — the whole design has been intentionally over-explained in code comments for exactly this reason.

Thanks again for taking the time to contribute.
