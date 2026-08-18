# Backend Template — Conventions

NestJS + TypeScript + Prisma. Follow the patterns already in `src/` rather than
introducing new ones.

## Testing

### Spec location: `__specs__/`

Every module keeps its unit specs in a `__specs__/` folder at the module root —
**not** beside the file under test, and **not** mirrored into a top-level
`test/` tree.

```
src/auth/
├── __specs__/
│   ├── auth.service.spec.ts      # tests ../auth.service.ts
│   ├── auth.controller.spec.ts   # tests ../auth.controller.ts
│   └── auth-dto.spec.ts          # tests ../dto/*.dto.ts
├── dto/
├── guards/
├── strategies/
├── auth.controller.ts
├── auth.module.ts
└── auth.service.ts
```

Rules:

- One `__specs__/` per module (`src/auth/__specs__/`, `src/users/__specs__/`, …).
- Name the spec after the file it covers: `auth.service.ts` → `auth.service.spec.ts`.
- Specs for a whole subfolder collapse into one file named after the group:
  all of `dto/` is covered by `auth-dto.spec.ts`.
- Imports reach back out with `../` — `../auth.service`, `../../prisma/prisma.service`.
- E2E specs stay in the root `test/` folder as `*.e2e-spec.ts`; they use a
  separate config (`test/jest-e2e.json`) and are not affected by this layout.

No Jest config change is needed when adding a `__specs__/` folder — `testRegex`
(`.*\.spec\.ts$`) matches on the full path, and `nest build` excludes `*.spec.ts`
from `dist/` automatically.

### Writing specs

- Unit-test services with mocked `PrismaService` and `EmailService`; do not hit a
  real database. Provide them via `Test.createTestingModule` overrides.
- Controller specs mock the service layer entirely and assert HTTP-shaped
  concerns: what the response body contains, which cookies get set/cleared, and
  that the authenticated user id comes from the session rather than the request body.
- DTO specs run `class-validator`'s `validate()` over `plainToInstance` output to
  pin down validation rules (email format, `MinLength`, required fields).
- Assert security properties explicitly, not just happy paths: passwords are
  hashed, only token *hashes* are persisted, expired/used/replayed tokens are
  rejected, and endpoints do not leak whether an account exists.
- Avoid `any` in specs. Reach into mock call arguments through a typed helper
  (see `firstCallArg` in `src/auth/__specs__/auth.service.spec.ts`) so
  `@typescript-eslint/no-unsafe-argument` stays quiet.

### Running

```bash
pnpm test              # all unit specs
pnpm test -- auth      # specs matching a path fragment
pnpm test:cov          # coverage (excludes src/generated/**)
pnpm test:e2e          # e2e specs in test/
```

`@types/jest` is listed explicitly under `compilerOptions.types` in
`tsconfig.json` — pnpm's non-hoisted layout keeps it out of the `node_modules/@types`
directory TypeScript scans by default, so removing it breaks `describe`/`it` in
every spec.

## Auth

- Self-registration (`POST /auth/register`) always assigns the lowest role
  (`STUDENT`). The role is set server-side and `RegisterDto` deliberately has no
  `role` field, so the global `ValidationPipe` (`whitelist: true`) strips any
  client-supplied one. Elevated roles are assigned by an admin via `POST /users`.
- Password-reset and email-verification tokens are random 32-byte values. Only
  their SHA-256 hash is stored; the raw token exists solely in the email link.
- Endpoints that take an email (`forgot-password`, `resend-verification`) return
  an identical response whether or not the account exists, so they cannot be used
  to enumerate users.
- A completed password reset deletes every session for that user; a password
  change deletes every *other* session and re-issues the caller's.

### Sessions

Auth is an opaque, server-backed session — not a JWT. `src/auth/session/`
owns it (`session.service.ts`, `session.constants.ts`).

- The client holds a 32-byte random id in an httpOnly cookie and nothing else.
  It carries no claims, so it is useless to read; all authority is the database
  row it points at. Revocation is a `DELETE`, effective on the next request
  rather than whenever a signed token would have expired.
- Only the SHA-256 hash of the id is stored, so a database leak yields no usable
  sessions.
- The cookie is `__Host-`-prefixed in production (browser-enforced: `Secure`, no
  `Domain`, `Path=/`). That requires HTTPS, so local development falls back to
  the unprefixed `session` name — see `sessionCookieName()`.
- Ids rotate hourly. A rotated-away id is kept as a revoked row, so replaying it
  is detectable: presenting one burns the whole `familyId` and forces re-login.
- Expiry is two-tier — a sliding idle window plus a hard absolute ceiling, so an
  actively-used stolen session still dies.
- `SessionGuard` replaces the old `JwtAuthGuard` and resolves the cookie into
  `req.user`. Routes opt out with `@Public()`.
- CSRF is defended in three layers, all required because the session rides in a
  cookie the browser attaches automatically:
  1. **Double-submit token** (`CsrfGuard`, global). The server sets a *readable*
     `csrf_token` cookie; clients echo it in `X-CSRF-Token` on mutations.
     Readable is safe — it is not a credential, and a cross-site page can cause
     the cookie to be *sent* but cannot read it or set a custom header.
     Compared in constant time. Skipped for callers with no token cookie
     (native mobile attaches its session explicitly and is not CSRF-exposed).
  2. **`SameSite=Lax`** on the session cookie.
  3. **`Sec-Fetch-Site`** (`OriginGuard`, global) — browsers stamp it and a page
     cannot forge it, closing the sibling-subdomain gap SameSite leaves. It
     deliberately rejects `same-site`, not just `cross-site`.
- Rate limiting uses `SessionThrottlerGuard`, which keys on the **session**, not
  the IP. Behind a BFF every browser request is relayed by the frontend server,
  so IP-keyed limits would put all users in one bucket and a few page loads
  would 429 everybody. Anonymous requests still fall back to IP, which is the
  right key for login/reset throttling.
- `TRUST_PROXY` must be `true` when deployed behind a proxy or load balancer, so
  anonymous limits read the real client IP from `X-Forwarded-For` instead of
  bucketing every user under the proxy's address. Keep it `false` when the app is
  directly exposed — otherwise a client can forge that header to reset its own
  bucket and walk past the login and password-reset limits.
- Login always mints a fresh id and never adopts one from the request, which is
  what closes session fixation.
- `mustChangePassword` belongs to the admin-created-user flow (temporary password
  emailed via `sendWelcomeEmail`), not to self-registration.
