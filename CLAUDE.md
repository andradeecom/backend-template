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
  that the authenticated user id comes from the JWT rather than the request body.
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
- A completed password reset revokes every outstanding refresh token.
- `mustChangePassword` belongs to the admin-created-user flow (temporary password
  emailed via `sendWelcomeEmail`), not to self-registration.
