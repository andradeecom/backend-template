# Backend Template

NestJS + TypeScript API template with session-based authentication, Prisma, and
Postgres.

Auth is the part worth knowing about: sessions are **opaque and server-backed**
rather than JWTs, so logout, bans, and role changes take effect on the next
request instead of whenever a token happens to expire. See
[docs/authentication.md](docs/authentication.md).

## Requirements

- Node `24.x` (see `.nvmrc`)
- pnpm `11.21.0` (pinned via `packageManager`)
- Docker, for the local Postgres

## Getting started

```bash
pnpm install
cp .env.example .env.dev     # then fill in the blanks — see Environment
pnpm start:dev:db            # starts Postgres in Docker
pnpm db:migrate:dev          # applies migrations
pnpm start:dev
```

The API listens on `http://localhost:3001` with every route under `/api`.
Swagger UI is at `http://localhost:3001/api/docs`.

## Scripts

| Script | What it does |
| --- | --- |
| `pnpm start:dev` | Watch mode, loads `.env.dev` |
| `pnpm start:debug` | Watch mode with the inspector attached |
| `pnpm build` / `pnpm start:prod` | Compile to `dist/`, then run it |
| `pnpm start:dev:db` | Start the local Postgres container |
| `pnpm db:migrate:dev` | Create and apply a migration |
| `pnpm db:push:dev` | Push the schema without a migration (prototyping) |
| `pnpm db:reset:dev` | Drop and recreate the database |
| `pnpm db:generate` | Regenerate the Prisma client |
| `pnpm db:seed` | Run the seed script |
| `pnpm test` / `test:watch` / `test:cov` | Jest |
| `pnpm test:e2e` | End-to-end suite |
| `pnpm lint` / `pnpm format` | ESLint (with `--fix`) / Prettier |

## Environment

Copy `.env.example` and fill it in. Notable entries:

| Variable | Notes |
| --- | --- |
| `DATABASE_URL` | Postgres connection string |
| `FRONTEND_URL` | Always allowed as a CORS origin; also used for email links |
| `ALLOWED_ORIGINS` | Comma-separated extra origins allowed to send credentialed requests |
| `TRUSTED_PROXIES` | Which upstream proxies may be believed about client IP — see [deployment](docs/deployment.md) |
| `RESEND_API_KEY` | Transactional email |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_CALLBACK_URL` | Social login |

There are no JWT signing secrets to manage: sessions are random ids stored in
the database, so revoking one is a `DELETE` rather than a key rotation.

Anonymous rate limiting keys on the client's IP, so behind a proxy the app has
to be told which upstream it may believe about that. `TRUSTED_PROXIES` accepts a
CIDR allow-list or a hop count, and is safe to leave **empty** — the default —
when the app is exposed directly or when rate limiting lives at the edge. See
[docs/deployment.md](docs/deployment.md).

## Authentication

The client holds one thing: an opaque session id in an httpOnly cookie — not a
JWT — so logout, bans, and role changes take effect on the next request rather
than whenever a token happens to expire. Only its SHA-256 hash is stored, ids
rotate hourly with reuse detection, and CSRF is defended in three layers.

Full detail — cookie prefixes, rotation, CSRF layers, why `SameSite` is `Lax`,
and rate limiting — in [docs/authentication.md](docs/authentication.md).

## API

All routes are prefixed with `/api`.

| Method | Route | Notes |
| --- | --- | --- |
| `POST` | `/auth/register` | Always creates the lowest role; the role is never read from the body |
| `POST` | `/auth/login` | Sets the session cookie; returns the user, never a token |
| `POST` | `/auth/logout` | Deletes the session row |
| `POST` | `/auth/logout-all` | Signs out every device |
| `GET` | `/auth/me` | Current user (returned unwrapped) |
| `POST` | `/auth/change-password` | Signs out other devices, keeps the caller in |
| `POST` | `/auth/forgot-password` | Identical response whether or not the account exists |
| `POST` | `/auth/reset-password` | Single-use token; revokes all sessions |
| `POST` | `/auth/verify-email` | |
| `POST` | `/auth/resend-verification` | Identical response whether or not the account exists |
| `GET` | `/auth/google` → `/auth/google/callback` | Web OAuth redirect flow |
| `POST` | `/auth/google/exchange` | Exchanges the single-use code for a session |
| `POST` | `/auth/google/token` | Mobile: verifies a native Google ID token |
| `GET`/`POST`/`PATCH`/`DELETE` | `/users`, `/users/:id` | Admin only |

## Project structure

```
src/
├── auth/
│   ├── session/          SessionService + cookie/lifetime constants
│   ├── strategies/       Google OAuth
│   ├── guards/           SessionGuard
│   ├── dto/
│   └── __specs__/
├── common/
│   ├── guards/           CsrfGuard, OriginGuard, SessionThrottlerGuard, RolesGuard
│   └── decorators/       @CurrentUser, @Roles, @Public
├── users/
├── email/                Resend
└── prisma/
```

Specs live in a `__specs__/` folder inside the module they cover, named after the
file under test.

## Testing

```bash
pnpm test           # unit
pnpm test:cov       # with coverage
pnpm test:e2e       # end-to-end
```

Services are tested against mocked `PrismaService` and `EmailService` rather than
a real database. Specs assert security properties explicitly — that passwords are
hashed, that only token hashes are stored, that replayed and expired credentials
are rejected, and that endpoints do not leak whether an account exists.

## Releasing

The **Bump Version** GitHub Action (`workflow_dispatch`) bumps
`package.json`, syncs the version Swagger reports, then commits, tags, and
pushes. Dispatch it from `main` — it has no branch filter, so it tags whichever
branch you run it against.

## Features

- [x] NestJS + TypeScript
- [x] Opaque server-side sessions (httpOnly cookies, rotation + reuse detection)
- [x] CSRF protection (double-submit token, SameSite, Sec-Fetch-Site)
- [x] Per-session rate limiting
- [x] Prisma ORM + Postgres
- [x] Swagger documentation
- [x] Resend (email service)
- [x] Login with Google (social login)
- [x] Jest + Supertest
- [x] ESLint, Prettier, Husky, lint-staged
- [ ] Login with Apple (social login)

## Contributing

`main` is protected by a branch ruleset: it cannot be force-pushed or deleted,
and changes land through a pull request. Only the **admin** repository role can
bypass that — for everyone else the requirement is absolute, with no bypass
option offered. Owners listed in `.github/CODEOWNERS` are auto-requested for
review on every PR.

```bash
git switch -c feat/short-description
# ...work...
git push -u origin feat/short-description
gh pr create --fill
```

**Branch names** carry the same prefix as the commit type: `feat/`, `fix/`,
`docs/`, `refactor/`, `chore/`.

**Commits** follow [Conventional Commits](https://www.conventionalcommits.org):

```
<type>(<optional scope>): <summary in the imperative mood>

<body explaining *why*, not what the diff already shows>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `perf`.
Append `!` and add a `BREAKING CHANGE:` footer when the change breaks callers —
for example `refactor(auth)!: issue sessions instead of JWTs`.

Split work into commits that each stand on their own rather than one large
commit at the end. Husky runs Prettier and ESLint on staged files, so a commit
that fails linting will not complete.

**Before opening a PR**, run the checks below locally; describe *why* the change
is needed and call out anything that alters behaviour for existing clients.

```bash
pnpm lint
pnpm test
pnpm build
```

## License

MIT — see [LICENSE.md](LICENSE.md).
