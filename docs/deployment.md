# Deployment

Notes for running this API in production. The parts that matter most are the
ones that decide **who the client is** — everything below builds toward making
`req.ip` trustworthy, because anonymous rate limiting keys on it.

## Why client IP matters at all

Most endpoints are protected by the session: the cookie identifies the caller
and `SessionThrottlerGuard` keys the rate limit on the session id, not the
address.

But the endpoints that most need throttling have no session yet, by definition:

- `POST /auth/login`
- `POST /auth/register`
- `POST /auth/forgot-password`
- `POST /auth/resend-verification`

For those, the only identifier available is the network address. That is the
entire reason this app cares about client IP — it is not a session concern, and
would be identical with JWTs or with no auth at all.

Two ways to get it right, and they compose:

1. **Rate limit at the edge** (Cloudflare). Best option: abuse is dropped before
   it costs the origin anything, and the app never needs the client IP.
2. **Rate limit in the app** (the built-in throttler). Requires the app to read
   `X-Forwarded-For`, which requires trusting the proxy — see `TRUSTED_PROXIES`.

## The architecture these notes assume

```
client ──► Cloudflare ──► Hetzner firewall ──► origin (this app)
             │                  │
             │                  └── drops anything not from Cloudflare
             └── terminates TLS, sets CF-Connecting-IP, rate limits /api/auth/*
```

The firewall is not optional decoration. **Every edge protection is bypassable
if the origin is reachable directly** — an attacker who discovers the origin
address skips Cloudflare entirely and forges whatever headers they like. Closing
that path is what makes the rest of this trustworthy.

## Hetzner Cloud Firewall

Hetzner Cloud Firewalls are stateful and filter **before traffic reaches the
server's network interface**, so they hold even if a container publishes a port
it should not have. They cost nothing, support IPv6, and **deny all inbound
traffic by default** — you only add what you want to allow.

Allow inbound `443` (and `80`, if you redirect) **only from Cloudflare's ranges**:

- IPv4: <https://www.cloudflare.com/ips-v4>
- IPv6: <https://www.cloudflare.com/ips-v6>

Add SSH separately, scoped to your own address or a bastion — never `0.0.0.0/0`.

Two practical notes:

- **The ranges change.** Refresh them from the URLs above with a scheduled job
  or Terraform/OpenTofu rather than pasting once and forgetting. A stale list
  fails closed — legitimate traffic starts 5xx-ing — which is noisy but safe.
- **Rules sharing a source prefix are merged** into one effective rule; the
  limit is 500 effective rules per firewall, so the ~22 Cloudflare ranges are a
  non-issue.

For a belt-and-braces layer that needs no list maintenance, enable
[authenticated origin pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/):
the origin then requires a client certificate only Cloudflare holds.

## Cloudflare

### Rate limiting

Put the anonymous limits here rather than in Node. Cloudflare terminates TLS, so
it sees the true client address and cannot be fooled by a forged header.

A rule covering the unauthenticated auth endpoints, for example:

```
(http.request.uri.path in {"/api/auth/login" "/api/auth/register"
                           "/api/auth/forgot-password"
                           "/api/auth/resend-verification"})
```

with something like 10 requests per minute per IP, action `Block`.

**The Free plan allows one rate limiting rule, and can only track by IP.** One
rule with a path expression like the above covers the whole auth surface, which
is enough — but it is the only one you get, so spend it here. Pro raises it to
2, Business to 5.

### Client IP headers

Cloudflare sets `CF-Connecting-IP` to the address that connected to its edge.
It **appends** to `X-Forwarded-For` rather than replacing it, which is why the
right-most entries are the trustworthy ones and the left-most is whatever the
caller typed. (`True-Client-IP` is the same value under a different name, and is
Enterprise-only — do not build on it.)

This app reads `req.ip`, which Express derives from `X-Forwarded-For` according
to `TRUSTED_PROXIES`. Never parse that header by hand.

## `TRUSTED_PROXIES`

Decides which upstream proxies may be believed about the client's IP.

**Leave it empty when the app is exposed directly** — the header is then ignored
entirely and `req.ip` is the raw socket address. That is the safe default, and
it stays correct indefinitely if rate limiting lives at the edge.

Set it only when this app genuinely sits behind a proxy *and* you want the app's
own throttler to see real client addresses. Two accepted forms:

| Value | Meaning |
| --- | --- |
| `"173.245.48.0/20,103.21.244.0/22,…"` | CIDR/IP allow-list — **preferred** |
| `"loopback"`, `"linklocal"`, `"uniquelocal"` | Named ranges |
| `"1"` | Hop count |
| `true` | **Not supported** — see below |

Behaviour measured against Express 5, with a client forging two entries
(`X-Forwarded-For: evil-1, evil-2, 10.0.0.7`, where only `10.0.0.7` was appended
by a real proxy):

| Setting | `req.ip` |
| --- | --- |
| unset | socket address — header ignored |
| `"10.0.0.0/8"` / `"loopback"` | `10.0.0.7` ✓ |
| `"1"` | `10.0.0.7` ✓ |
| `true` | `evil-1` ← **attacker's value** |

Express walks the chain right-to-left and stops at the first untrusted address.
`true` trusts everything, so it lands on the left-most, client-supplied entry —
handing an attacker a fresh rate-limit bucket per request and defeating the
login and password-reset limits entirely. The app rejects it for that reason.

**Prefer the CIDR allow-list over a hop count.** A CIDR list pins trust to
addresses, so an extra or missing hop cannot shift which entry is believed. A
hop count is only correct while *every* request traverses exactly that many
proxies — if any path reaches the app with fewer, a client can pad the header
and be believed. Behind Cloudflare, the allow-list is Cloudflare's published
ranges: the same list as the firewall rule, kept in sync by the same job.

A startup warning fires when `X-Forwarded-For` arrives while `TRUSTED_PROXIES`
is unset. That is the silent failure worth catching — every anonymous caller
buckets under the proxy's address and the limits fire far too early.

## Application environment

Beyond `TRUSTED_PROXIES`, in production:

| Variable | Notes |
| --- | --- |
| `NODE_ENV=production` | Switches the session cookie to the `__Host-` prefix, which requires HTTPS |
| `DATABASE_URL` | Postgres connection string |
| `FRONTEND_URL` | Always allowed as a CORS origin; also used for email links |
| `ALLOWED_ORIGINS` | Comma-separated extra credentialed origins |

There are no JWT signing secrets to manage: sessions are random ids stored in
the database, so revoking one is a `DELETE` rather than a key rotation.

**TLS must terminate somewhere in front of the app.** The production session
cookie is `__Host-`-prefixed, a browser-enforced contract requiring `Secure`,
no `Domain`, and `Path=/`. Over plain HTTP the browser rejects the cookie
outright and nobody can log in.

## Checklist

- [ ] Hetzner firewall: inbound 443 (and 80) restricted to Cloudflare ranges
- [ ] Hetzner firewall: SSH scoped to a known address, not `0.0.0.0/0`
- [ ] A job refreshes the Cloudflare ranges on a schedule
- [ ] Cloudflare rate limiting rule covering `/api/auth/*` unauthenticated routes
- [ ] Verified the origin is *not* reachable directly (`curl` its IP — expect a timeout)
- [ ] `NODE_ENV=production` and TLS terminating in front of the app
- [ ] `TRUSTED_PROXIES` empty, or set to the Cloudflare ranges — never `true`
- [ ] Startup logs show no `X-Forwarded-For received but TRUSTED_PROXIES is unset` warning
