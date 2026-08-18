# Authentication

The client holds one thing: an opaque session id in an httpOnly cookie. It
carries no claims, so reading it reveals nothing, and all authority lives in the
database row it points at.

- **Cookie**: `__Host-session` in production — a browser-enforced contract that
  the cookie is `Secure`, has no `Domain`, and uses `Path=/`, pinning it to the
  exact host. That requires HTTPS, so development falls back to `session`.
- **Storage**: only the SHA-256 hash of the id is persisted, so a database leak
  yields no usable sessions.
- **Rotation**: ids rotate hourly. The rotated-away row is kept and marked
  revoked rather than deleted, so replaying an old id is detectable and burns
  the whole rotation family.
- **Expiry**: two-tier — a sliding idle window plus a hard absolute ceiling, so
  an actively-used stolen session still dies.
- **Revocation**: logout deletes the row. A password reset deletes every session
  for the user; a password change deletes every *other* session and re-issues
  the caller's.

## CSRF

Because the session rides in a cookie the browser attaches automatically, three
independent layers guard state-changing requests:

1. **Double-submit token** — the server sets a *readable* `csrf_token` cookie and
   requires it echoed in `X-CSRF-Token`. Readable is deliberate: it is not a
   credential, and while a cross-site page can cause the cookie to be *sent*, it
   can neither read it nor set a custom header.
2. **`SameSite=Lax`** on the session cookie — see below for why not `Strict`.
3. **`Sec-Fetch-Site`** — stamped by the browser and unforgeable by a page. This
   layer rejects `same-site` as well as `cross-site`, closing the sibling
   subdomain gap that `SameSite` leaves open.

Native clients attach their session explicitly rather than having it sent
ambiently, so they are not CSRF-exposed and are not asked for a token.

### Why `Lax` and not `Strict`

`Strict` withholds the cookie on *every* cross-site request, including top-level
navigations the user makes deliberately. Someone following a link to this app
from an email, a chat message, or a search result would arrive without their
session and be bounced to login despite being signed in — which reads as the app
logging people out at random. The emailed verification and password-reset links
this API sends are exactly that case.

The extra protection `Strict` buys is narrow, because `Lax` already withholds
the cookie on cross-site POSTs and on background subrequests. What it permits is
cross-site top-level **GET** navigations — so the residual risk is confined to
GETs that change state, and **GET requests must never mutate data**. The CSRF
token and the `Sec-Fetch-Site` check both cover what remains.

## Rate limiting

Keyed by **session**, not IP. Behind a backend-for-frontend every browser
request is relayed by the frontend server, so IP-keyed limits would put all
users in one bucket. Anonymous requests fall back to IP, which is the right key
for login and password-reset throttling.
