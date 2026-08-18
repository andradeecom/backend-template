/**
 * Cookie and lifetime constants for the opaque-session auth model.
 *
 * The browser holds exactly one credential: an opaque session id in an
 * httpOnly cookie. It carries no claims, so reading it tells an attacker
 * nothing and it can be revoked instantly by deleting the row.
 */

/**
 * The `__Host-` prefix is a browser-enforced contract: the cookie is rejected
 * unless it is `Secure`, has no `Domain`, and uses `Path=/`. That pins the
 * cookie to this exact host, which is what stops a compromised sibling
 * subdomain from planting a session (`SameSite` cannot — subdomains are the
 * same *site*).
 *
 * The prefix requires HTTPS, so plain-http local development falls back to the
 * unprefixed name. Production must use the prefixed one.
 */
export const SESSION_COOKIE_SECURE = '__Host-session';
export const SESSION_COOKIE_INSECURE = 'session';

export function sessionCookieName(isProduction: boolean): string {
  return isProduction ? SESSION_COOKIE_SECURE : SESSION_COOKIE_INSECURE;
}

/**
 * Idle window. Every authenticated request slides this forward, so an active
 * user is never logged out mid-session while an abandoned session dies.
 */
export const SESSION_IDLE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Hard ceiling regardless of activity. Sliding expiry alone would let a stolen
 * session live forever as long as the thief kept using it.
 */
export const SESSION_ABSOLUTE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * How often an active session id is rotated. Rotation limits the value of a
 * cookie captured off the wire or off disk: it stops working at the next
 * rotation, and if the legitimate client then presents the old id, reuse
 * detection burns the family.
 */
export const SESSION_ROTATION_INTERVAL_MS = 60 * 60 * 1000;

/**
 * The CSRF token cookie is deliberately **not** httpOnly: the frontend has to
 * read it to echo it back in a header. That is safe because the token is not a
 * credential — it proves only that the request came from a page able to read
 * this origin's cookies, which a cross-site attacker cannot do.
 *
 * `__Host-` is used in production for the same host-pinning reason as the
 * session cookie.
 */
export const CSRF_COOKIE_SECURE = '__Host-csrf_token';
export const CSRF_COOKIE_INSECURE = 'csrf_token';

export function csrfCookieName(isProduction: boolean): string {
  return isProduction ? CSRF_COOKIE_SECURE : CSRF_COOKIE_INSECURE;
}

/** Header the client echoes the CSRF token back in. */
export const CSRF_HEADER = 'x-csrf-token';
