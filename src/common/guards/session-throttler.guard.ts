import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import * as crypto from 'crypto';
import { sessionCookieName } from '../../auth/session/session.constants';

/**
 * Rate-limits per session rather than per IP.
 *
 * The default tracker keys on `req.ip`, which breaks behind a
 * backend-for-frontend: every browser request is relayed by the Next.js server,
 * so all users share that one address and therefore one bucket — a handful of
 * page loads exhausts the limit for everybody.
 *
 * Authenticated requests are keyed by the session id instead, giving each user
 * their own allowance. Anonymous requests still fall back to IP, which is the
 * right key for login and password-reset throttling.
 */
@Injectable()
export class SessionThrottlerGuard extends ThrottlerGuard {
  protected async getTracker(req: Record<string, any>): Promise<string> {
    const cookies = req.cookies as
      Record<string, string | undefined> | undefined;
    const sessionId =
      cookies?.[sessionCookieName(process.env.NODE_ENV === 'production')];

    if (sessionId) {
      // Hashed so raw session ids never reach the throttler's storage keys.
      const digest = crypto
        .createHash('sha256')
        .update(sessionId)
        .digest('hex');
      return `session:${digest}`;
    }

    // `req.ip` is already correct: Express derives it from X-Forwarded-For using
    // the `trust proxy` hop count configured in main.ts, counting from the right
    // of the chain so client-supplied entries are ignored. Parsing the header
    // here instead would take the left-most value — the part an attacker
    // controls — handing them a fresh bucket per request.
    return `ip:${req.ip}`;
  }
}
