import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import type { CookieOptions, Request, Response } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import {
  SESSION_ABSOLUTE_TTL_MS,
  SESSION_IDLE_TTL_MS,
  SESSION_ROTATION_INTERVAL_MS,
  csrfCookieName,
  sessionCookieName,
} from './session.constants';

export interface SessionUser {
  id: string;
  email: string;
  role: string;
  firstName: string;
  lastName: string;
  mustChangePassword: boolean;
}

export interface ResolvedSession {
  user: SessionUser;
  sessionId: string;
}

/**
 * Opaque, server-backed sessions.
 *
 * The id handed to the client is a 256-bit random string that means nothing on
 * its own — all authority lives in the database row it points at. That is the
 * whole point: logout, bans and role changes take effect on the next request
 * instead of whenever a signed token happens to expire.
 */
@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);

  constructor(private readonly prisma: PrismaService) {}

  private get isProduction(): boolean {
    return process.env.NODE_ENV === 'production';
  }

  get cookieName(): string {
    return sessionCookieName(this.isProduction);
  }

  get csrfCookieName(): string {
    return csrfCookieName(this.isProduction);
  }

  /**
   * Issues the double-submit CSRF token.
   *
   * Readable by JavaScript on purpose — the frontend copies it into a request
   * header. A cross-site page can cause the *cookie* to be sent, but cannot
   * read it to set the header, and cannot set custom headers on a forged
   * form post either. That asymmetry is the entire defence.
   */
  writeCsrfCookie(res: Response, maxAgeMs: number): string {
    const token = crypto.randomBytes(32).toString('hex');

    res.cookie(this.csrfCookieName, token, {
      httpOnly: false,
      secure: this.isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: maxAgeMs,
    });

    return token;
  }

  clearCsrfCookie(res: Response): void {
    res.clearCookie(this.csrfCookieName, {
      httpOnly: false,
      secure: this.isProduction,
      sameSite: 'lax',
      path: '/',
    });
  }

  private hash(rawId: string): string {
    return crypto.createHash('sha256').update(rawId).digest('hex');
  }

  /**
   * `__Host-` forbids a `Domain` and requires `Path=/`, so the cookie cannot be
   * narrowed to a single endpoint. That is a deliberate trade: with one opaque
   * session cookie (rather than a separate refresh token) there is no
   * refresh-only endpoint to scope it to, and host-pinning is worth more than
   * path-scoping here.
   */
  cookieOptions(maxAgeMs: number): CookieOptions {
    return {
      httpOnly: true,
      secure: this.isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: maxAgeMs,
    };
  }

  /**
   * Issues a brand-new session. Always called on a fresh login and never reuses
   * an id supplied by the client, which is what closes session fixation.
   */
  async create(
    userId: string,
    req?: Request,
    familyId?: string,
  ): Promise<{ rawId: string; expiresAt: Date; absoluteExpiresAt: Date }> {
    const rawId = crypto.randomBytes(32).toString('hex');
    const now = Date.now();

    const absoluteExpiresAt = new Date(now + SESSION_ABSOLUTE_TTL_MS);
    const expiresAt = new Date(
      Math.min(now + SESSION_IDLE_TTL_MS, absoluteExpiresAt.getTime()),
    );

    await this.prisma.session.create({
      data: {
        tokenHash: this.hash(rawId),
        userId,
        familyId: familyId ?? crypto.randomUUID(),
        expiresAt,
        absoluteExpiresAt,
        userAgent: req?.get('user-agent')?.slice(0, 512) ?? null,
        ipAddress: req?.ip ?? null,
      },
    });

    return { rawId, expiresAt, absoluteExpiresAt };
  }

  /**
   * Rotation with reuse detection.
   *
   * A rotated-away id is kept as a revoked row rather than deleted, so
   * presenting it later is distinguishable from presenting garbage. Two clients
   * holding the same id means one of them is an attacker, and since we cannot
   * tell which, the entire family is burned and everyone re-authenticates.
   */
  private async rotate(
    current: {
      id: string;
      userId: string;
      familyId: string;
      absoluteExpiresAt: Date;
    },
    req: Request,
  ): Promise<{ rawId: string; expiresAt: Date } | null> {
    const rawId = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiresAt = new Date(
      Math.min(now + SESSION_IDLE_TTL_MS, current.absoluteExpiresAt.getTime()),
    );

    try {
      await this.prisma.$transaction([
        this.prisma.session.update({
          where: { id: current.id, revoked: false },
          data: { revoked: true },
        }),
        this.prisma.session.create({
          data: {
            tokenHash: this.hash(rawId),
            userId: current.userId,
            familyId: current.familyId,
            expiresAt,
            absoluteExpiresAt: current.absoluteExpiresAt,
            userAgent: req.get('user-agent')?.slice(0, 512) ?? null,
            ipAddress: req.ip ?? null,
          },
        }),
      ]);
    } catch {
      // A concurrent request won the rotation race. Its new id is already on
      // its way to the client, so this request keeps using the still-valid
      // current id rather than racing it and tripping reuse detection.
      return null;
    }

    return { rawId, expiresAt };
  }

  /**
   * Validates the session cookie and returns the live user, refreshing the
   * idle window and rotating the id when it is old enough.
   *
   * The user row is read on every request by design — that is what makes a
   * ban, a role change or a logout take effect immediately.
   */
  async resolve(req: Request, res?: Response): Promise<ResolvedSession | null> {
    const cookies = req.cookies as Record<string, string | undefined>;
    const rawId = cookies?.[this.cookieName];
    if (!rawId) return null;

    const session = await this.prisma.session.findUnique({
      where: { tokenHash: this.hash(rawId) },
      include: { user: true },
    });

    if (!session) return null;

    if (session.revoked) {
      // This id was already rotated away or explicitly killed, yet someone
      // still holds it. Treat the family as compromised.
      await this.revokeFamily(session.familyId);
      this.logger.warn(
        `Session reuse detected for user ${session.userId}; family ${session.familyId} revoked`,
      );
      return null;
    }

    const now = new Date();
    if (session.expiresAt < now || session.absoluteExpiresAt < now) {
      await this.prisma.session.update({
        where: { id: session.id },
        data: { revoked: true },
      });
      return null;
    }

    if (!session.user.isActive) return null;

    let activeRawId = rawId;
    const rotationDue =
      now.getTime() - session.lastUsedAt.getTime() >=
      SESSION_ROTATION_INTERVAL_MS;

    if (rotationDue && res) {
      const rotated = await this.rotate(session, req);
      if (rotated) {
        activeRawId = rotated.rawId;
        this.writeCookie(res, rotated.rawId, rotated.expiresAt);
      }
    } else {
      // Slide the idle window forward, capped by the absolute deadline.
      const slid = new Date(
        Math.min(
          now.getTime() + SESSION_IDLE_TTL_MS,
          session.absoluteExpiresAt.getTime(),
        ),
      );
      await this.prisma.session.update({
        where: { id: session.id },
        data: { lastUsedAt: now, expiresAt: slid },
      });
      if (res) this.writeCookie(res, rawId, slid);
    }

    return {
      sessionId: activeRawId,
      user: {
        id: session.user.id,
        email: session.user.email,
        role: session.user.role,
        firstName: session.user.firstName,
        lastName: session.user.lastName,
        mustChangePassword: session.user.mustChangePassword,
      },
    };
  }

  writeCookie(res: Response, rawId: string, expiresAt: Date): void {
    const maxAge = Math.max(0, expiresAt.getTime() - Date.now());
    res.cookie(this.cookieName, rawId, this.cookieOptions(maxAge));
    // The CSRF token tracks the session's lifetime, so a page that still has a
    // session always has a usable token to echo back.
    this.writeCsrfCookie(res, maxAge);
  }

  clearCookie(res: Response): void {
    this.clearCsrfCookie(res);
    // `clearCookie` sets its own expiry, so maxAge is dropped while the
    // remaining flags stay identical — a mismatch would leave the cookie in
    // place.
    const options = this.cookieOptions(0);
    delete options.maxAge;
    res.clearCookie(this.cookieName, options);
  }

  /** Kills one session. The row is deleted, so the id is dead everywhere at once. */
  async revoke(rawId: string): Promise<void> {
    await this.prisma.session.deleteMany({
      where: { tokenHash: this.hash(rawId) },
    });
  }

  /** Kills a rotation chain after reuse detection. */
  async revokeFamily(familyId: string): Promise<void> {
    await this.prisma.session.updateMany({
      where: { familyId },
      data: { revoked: true },
    });
  }

  /** Signs the user out of every device — used on password change and reset. */
  async revokeAllForUser(userId: string): Promise<void> {
    await this.prisma.session.deleteMany({ where: { userId } });
  }

  /** Drops rows that can no longer authenticate anything. */
  async pruneExpired(): Promise<number> {
    const { count } = await this.prisma.session.deleteMany({
      where: { OR: [{ expiresAt: { lt: new Date() } }, { revoked: true }] },
    });
    return count;
  }
}
