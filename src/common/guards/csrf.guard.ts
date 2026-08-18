import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import * as crypto from 'crypto';
import type { Request } from 'express';
import {
  CSRF_HEADER,
  csrfCookieName,
} from '../../auth/session/session.constants';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Double-submit CSRF validation — the primary of the three CSRF layers
 * (the others being `SameSite=Lax` and the `Sec-Fetch-Site` check in
 * `OriginGuard`).
 *
 * The server plants a random token in a readable cookie; the client echoes it
 * in a header. A cross-site attacker can make the browser *send* the cookie but
 * cannot read it, and cannot set a custom header on a forged form post — so a
 * matching pair proves the request came from our own origin.
 *
 * Only applied to cookie-authenticated requests: native mobile clients attach
 * the session explicitly rather than having it sent ambiently, so they are not
 * exposed to CSRF and are not asked for a token.
 */
@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();

    if (!STATE_CHANGING.has(req.method)) return true;

    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const cookies = req.cookies as Record<string, string | undefined>;
    const cookieName = csrfCookieName(process.env.NODE_ENV === 'production');
    const cookieToken = cookies?.[cookieName];

    // Unauthenticated entry points (login, register, password reset) have no
    // session to ride on, so there is nothing for CSRF to abuse.
    if (isPublic && !cookieToken) return true;

    // No token cookie means no browser session — a native client attaching its
    // session by hand, which CSRF does not apply to.
    if (!cookieToken) return true;

    const headerToken = req.get(CSRF_HEADER);

    if (!headerToken) {
      throw new ForbiddenException('Missing CSRF token');
    }

    if (!safeEqual(cookieToken, headerToken)) {
      throw new ForbiddenException('Invalid CSRF token');
    }

    return true;
  }
}

/** Constant-time compare, so a mismatch cannot be probed byte by byte. */
function safeEqual(a: string, b: string): boolean {
  const bufferA = Buffer.from(a);
  const bufferB = Buffer.from(b);
  if (bufferA.length !== bufferB.length) return false;
  return crypto.timingSafeEqual(bufferA, bufferB);
}
