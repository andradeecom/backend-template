import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';

const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * CSRF defence in depth.
 *
 * Because the session travels in a cookie the browser attaches automatically, a
 * cross-site form could otherwise drive state-changing requests. `SameSite=Lax`
 * covers most of that, but it is scoped to the *site*, so it offers no
 * protection between sibling subdomains — and it permits top-level GET
 * navigations.
 *
 * Browsers stamp `Sec-Fetch-Site` themselves and a page cannot forge it, so
 * checking it closes the subdomain gap that SameSite leaves open. `Origin` is
 * the fallback for clients that predate Fetch Metadata.
 *
 * Non-browser callers (native mobile, server-to-server) send neither header and
 * are not subject to ambient cookie attachment, so they pass through.
 */
@Injectable()
export class OriginGuard implements CanActivate {
  private readonly allowedOrigins: string[];

  constructor() {
    this.allowedOrigins = (process.env.ALLOWED_ORIGINS ?? '')
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean);

    const frontendUrl = process.env.FRONTEND_URL;
    if (frontendUrl && !this.allowedOrigins.includes(frontendUrl)) {
      this.allowedOrigins.push(frontendUrl);
    }
  }

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();

    if (!STATE_CHANGING.has(req.method)) return true;

    const fetchSite = req.get('sec-fetch-site');
    if (fetchSite) {
      // `none` is a user-initiated navigation (typed URL, bookmark) — never an
      // attacker-driven cross-site POST.
      if (fetchSite === 'same-origin' || fetchSite === 'none') return true;
      throw new ForbiddenException('Cross-site request rejected');
    }

    const origin = req.get('origin');
    if (origin) {
      if (this.allowedOrigins.includes(origin)) return true;
      throw new ForbiddenException('Cross-site request rejected');
    }

    return true;
  }
}
