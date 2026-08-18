import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import { SessionService } from '../session/session.service';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';

/**
 * Resolves the opaque session cookie into `req.user` on every request.
 *
 * Replaces the old JwtAuthGuard. The cost is one indexed lookup per request;
 * the payoff is that revocation, bans and role changes are immediate rather
 * than eventual.
 */
@Injectable()
export class SessionGuard implements CanActivate {
  constructor(
    private readonly sessionService: SessionService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const http = context.switchToHttp();
    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();

    const resolved = await this.sessionService.resolve(req, res);
    if (!resolved) {
      throw new UnauthorizedException('Not logged in');
    }

    req.user = resolved.user;
    (req as Request & { sessionId?: string }).sessionId = resolved.sessionId;
    return true;
  }
}
