import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { CsrfGuard } from '../guards/csrf.guard';

const buildContext = (
  req: Record<string, unknown>,
  isPublic = false,
): { context: ExecutionContext; reflector: Reflector } => {
  const context = {
    switchToHttp: () => ({ getRequest: () => req }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as unknown as ExecutionContext;

  const reflector = {
    getAllAndOverride: jest.fn().mockReturnValue(isPublic),
  } as unknown as Reflector;

  return { context, reflector };
};

const buildRequest = (
  method: string,
  cookies: Record<string, string> = {},
  headers: Record<string, string> = {},
) => ({
  method,
  cookies,
  get: (name: string) => headers[name.toLowerCase()],
});

describe('CsrfGuard', () => {
  it('ignores safe methods', () => {
    const req = buildRequest('GET', { csrf_token: 'token' });
    const { context, reflector } = buildContext(req);

    expect(new CsrfGuard(reflector).canActivate(context)).toBe(true);
  });

  it('accepts a mutation whose header matches the cookie', () => {
    const req = buildRequest(
      'POST',
      { csrf_token: 'matching-token' },
      { 'x-csrf-token': 'matching-token' },
    );
    const { context, reflector } = buildContext(req);

    expect(new CsrfGuard(reflector).canActivate(context)).toBe(true);
  });

  it('rejects a forged request that has the cookie but no header', () => {
    // The CSRF case: the browser attaches the cookie automatically, but a
    // cross-site page cannot read it to set the matching header.
    const req = buildRequest('POST', { csrf_token: 'token' });
    const { context, reflector } = buildContext(req);

    expect(() => new CsrfGuard(reflector).canActivate(context)).toThrow(
      ForbiddenException,
    );
  });

  it('rejects a mismatched header', () => {
    const req = buildRequest(
      'POST',
      { csrf_token: 'real-token' },
      { 'x-csrf-token': 'guessed-token' },
    );
    const { context, reflector } = buildContext(req);

    expect(() => new CsrfGuard(reflector).canActivate(context)).toThrow(
      ForbiddenException,
    );
  });

  it('rejects a header of a different length', () => {
    const req = buildRequest(
      'POST',
      { csrf_token: 'real-token' },
      { 'x-csrf-token': 'x' },
    );
    const { context, reflector } = buildContext(req);

    expect(() => new CsrfGuard(reflector).canActivate(context)).toThrow(
      ForbiddenException,
    );
  });

  it('allows public endpoints that carry no session', () => {
    // Login and password reset have no session to abuse.
    const req = buildRequest('POST');
    const { context, reflector } = buildContext(req, true);

    expect(new CsrfGuard(reflector).canActivate(context)).toBe(true);
  });

  it('allows native clients, which attach their session explicitly', () => {
    const req = buildRequest('POST');
    const { context, reflector } = buildContext(req);

    expect(new CsrfGuard(reflector).canActivate(context)).toBe(true);
  });

  it('still enforces the token on a public route once a session exists', () => {
    // e.g. logout: marked public, but a browser session is present.
    const req = buildRequest('POST', { csrf_token: 'token' });
    const { context, reflector } = buildContext(req, true);

    expect(() => new CsrfGuard(reflector).canActivate(context)).toThrow(
      ForbiddenException,
    );
  });
});
