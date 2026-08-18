import { Test, TestingModule } from '@nestjs/testing';
import * as crypto from 'crypto';
import type { Request, Response } from 'express';
import { SessionService } from '../session/session.service';
import { PrismaService } from '../../prisma/prisma.service';
import { SESSION_ROTATION_INTERVAL_MS } from '../session/session.constants';

const hash = (raw: string) =>
  crypto.createHash('sha256').update(raw).digest('hex');

const buildRequest = () =>
  ({
    cookies: {},
    get: () => 'jest-agent',
    ip: '127.0.0.1',
  }) as unknown as Request & { cookies: Record<string, string> };

const buildResponse = () =>
  ({ cookie: jest.fn(), clearCookie: jest.fn() }) as unknown as Response & {
    cookie: jest.Mock;
    clearCookie: jest.Mock;
  };

const buildSessionRow = (overrides: Record<string, unknown> = {}) => ({
  id: 'session-row-1',
  tokenHash: hash('raw-id'),
  userId: 'user-1',
  familyId: 'family-1',
  expiresAt: new Date(Date.now() + 60_000),
  absoluteExpiresAt: new Date(Date.now() + 86_400_000),
  revoked: false,
  lastUsedAt: new Date(),
  createdAt: new Date(),
  user: {
    id: 'user-1',
    email: 'u@example.com',
    role: 'STUDENT',
    firstName: 'J',
    lastName: 'D',
    isActive: true,
    mustChangePassword: false,
  },
  ...overrides,
});

describe('SessionService', () => {
  let service: SessionService;
  let prisma: {
    session: Record<string, jest.Mock>;
    $transaction: jest.Mock;
  };

  beforeEach(async () => {
    prisma = {
      session: {
        create: jest.fn().mockResolvedValue({}),
        findUnique: jest.fn(),
        update: jest.fn().mockResolvedValue({}),
        updateMany: jest.fn().mockResolvedValue({ count: 0 }),
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
      },
      $transaction: jest.fn().mockResolvedValue([]),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [SessionService, { provide: PrismaService, useValue: prisma }],
    }).compile();

    service = module.get(SessionService);
  });

  describe('create', () => {
    it('stores only a hash, never the raw session id', async () => {
      const { rawId } = await service.create('user-1', buildRequest());

      const data = prisma.session.create.mock.calls[0][0].data;
      expect(data.tokenHash).toBe(hash(rawId));
      expect(JSON.stringify(data)).not.toContain(rawId);
    });

    it('generates an unguessable id', async () => {
      const a = await service.create('user-1', buildRequest());
      const b = await service.create('user-1', buildRequest());

      // 32 random bytes, hex encoded.
      expect(a.rawId).toMatch(/^[0-9a-f]{64}$/);
      expect(a.rawId).not.toBe(b.rawId);
    });

    it('caps the idle window at the absolute deadline', async () => {
      const { expiresAt, absoluteExpiresAt } = await service.create(
        'user-1',
        buildRequest(),
      );
      expect(expiresAt.getTime()).toBeLessThanOrEqual(
        absoluteExpiresAt.getTime(),
      );
    });
  });

  describe('resolve', () => {
    it('returns null when no cookie is present', async () => {
      const req = buildRequest();
      await expect(service.resolve(req, buildResponse())).resolves.toBeNull();
    });

    it('returns null for an unknown session id', async () => {
      const req = buildRequest();
      req.cookies.session = 'raw-id';
      prisma.session.findUnique.mockResolvedValue(null);

      await expect(service.resolve(req, buildResponse())).resolves.toBeNull();
    });

    it('burns the whole family when a revoked id is replayed', async () => {
      const req = buildRequest();
      req.cookies.session = 'raw-id';
      prisma.session.findUnique.mockResolvedValue(
        buildSessionRow({ revoked: true }),
      );

      const result = await service.resolve(req, buildResponse());

      expect(result).toBeNull();
      // Reuse detection: we cannot tell attacker from victim, so both lose.
      expect(prisma.session.updateMany).toHaveBeenCalledWith({
        where: { familyId: 'family-1' },
        data: { revoked: true },
      });
    });

    it('rejects an expired session', async () => {
      const req = buildRequest();
      req.cookies.session = 'raw-id';
      prisma.session.findUnique.mockResolvedValue(
        buildSessionRow({ expiresAt: new Date(Date.now() - 1000) }),
      );

      await expect(service.resolve(req, buildResponse())).resolves.toBeNull();
    });

    it('rejects a session past its absolute deadline even if recently used', async () => {
      const req = buildRequest();
      req.cookies.session = 'raw-id';
      prisma.session.findUnique.mockResolvedValue(
        buildSessionRow({
          expiresAt: new Date(Date.now() + 60_000),
          absoluteExpiresAt: new Date(Date.now() - 1000),
        }),
      );

      await expect(service.resolve(req, buildResponse())).resolves.toBeNull();
    });

    it('rejects a deactivated user immediately, without waiting for expiry', async () => {
      const req = buildRequest();
      req.cookies.session = 'raw-id';
      const row = buildSessionRow();
      row.user.isActive = false;
      prisma.session.findUnique.mockResolvedValue(row);

      await expect(service.resolve(req, buildResponse())).resolves.toBeNull();
    });

    it('resolves a valid session and slides the idle window', async () => {
      const req = buildRequest();
      req.cookies.session = 'raw-id';
      prisma.session.findUnique.mockResolvedValue(buildSessionRow());
      const res = buildResponse();

      const result = await service.resolve(req, res);

      expect(result?.user.id).toBe('user-1');
      expect(prisma.session.update).toHaveBeenCalled();
      expect(res.cookie).toHaveBeenCalled();
    });

    it('rotates the id once the rotation interval has elapsed', async () => {
      const req = buildRequest();
      req.cookies.session = 'raw-id';
      prisma.session.findUnique.mockResolvedValue(
        buildSessionRow({
          lastUsedAt: new Date(
            Date.now() - SESSION_ROTATION_INTERVAL_MS - 1000,
          ),
        }),
      );
      const res = buildResponse();

      const result = await service.resolve(req, res);

      expect(prisma.$transaction).toHaveBeenCalled();
      // A rotated session hands the client a different id than it presented.
      expect(result?.sessionId).not.toBe('raw-id');
      expect(res.cookie).toHaveBeenCalled();
    });

    it('keeps serving the current id when a concurrent rotation wins the race', async () => {
      const req = buildRequest();
      req.cookies.session = 'raw-id';
      prisma.session.findUnique.mockResolvedValue(
        buildSessionRow({
          lastUsedAt: new Date(
            Date.now() - SESSION_ROTATION_INTERVAL_MS - 1000,
          ),
        }),
      );
      prisma.$transaction.mockRejectedValue(new Error('row already revoked'));

      const result = await service.resolve(req, buildResponse());

      // The loser of the race must not log the user out or trip reuse detection.
      expect(result?.sessionId).toBe('raw-id');
    });
  });

  describe('CSRF token', () => {
    it('is readable by JavaScript, unlike the session cookie', () => {
      const res = buildResponse();

      service.writeCsrfCookie(res, 1000);

      const [name, , options] = res.cookie.mock.calls[0];
      expect(name).toBe('csrf_token');
      // Readable on purpose: the client has to echo it back in a header.
      // It is not a credential, so this does not weaken the session.
      expect(options.httpOnly).toBe(false);
    });

    it('issues an unguessable token', () => {
      const res = buildResponse();

      const first = service.writeCsrfCookie(res, 1000);
      const second = service.writeCsrfCookie(res, 1000);

      expect(first).toMatch(/^[0-9a-f]{64}$/);
      expect(first).not.toBe(second);
    });

    it('accompanies every session cookie write', () => {
      const res = buildResponse();

      service.writeCookie(res, 'raw-id', new Date(Date.now() + 1000));

      const names = res.cookie.mock.calls.map((call) => call[0] as string);
      expect(names).toEqual(expect.arrayContaining(['session', 'csrf_token']));
    });

    it('is cleared alongside the session', () => {
      const res = buildResponse();

      service.clearCookie(res);

      const names = res.clearCookie.mock.calls.map((call) => call[0] as string);
      expect(names).toEqual(expect.arrayContaining(['session', 'csrf_token']));
    });
  });

  describe('cookie flags', () => {
    it('is httpOnly and path-scoped to the whole host', () => {
      const options = service.cookieOptions(1000);

      expect(options.httpOnly).toBe(true);
      expect(options.sameSite).toBe('lax');
      expect(options.path).toBe('/');
      // __Host- forbids a Domain attribute, pinning the cookie to this host.
      expect(options).not.toHaveProperty('domain');
    });
  });

  describe('revocation', () => {
    it('deletes the row on logout so the id dies everywhere at once', async () => {
      await service.revoke('raw-id');

      expect(prisma.session.deleteMany).toHaveBeenCalledWith({
        where: { tokenHash: hash('raw-id') },
      });
    });

    it('signs a user out of every device', async () => {
      await service.revokeAllForUser('user-1');

      expect(prisma.session.deleteMany).toHaveBeenCalledWith({
        where: { userId: 'user-1' },
      });
    });
  });
});
