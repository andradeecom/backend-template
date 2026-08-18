import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { createTestApp, TestApp } from './create-test-app';
import { PrismaMock } from './prisma.mock';
import { EmailService } from '../src/email/email.service';

/**
 * These assert the properties that only show up once the whole request pipeline
 * is assembled: the global guards, the ValidationPipe's whitelist, and the
 * cookie flags. Unit specs mock the guards away, so none of this is covered
 * there.
 */
describe('Auth (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaMock;
  let ctx: TestApp;

  const server = () => app.getHttpServer() as App;

  beforeAll(async () => {
    ctx = await createTestApp();
    app = ctx.app;
    prisma = ctx.prisma;
  });

  afterEach(() => {
    prisma.reset();
    jest.clearAllMocks();
  });

  afterAll(async () => {
    await app.close();
  });

  // A stub whose method names drift from EmailService would stop intercepting
  // and let the real Resend client run. Pin the names to the class itself.
  it('stubs every EmailService method', () => {
    const real = Object.getOwnPropertyNames(EmailService.prototype).filter(
      (name) => name.startsWith('send'),
    );

    expect(Object.keys(ctx.email).sort()).toEqual(real.sort());
  });

  describe('protected routes', () => {
    it('rejects GET /api/auth/me without a session cookie', async () => {
      await request(server()).get('/api/auth/me').expect(401);
    });

    it('rejects an unknown session id rather than trusting the cookie', async () => {
      await request(server())
        .get('/api/auth/me')
        .set('Cookie', 'session=not-a-real-session-id')
        .expect(401);
    });
  });

  describe('CSRF (OriginGuard, layer 3)', () => {
    // Sec-Fetch-Site is stamped by the browser and cannot be forged by a page,
    // so the guard rejects same-site as well as cross-site — that is what
    // closes the sibling-subdomain gap SameSite leaves open.
    it.each(['cross-site', 'same-site'])(
      'rejects a mutation with Sec-Fetch-Site: %s',
      async (value) => {
        const res = await request(server())
          .post('/api/auth/login')
          .set('Sec-Fetch-Site', value)
          .send({ email: 'a@b.com', password: 'password123' });

        expect(res.status).toBe(403);
      },
    );

    it('allows same-origin', async () => {
      const res = await request(server())
        .post('/api/auth/login')
        .set('Sec-Fetch-Site', 'same-origin')
        .send({ email: 'nobody@example.com', password: 'password123' });

      // Credentials are wrong, but the request got past the guard — which is
      // the distinction being asserted.
      expect(res.status).not.toBe(403);
    });
  });

  describe('input validation', () => {
    it('rejects a malformed email', async () => {
      await request(server())
        .post('/api/auth/register')
        .send({
          email: 'not-an-email',
          password: 'password123',
          firstName: 'A',
          lastName: 'B',
        })
        .expect(400);
    });

    // whitelist + forbidNonWhitelisted is what stops a client from assigning
    // itself a role at registration. RegisterDto has no role field at all.
    it('rejects a client-supplied role instead of silently accepting it', async () => {
      const res = await request(server()).post('/api/auth/register').send({
        email: 'escalate@example.com',
        password: 'password123',
        firstName: 'A',
        lastName: 'B',
        role: 'ADMIN',
      });

      expect(res.status).toBe(400);
      expect(prisma.user.count()).toBe(0);
    });
  });

  describe('user enumeration', () => {
    // Both of these must answer identically whether or not the account exists,
    // or the endpoint becomes an account-existence oracle.
    it('answers forgot-password the same for known and unknown addresses', async () => {
      const unknown = await request(server())
        .post('/api/auth/forgot-password')
        .send({ email: 'ghost@example.com' });

      prisma.user.seed([
        {
          id: 'u1',
          email: 'real@example.com',
          password: 'hashed',
          firstName: 'R',
          lastName: 'L',
          role: 'STUDENT',
          isActive: true,
        },
      ]);

      const known = await request(server())
        .post('/api/auth/forgot-password')
        .send({ email: 'real@example.com' });

      expect(unknown.status).toBe(known.status);
      expect(unknown.body).toEqual(known.body);

      // The responses match, so the only observable difference would be the
      // side effect: mail goes out for the real address and not the ghost.
      expect(ctx.email.sendPasswordResetEmail).toHaveBeenCalledTimes(1);
    });
  });
});
