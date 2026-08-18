import { Test, TestingModule } from '@nestjs/testing';
import type { Request, Response } from 'express';
import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
import { SessionService } from '../session/session.service';
import { UserRole } from '../../generated/prisma/client';

const buildResponse = () =>
  ({
    cookie: jest.fn(),
    clearCookie: jest.fn(),
    redirect: jest.fn(),
  }) as unknown as Response & {
    cookie: jest.Mock;
    clearCookie: jest.Mock;
    redirect: jest.Mock;
  };

const buildRequest = (cookies: Record<string, string> = {}) =>
  ({ cookies, get: () => undefined, ip: '127.0.0.1' }) as unknown as Request;

describe('AuthController', () => {
  let controller: AuthController;
  let authService: Record<string, jest.Mock>;
  let sessionService: Record<string, jest.Mock> & { cookieName: string };

  beforeEach(async () => {
    authService = {
      me: jest.fn(),
      register: jest.fn(),
      login: jest.fn(),
      changePassword: jest.fn(),
      forgotPassword: jest.fn(),
      resetPassword: jest.fn(),
      verifyEmail: jest.fn(),
      resendVerificationEmail: jest.fn(),
      verifyGoogleIdToken: jest.fn(),
      upsertGoogleUser: jest.fn(),
      createAuthCode: jest.fn(),
      exchangeAuthCode: jest.fn(),
    };

    sessionService = Object.assign(
      {
        create: jest.fn().mockResolvedValue({
          rawId: 'new-session-id',
          expiresAt: new Date(Date.now() + 1000),
        }),
        writeCookie: jest.fn(),
        clearCookie: jest.fn(),
        revoke: jest.fn(),
        revokeAllForUser: jest.fn(),
      },
      { cookieName: 'session' },
    );

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: authService },
        { provide: SessionService, useValue: sessionService },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  describe('POST /auth/register', () => {
    it('delegates to the service and returns its result', async () => {
      const expected = {
        message:
          'Registration successful. Check your email to confirm your account.',
        user: {
          id: 'user-1',
          email: 'user@example.com',
          firstName: 'John',
          lastName: 'Doe',
          role: UserRole.STUDENT,
          emailVerifiedAt: null,
        },
      };
      authService.register.mockResolvedValue(expected);

      const dto = {
        email: 'user@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe',
      };
      const result = await controller.register(dto);

      expect(authService.register).toHaveBeenCalledWith(dto);
      expect(result).toEqual(expected);
    });

    it('does not set a session cookie — registration does not log the user in', async () => {
      authService.register.mockResolvedValue({ message: 'ok', user: {} });

      const result = await controller.register({
        email: 'user@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe',
      });

      expect(result).not.toHaveProperty('accessToken');
    });
  });

  describe('POST /auth/login', () => {
    it('starts a session and plants it in a cookie, returning only the user', async () => {
      authService.login.mockResolvedValue({
        user: { id: 'user-1', email: 'user@example.com' },
      });
      const res = buildResponse();

      const result = await controller.login(
        { email: 'user@example.com', password: 'password123' },
        buildRequest(),
        res,
      );

      expect(result).toEqual({
        user: { id: 'user-1', email: 'user@example.com' },
      });
      expect(sessionService.create).toHaveBeenCalledWith(
        'user-1',
        expect.anything(),
      );
      expect(sessionService.writeCookie).toHaveBeenCalledWith(
        res,
        'new-session-id',
        expect.any(Date),
      );
    });

    it('never puts a credential in the response body', async () => {
      authService.login.mockResolvedValue({ user: { id: 'user-1' } });

      const result = await controller.login(
        { email: 'user@example.com', password: 'password123' },
        buildRequest(),
        buildResponse(),
      );

      expect(result).not.toHaveProperty('accessToken');
      expect(result).not.toHaveProperty('refreshToken');
      expect(result).not.toHaveProperty('sessionId');
    });

    it('mints a fresh session id rather than honouring one supplied by the client', async () => {
      authService.login.mockResolvedValue({ user: { id: 'user-1' } });

      await controller.login(
        { email: 'user@example.com', password: 'password123' },
        buildRequest({ session: 'attacker-planted-id' }),
        buildResponse(),
      );

      // Session fixation: the incoming cookie must never be adopted.
      expect(sessionService.writeCookie).toHaveBeenCalledWith(
        expect.anything(),
        'new-session-id',
        expect.any(Date),
      );
    });
  });

  describe('POST /auth/forgot-password', () => {
    it('delegates to the service', async () => {
      const expected = {
        message: 'If the email exists, you will receive a password reset email',
      };
      authService.forgotPassword.mockResolvedValue(expected);

      const result = await controller.forgotPassword({
        email: 'user@example.com',
      });

      expect(authService.forgotPassword).toHaveBeenCalledWith({
        email: 'user@example.com',
      });
      expect(result).toEqual(expected);
    });
  });

  describe('POST /auth/reset-password', () => {
    it('delegates to the service', async () => {
      authService.resetPassword.mockResolvedValue({
        message: 'Password reset successfully',
      });

      const dto = {
        token: 'reset-token',
        newPassword: 'newPassword123',
        confirmPassword: 'newPassword123',
      };
      const res = buildResponse();
      const result = await controller.resetPassword(dto, res);

      expect(authService.resetPassword).toHaveBeenCalledWith(dto);
      expect(result).toEqual({ message: 'Password reset successfully' });
      // Every session for the user is gone, so the caller's cookie must go too.
      expect(sessionService.clearCookie).toHaveBeenCalledWith(res);
    });
  });

  describe('POST /auth/verify-email', () => {
    it('passes the token through to the service', async () => {
      authService.verifyEmail.mockResolvedValue({
        message: 'Email confirmed successfully',
      });

      const result = await controller.verifyEmail({ token: 'verify-token' });

      expect(authService.verifyEmail).toHaveBeenCalledWith('verify-token');
      expect(result).toEqual({ message: 'Email confirmed successfully' });
    });
  });

  describe('POST /auth/resend-verification', () => {
    it('passes the email through to the service', async () => {
      authService.resendVerificationEmail.mockResolvedValue({
        message: 'If the email exists and is unconfirmed, a new link was sent',
      });

      await controller.resendVerification({ email: 'user@example.com' });

      expect(authService.resendVerificationEmail).toHaveBeenCalledWith(
        'user@example.com',
      );
    });
  });

  describe('POST /auth/change-password', () => {
    it('uses the authenticated user id, not a body field', async () => {
      authService.changePassword.mockResolvedValue({
        message: 'Password changed successfully',
      });

      const dto = {
        currentPassword: 'oldPassword123',
        newPassword: 'newPassword123',
        confirmPassword: 'newPassword123',
      };
      await controller.changePassword(
        'user-1',
        dto,
        buildRequest(),
        buildResponse(),
      );

      expect(authService.changePassword).toHaveBeenCalledWith('user-1', dto);
    });

    it('re-issues a session so the caller survives their own password change', async () => {
      authService.changePassword.mockResolvedValue({
        message: 'Password changed successfully',
      });

      const res = buildResponse();
      await controller.changePassword(
        'user-1',
        {
          currentPassword: 'oldPassword123',
          newPassword: 'newPassword123',
          confirmPassword: 'newPassword123',
        },
        buildRequest(),
        res,
      );

      expect(sessionService.create).toHaveBeenCalledWith(
        'user-1',
        expect.anything(),
      );
      expect(sessionService.writeCookie).toHaveBeenCalledWith(
        res,
        'new-session-id',
        expect.any(Date),
      );
    });
  });

  describe('POST /auth/logout', () => {
    it('deletes the session row and clears the cookie', async () => {
      const req = buildRequest({ session: 'session-id' });
      const res = buildResponse();

      const result = await controller.logout(req, res);

      expect(sessionService.revoke).toHaveBeenCalledWith('session-id');
      expect(sessionService.clearCookie).toHaveBeenCalledWith(res);
      expect(result).toEqual({ message: 'Logged out successfully' });
    });

    it('still clears the cookie when no session is present', async () => {
      const res = buildResponse();

      await controller.logout(buildRequest(), res);

      expect(sessionService.revoke).not.toHaveBeenCalled();
      expect(sessionService.clearCookie).toHaveBeenCalledWith(res);
    });
  });

  describe('POST /auth/logout-all', () => {
    it('revokes every session for the user', async () => {
      const res = buildResponse();

      const result = await controller.logoutAll('user-1', res);

      expect(sessionService.revokeAllForUser).toHaveBeenCalledWith('user-1');
      expect(sessionService.clearCookie).toHaveBeenCalledWith(res);
      expect(result).toEqual({ message: 'Logged out from all devices' });
    });
  });

  describe('GET /auth/me', () => {
    it('returns the current user profile', async () => {
      const profile = {
        id: 'user-1',
        email: 'user@example.com',
        role: UserRole.STUDENT,
      };
      authService.me.mockResolvedValue(profile);

      const result = await controller.me('user-1');

      expect(authService.me).toHaveBeenCalledWith('user-1');
      expect(result).toEqual(profile);
    });
  });
});
