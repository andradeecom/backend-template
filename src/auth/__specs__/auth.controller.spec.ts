import { Test, TestingModule } from '@nestjs/testing';
import type { Request, Response } from 'express';
import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
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

describe('AuthController', () => {
  let controller: AuthController;
  let authService: Record<string, jest.Mock>;

  beforeEach(async () => {
    authService = {
      me: jest.fn(),
      register: jest.fn(),
      login: jest.fn(),
      refreshToken: jest.fn(),
      changePassword: jest.fn(),
      forgotPassword: jest.fn(),
      resetPassword: jest.fn(),
      verifyEmail: jest.fn(),
      resendVerificationEmail: jest.fn(),
      revokeRefreshToken: jest.fn(),
      verifyGoogleIdToken: jest.fn(),
      upsertGoogleUser: jest.fn(),
      createAuthCode: jest.fn(),
      exchangeAuthCode: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [{ provide: AuthService, useValue: authService }],
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
    it('returns the access token and sets the refresh cookie', async () => {
      authService.login.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        user: { id: 'user-1', email: 'user@example.com' },
      });
      const res = buildResponse();

      const result = await controller.login(
        { email: 'user@example.com', password: 'password123' },
        res,
      );

      expect(result).toEqual({
        accessToken: 'access-token',
        user: { id: 'user-1', email: 'user@example.com' },
      });
      expect(res.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'refresh-token',
        expect.objectContaining({ httpOnly: true, sameSite: 'strict' }),
      );
    });

    it('never returns the refresh token in the response body', async () => {
      authService.login.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        user: { id: 'user-1' },
      });

      const result = await controller.login(
        { email: 'user@example.com', password: 'password123' },
        buildResponse(),
      );

      expect(result).not.toHaveProperty('refreshToken');
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
      const result = await controller.resetPassword(dto);

      expect(authService.resetPassword).toHaveBeenCalledWith(dto);
      expect(result).toEqual({ message: 'Password reset successfully' });
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
      await controller.changePassword('user-1', dto);

      expect(authService.changePassword).toHaveBeenCalledWith('user-1', dto);
    });
  });

  describe('POST /auth/logout', () => {
    it('revokes the refresh token and clears the auth cookies', async () => {
      const req = {
        cookies: { refresh_token: 'refresh-token' },
      } as unknown as Request;
      const res = buildResponse();

      const result = await controller.logout(req, res);

      expect(authService.revokeRefreshToken).toHaveBeenCalledWith(
        'refresh-token',
      );
      const clearedCookies = res.clearCookie.mock.calls.map(
        (call) => call[0] as string,
      );
      expect(clearedCookies).toEqual(
        expect.arrayContaining(['refresh_token', 'access_token', 'user_data']),
      );
      expect(result).toEqual({ message: 'Logged out successfully' });
    });

    it('still clears cookies when no refresh token is present', async () => {
      const req = { cookies: {} } as unknown as Request;
      const res = buildResponse();

      await controller.logout(req, res);

      expect(authService.revokeRefreshToken).not.toHaveBeenCalled();
      expect(res.clearCookie).toHaveBeenCalled();
    });
  });

  describe('POST /auth/refresh', () => {
    it('rotates the refresh cookie and returns a new access token', async () => {
      authService.refreshToken.mockResolvedValue({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      });
      const res = buildResponse();

      const result = await controller.refresh(
        {
          id: 'user-1',
          email: 'user@example.com',
          role: UserRole.STUDENT,
          rawRefreshToken: 'old-refresh-token',
        },
        res,
      );

      expect(authService.refreshToken).toHaveBeenCalledWith(
        'user-1',
        'user@example.com',
        UserRole.STUDENT,
        'old-refresh-token',
      );
      expect(result).toEqual({ accessToken: 'new-access-token' });
      expect(res.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'new-refresh-token',
        expect.objectContaining({ httpOnly: true }),
      );
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
