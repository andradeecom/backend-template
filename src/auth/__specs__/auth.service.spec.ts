import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { AuthService } from '../auth.service';
import { PrismaService } from '../../prisma/prisma.service';
import { EmailService } from '../../email/email.service';
import { SessionService } from '../session/session.service';
import { AuthProvider, UserRole } from '../../generated/prisma/client';

const hashToken = (token: string) =>
  crypto.createHash('sha256').update(token).digest('hex');

/** First argument of the first call, typed so specs avoid `any` chains. */
const firstCallArg = <T>(mock: jest.Mock, index = 0): T =>
  mock.mock.calls[0][index] as T;

const buildUser = (overrides: Record<string, unknown> = {}) => ({
  id: 'user-1',
  email: 'user@example.com',
  password: 'hashed-password',
  firstName: 'John',
  lastName: 'Doe',
  role: UserRole.STUDENT,
  authProvider: AuthProvider.LOCAL,
  googleId: null,
  profileImageUrl: null,
  isActive: true,
  mustChangePassword: false,
  emailVerifiedAt: null,
  createdById: null,
  lastLoginAt: null,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

describe('AuthService', () => {
  let service: AuthService;
  let prisma: {
    user: Record<string, jest.Mock>;
    session: Record<string, jest.Mock>;
    passwordResetToken: Record<string, jest.Mock>;
    emailVerificationToken: Record<string, jest.Mock>;
    authCode: Record<string, jest.Mock>;
    $transaction: jest.Mock;
  };
  let emailService: Record<string, jest.Mock>;

  beforeEach(async () => {
    prisma = {
      user: {
        findUnique: jest.fn(),
        findFirst: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
      },
      session: {
        create: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
        updateMany: jest.fn(),
        deleteMany: jest.fn(),
      },
      passwordResetToken: {
        create: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
        updateMany: jest.fn(),
      },
      emailVerificationToken: {
        create: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
        updateMany: jest.fn(),
      },
      authCode: {
        create: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
      },
      // The service only uses $transaction to batch writes, so resolving the
      // already-invoked mock calls is enough for these tests.
      $transaction: jest.fn().mockResolvedValue([]),
    };

    emailService = {
      sendWelcomeEmail: jest.fn().mockResolvedValue(undefined),
      sendPasswordRecoveryEmail: jest.fn().mockResolvedValue(undefined),
      sendPasswordResetEmail: jest.fn().mockResolvedValue(undefined),
      sendEmailVerificationEmail: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prisma },
        { provide: EmailService, useValue: emailService },
        {
          provide: SessionService,
          useValue: {
            create: jest.fn().mockResolvedValue({
              rawId: 'session-id',
              expiresAt: new Date(Date.now() + 1000),
            }),
            revoke: jest.fn(),
            revokeAllForUser: jest.fn(),
            writeCookie: jest.fn(),
            clearCookie: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              const values: Record<string, string> = {
                GOOGLE_CLIENT_ID: 'google-client-id',
              };
              return values[key];
            }),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  describe('register', () => {
    it('creates a STUDENT account and sends a verification email', async () => {
      prisma.user.findUnique.mockResolvedValue(null);
      prisma.user.create.mockResolvedValue(buildUser());
      prisma.emailVerificationToken.updateMany.mockResolvedValue({ count: 0 });
      prisma.emailVerificationToken.create.mockResolvedValue({});

      const result = await service.register({
        email: 'user@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe',
      });

      expect(prisma.user.create).toHaveBeenCalledTimes(1);
      const { data } = firstCallArg<{
        data: {
          role: UserRole;
          authProvider: AuthProvider;
          mustChangePassword: boolean;
        };
      }>(prisma.user.create);
      expect(data.role).toBe(UserRole.STUDENT);
      expect(data.authProvider).toBe(AuthProvider.LOCAL);
      expect(data.mustChangePassword).toBe(false);
      expect(result.user.role).toBe(UserRole.STUDENT);
      expect(emailService.sendEmailVerificationEmail).toHaveBeenCalledTimes(1);
    });

    it('hashes the password instead of storing it in plain text', async () => {
      prisma.user.findUnique.mockResolvedValue(null);
      prisma.user.create.mockResolvedValue(buildUser());
      prisma.emailVerificationToken.updateMany.mockResolvedValue({ count: 0 });
      prisma.emailVerificationToken.create.mockResolvedValue({});

      await service.register({
        email: 'user@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe',
      });

      const { data } = firstCallArg<{ data: { password: string } }>(
        prisma.user.create,
      );
      expect(data.password).not.toBe('password123');
      await expect(bcrypt.compare('password123', data.password)).resolves.toBe(
        true,
      );
    });

    it('never returns the password hash', async () => {
      prisma.user.findUnique.mockResolvedValue(null);
      prisma.user.create.mockResolvedValue(buildUser());
      prisma.emailVerificationToken.updateMany.mockResolvedValue({ count: 0 });
      prisma.emailVerificationToken.create.mockResolvedValue({});

      const result = await service.register({
        email: 'user@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe',
      });

      expect(result.user).not.toHaveProperty('password');
    });

    it('rejects an email that is already registered', async () => {
      prisma.user.findUnique.mockResolvedValue(buildUser());

      await expect(
        service.register({
          email: 'user@example.com',
          password: 'password123',
          firstName: 'John',
          lastName: 'Doe',
        }),
      ).rejects.toThrow(ConflictException);

      expect(prisma.user.create).not.toHaveBeenCalled();
    });

    it('still registers the user when the verification email fails to send', async () => {
      prisma.user.findUnique.mockResolvedValue(null);
      prisma.user.create.mockResolvedValue(buildUser());
      prisma.emailVerificationToken.updateMany.mockResolvedValue({ count: 0 });
      prisma.emailVerificationToken.create.mockResolvedValue({});
      emailService.sendEmailVerificationEmail.mockRejectedValue(
        new Error('resend is down'),
      );

      await expect(
        service.register({
          email: 'user@example.com',
          password: 'password123',
          firstName: 'John',
          lastName: 'Doe',
        }),
      ).resolves.toBeDefined();

      expect(prisma.user.create).toHaveBeenCalledTimes(1);
    });
  });

  describe('login', () => {
    it('returns the user for valid credentials without any token', async () => {
      const password = await bcrypt.hash('password123', 10);
      prisma.user.findUnique.mockResolvedValue(buildUser({ password }));
      prisma.user.update.mockResolvedValue(buildUser({ password }));

      const result = await service.login({
        email: 'user@example.com',
        password: 'password123',
      });

      // The session is minted by the controller; the service only vouches for
      // the user, and never hands back anything token-shaped.
      expect(result).not.toHaveProperty('accessToken');
      expect(result).not.toHaveProperty('refreshToken');
      expect(result.user.email).toBe('user@example.com');
      expect(result.user).not.toHaveProperty('password');
    });

    it('rejects an unknown email', async () => {
      prisma.user.findUnique.mockResolvedValue(null);

      await expect(
        service.login({ email: 'nope@example.com', password: 'password123' }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('rejects a wrong password', async () => {
      const password = await bcrypt.hash('password123', 10);
      prisma.user.findUnique.mockResolvedValue(buildUser({ password }));

      await expect(
        service.login({
          email: 'user@example.com',
          password: 'wrong-password',
        }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('rejects a deactivated account', async () => {
      const password = await bcrypt.hash('password123', 10);
      prisma.user.findUnique.mockResolvedValue(
        buildUser({ password, isActive: false }),
      );

      await expect(
        service.login({ email: 'user@example.com', password: 'password123' }),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('forgotPassword', () => {
    it('stores only the token hash and emails the raw token', async () => {
      prisma.user.findUnique.mockResolvedValue(buildUser());
      prisma.passwordResetToken.updateMany.mockResolvedValue({ count: 0 });
      prisma.passwordResetToken.create.mockResolvedValue({});

      await service.forgotPassword({ email: 'user@example.com' });

      const { data: stored } = firstCallArg<{ data: { tokenHash: string } }>(
        prisma.passwordResetToken.create,
      );
      const emailedToken = firstCallArg<string>(
        emailService.sendPasswordResetEmail,
        2,
      );

      expect(stored.tokenHash).toBe(hashToken(emailedToken));
      expect(stored.tokenHash).not.toBe(emailedToken);
    });

    it('invalidates previously issued reset tokens', async () => {
      prisma.user.findUnique.mockResolvedValue(buildUser());
      prisma.passwordResetToken.updateMany.mockResolvedValue({ count: 1 });
      prisma.passwordResetToken.create.mockResolvedValue({});

      await service.forgotPassword({ email: 'user@example.com' });

      expect(prisma.passwordResetToken.updateMany).toHaveBeenCalledWith({
        where: { userId: 'user-1', usedAt: null },
        data: { usedAt: expect.any(Date) },
      });
    });

    it('does not leak whether the email exists', async () => {
      prisma.user.findUnique.mockResolvedValue(null);

      const unknown = await service.forgotPassword({
        email: 'nobody@example.com',
      });

      prisma.user.findUnique.mockResolvedValue(buildUser());
      prisma.passwordResetToken.updateMany.mockResolvedValue({ count: 0 });
      prisma.passwordResetToken.create.mockResolvedValue({});
      const known = await service.forgotPassword({ email: 'user@example.com' });

      expect(unknown).toEqual(known);
    });

    it('does not issue a token for an unknown email', async () => {
      prisma.user.findUnique.mockResolvedValue(null);

      await service.forgotPassword({ email: 'nobody@example.com' });

      expect(prisma.passwordResetToken.create).not.toHaveBeenCalled();
      expect(emailService.sendPasswordResetEmail).not.toHaveBeenCalled();
    });

    it('does not issue a token for a deactivated account', async () => {
      prisma.user.findUnique.mockResolvedValue(buildUser({ isActive: false }));

      await service.forgotPassword({ email: 'user@example.com' });

      expect(prisma.passwordResetToken.create).not.toHaveBeenCalled();
    });
  });

  describe('resetPassword', () => {
    const validToken = 'a'.repeat(64);

    const validResetRecord = () => ({
      id: 'reset-1',
      tokenHash: hashToken(validToken),
      userId: 'user-1',
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      usedAt: null,
      createdAt: new Date(),
    });

    it('sets a new hashed password and consumes the token', async () => {
      prisma.passwordResetToken.findUnique.mockResolvedValue(
        validResetRecord(),
      );
      prisma.user.findUnique.mockResolvedValue(buildUser());

      const result = await service.resetPassword({
        token: validToken,
        newPassword: 'newPassword123',
        confirmPassword: 'newPassword123',
      });

      expect(result).toEqual({ message: 'Password reset successfully' });
      expect(prisma.$transaction).toHaveBeenCalledTimes(1);

      const { data } = firstCallArg<{
        data: { password: string; mustChangePassword: boolean };
      }>(prisma.user.update);
      await expect(
        bcrypt.compare('newPassword123', data.password),
      ).resolves.toBe(true);
      expect(data.mustChangePassword).toBe(false);
    });

    it('deletes every session so old ones cannot continue', async () => {
      prisma.passwordResetToken.findUnique.mockResolvedValue(
        validResetRecord(),
      );
      prisma.user.findUnique.mockResolvedValue(buildUser());

      await service.resetPassword({
        token: validToken,
        newPassword: 'newPassword123',
        confirmPassword: 'newPassword123',
      });

      expect(prisma.session.deleteMany).toHaveBeenCalledWith({
        where: { userId: 'user-1' },
      });
    });

    it('rejects mismatched passwords', async () => {
      await expect(
        service.resetPassword({
          token: validToken,
          newPassword: 'newPassword123',
          confirmPassword: 'differentPassword',
        }),
      ).rejects.toThrow(BadRequestException);

      expect(prisma.passwordResetToken.findUnique).not.toHaveBeenCalled();
    });

    it('rejects an unknown token', async () => {
      prisma.passwordResetToken.findUnique.mockResolvedValue(null);

      await expect(
        service.resetPassword({
          token: validToken,
          newPassword: 'newPassword123',
          confirmPassword: 'newPassword123',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('rejects an expired token', async () => {
      prisma.passwordResetToken.findUnique.mockResolvedValue({
        ...validResetRecord(),
        expiresAt: new Date(Date.now() - 1000),
      });

      await expect(
        service.resetPassword({
          token: validToken,
          newPassword: 'newPassword123',
          confirmPassword: 'newPassword123',
        }),
      ).rejects.toThrow(BadRequestException);

      expect(prisma.$transaction).not.toHaveBeenCalled();
    });

    it('rejects a token that was already used', async () => {
      prisma.passwordResetToken.findUnique.mockResolvedValue({
        ...validResetRecord(),
        usedAt: new Date(),
      });

      await expect(
        service.resetPassword({
          token: validToken,
          newPassword: 'newPassword123',
          confirmPassword: 'newPassword123',
        }),
      ).rejects.toThrow(BadRequestException);

      expect(prisma.$transaction).not.toHaveBeenCalled();
    });

    it('rejects a token belonging to a deactivated account', async () => {
      prisma.passwordResetToken.findUnique.mockResolvedValue(
        validResetRecord(),
      );
      prisma.user.findUnique.mockResolvedValue(buildUser({ isActive: false }));

      await expect(
        service.resetPassword({
          token: validToken,
          newPassword: 'newPassword123',
          confirmPassword: 'newPassword123',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('looks the token up by hash, never by the raw value', async () => {
      prisma.passwordResetToken.findUnique.mockResolvedValue(
        validResetRecord(),
      );
      prisma.user.findUnique.mockResolvedValue(buildUser());

      await service.resetPassword({
        token: validToken,
        newPassword: 'newPassword123',
        confirmPassword: 'newPassword123',
      });

      expect(prisma.passwordResetToken.findUnique).toHaveBeenCalledWith({
        where: { tokenHash: hashToken(validToken) },
      });
    });
  });

  describe('verifyEmail', () => {
    const validToken = 'b'.repeat(64);

    const validVerificationRecord = () => ({
      id: 'verify-1',
      tokenHash: hashToken(validToken),
      userId: 'user-1',
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      usedAt: null,
      createdAt: new Date(),
    });

    it('marks the email as verified and consumes the token', async () => {
      prisma.emailVerificationToken.findUnique.mockResolvedValue(
        validVerificationRecord(),
      );
      prisma.user.findUnique.mockResolvedValue(buildUser());

      const result = await service.verifyEmail(validToken);

      expect(result).toEqual({ message: 'Email confirmed successfully' });
      expect(
        firstCallArg<{ data: { emailVerifiedAt: Date } }>(prisma.user.update)
          .data.emailVerifiedAt,
      ).toEqual(expect.any(Date));
      expect(
        firstCallArg<{ data: { usedAt: Date } }>(
          prisma.emailVerificationToken.update,
        ).data.usedAt,
      ).toEqual(expect.any(Date));
    });

    it('is idempotent for an already confirmed email', async () => {
      prisma.emailVerificationToken.findUnique.mockResolvedValue(
        validVerificationRecord(),
      );
      prisma.user.findUnique.mockResolvedValue(
        buildUser({ emailVerifiedAt: new Date() }),
      );

      const result = await service.verifyEmail(validToken);

      expect(result).toEqual({ message: 'Email already confirmed' });
      expect(prisma.$transaction).not.toHaveBeenCalled();
    });

    it('rejects an unknown token', async () => {
      prisma.emailVerificationToken.findUnique.mockResolvedValue(null);

      await expect(service.verifyEmail(validToken)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('rejects an expired token', async () => {
      prisma.emailVerificationToken.findUnique.mockResolvedValue({
        ...validVerificationRecord(),
        expiresAt: new Date(Date.now() - 1000),
      });

      await expect(service.verifyEmail(validToken)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('rejects a token that was already used', async () => {
      prisma.emailVerificationToken.findUnique.mockResolvedValue({
        ...validVerificationRecord(),
        usedAt: new Date(),
      });

      await expect(service.verifyEmail(validToken)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('resendVerificationEmail', () => {
    it('sends a fresh link to an unconfirmed account', async () => {
      prisma.user.findUnique.mockResolvedValue(buildUser());
      prisma.emailVerificationToken.updateMany.mockResolvedValue({ count: 1 });
      prisma.emailVerificationToken.create.mockResolvedValue({});

      await service.resendVerificationEmail('user@example.com');

      expect(emailService.sendEmailVerificationEmail).toHaveBeenCalledTimes(1);
      expect(prisma.emailVerificationToken.updateMany).toHaveBeenCalled();
    });

    it('does nothing for an already confirmed account', async () => {
      prisma.user.findUnique.mockResolvedValue(
        buildUser({ emailVerifiedAt: new Date() }),
      );

      await service.resendVerificationEmail('user@example.com');

      expect(emailService.sendEmailVerificationEmail).not.toHaveBeenCalled();
    });

    it('does not leak whether the email exists', async () => {
      prisma.user.findUnique.mockResolvedValue(null);
      const unknown =
        await service.resendVerificationEmail('nobody@example.com');

      prisma.user.findUnique.mockResolvedValue(
        buildUser({ emailVerifiedAt: new Date() }),
      );
      const confirmed =
        await service.resendVerificationEmail('user@example.com');

      expect(unknown).toEqual(confirmed);
      expect(emailService.sendEmailVerificationEmail).not.toHaveBeenCalled();
    });
  });

  describe('changePassword', () => {
    it('changes the password when the current one is correct', async () => {
      const password = await bcrypt.hash('oldPassword123', 10);
      prisma.user.findUnique.mockResolvedValue(buildUser({ password }));

      const result = await service.changePassword('user-1', {
        currentPassword: 'oldPassword123',
        newPassword: 'newPassword123',
        confirmPassword: 'newPassword123',
      });

      expect(result).toEqual({ message: 'Password changed successfully' });
      const { data } = firstCallArg<{
        data: { password: string; mustChangePassword: boolean };
      }>(prisma.user.update);
      await expect(
        bcrypt.compare('newPassword123', data.password),
      ).resolves.toBe(true);
      expect(data.mustChangePassword).toBe(false);
    });

    it('rejects an incorrect current password', async () => {
      const password = await bcrypt.hash('oldPassword123', 10);
      prisma.user.findUnique.mockResolvedValue(buildUser({ password }));

      await expect(
        service.changePassword('user-1', {
          currentPassword: 'wrong-password',
          newPassword: 'newPassword123',
          confirmPassword: 'newPassword123',
        }),
      ).rejects.toThrow(BadRequestException);

      expect(prisma.user.update).not.toHaveBeenCalled();
    });

    it('rejects mismatched passwords', async () => {
      await expect(
        service.changePassword('user-1', {
          currentPassword: 'oldPassword123',
          newPassword: 'newPassword123',
          confirmPassword: 'differentPassword',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('requires the current password unless mustChangePassword is set', async () => {
      prisma.user.findUnique.mockResolvedValue(buildUser());

      await expect(
        service.changePassword('user-1', {
          newPassword: 'newPassword123',
          confirmPassword: 'newPassword123',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('skips the current password check for a forced change', async () => {
      prisma.user.findUnique.mockResolvedValue(
        buildUser({ mustChangePassword: true }),
      );

      const result = await service.changePassword('user-1', {
        newPassword: 'newPassword123',
        confirmPassword: 'newPassword123',
      });

      expect(result).toEqual({ message: 'Password changed successfully' });
      expect(
        firstCallArg<{ data: { mustChangePassword: boolean } }>(
          prisma.user.update,
        ).data.mustChangePassword,
      ).toBe(false);
    });
  });

  describe('me', () => {
    it('returns the profile without the password hash', async () => {
      prisma.user.findUnique.mockResolvedValue(buildUser());

      const result = await service.me('user-1');

      expect(result).not.toHaveProperty('password');
      expect(result.email).toBe('user@example.com');
      expect(result).toHaveProperty('emailVerifiedAt');
    });

    it('rejects an unknown user', async () => {
      prisma.user.findUnique.mockResolvedValue(null);

      await expect(service.me('missing')).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
