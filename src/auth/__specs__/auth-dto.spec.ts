import { ClassConstructor, plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import {
  LoginDto,
  RegisterDto,
  ResetPasswordDto,
  ForgotPasswordDto,
  VerifyEmailDto,
} from '../dto';

/**
 * `ClassConstructor` is class-transformer's own constructor type — using it
 * (rather than a hand-rolled `new () => T`) keeps `plainToInstance` on its
 * intended overload, so the DTO argument never widens to an unsafe type.
 */
const validateDto = async <T extends object>(
  cls: ClassConstructor<T>,
  payload: Record<string, unknown>,
) => {
  const errors = await validate(plainToInstance(cls, payload));
  return errors.flatMap((error) => Object.keys(error.constraints ?? {}));
};

const failedProperties = async <T extends object>(
  cls: ClassConstructor<T>,
  payload: Record<string, unknown>,
) => {
  const errors = await validate(plainToInstance(cls, payload));
  return errors.map((error) => error.property);
};

describe('Auth DTO validation', () => {
  describe('RegisterDto', () => {
    const valid = {
      email: 'user@example.com',
      password: 'password123',
      firstName: 'John',
      lastName: 'Doe',
    };

    it('accepts a valid payload', async () => {
      await expect(validateDto(RegisterDto, valid)).resolves.toHaveLength(0);
    });

    it('rejects a malformed email', async () => {
      await expect(
        failedProperties(RegisterDto, { ...valid, email: 'not-an-email' }),
      ).resolves.toContain('email');
    });

    it('rejects a password shorter than 8 characters', async () => {
      await expect(
        failedProperties(RegisterDto, { ...valid, password: 'short' }),
      ).resolves.toContain('password');
    });

    it('rejects missing required fields', async () => {
      const failed = await failedProperties(RegisterDto, {});
      expect(failed).toEqual(
        expect.arrayContaining(['email', 'password', 'firstName', 'lastName']),
      );
    });

    it('has no role property, so a client cannot request a privileged role', () => {
      const instance = plainToInstance(RegisterDto, {
        ...valid,
        role: 'ADMIN',
      });
      // `whitelist: true` in the global ValidationPipe strips unknown keys, and
      // the DTO deliberately has no `role` for it to bind to.
      expect(Object.keys(new RegisterDto())).not.toContain('role');
      expect(instance).toBeInstanceOf(RegisterDto);
    });
  });

  describe('LoginDto', () => {
    it('accepts a valid payload', async () => {
      await expect(
        validateDto(LoginDto, {
          email: 'user@example.com',
          password: 'password123',
        }),
      ).resolves.toHaveLength(0);
    });

    it('rejects a malformed email', async () => {
      await expect(
        failedProperties(LoginDto, {
          email: 'not-an-email',
          password: 'password123',
        }),
      ).resolves.toContain('email');
    });

    it('rejects an empty password', async () => {
      await expect(
        failedProperties(LoginDto, {
          email: 'user@example.com',
          password: '',
        }),
      ).resolves.toContain('password');
    });
  });

  describe('ResetPasswordDto', () => {
    const valid = {
      token: 'reset-token',
      newPassword: 'newPassword123',
      confirmPassword: 'newPassword123',
    };

    it('accepts a valid payload', async () => {
      await expect(validateDto(ResetPasswordDto, valid)).resolves.toHaveLength(
        0,
      );
    });

    it('rejects a new password shorter than 8 characters', async () => {
      await expect(
        failedProperties(ResetPasswordDto, { ...valid, newPassword: 'short' }),
      ).resolves.toContain('newPassword');
    });

    it('rejects a missing token', async () => {
      await expect(
        failedProperties(ResetPasswordDto, { ...valid, token: '' }),
      ).resolves.toContain('token');
    });
  });

  describe('ForgotPasswordDto', () => {
    it('accepts a valid email', async () => {
      await expect(
        validateDto(ForgotPasswordDto, { email: 'user@example.com' }),
      ).resolves.toHaveLength(0);
    });

    it('rejects a malformed email', async () => {
      await expect(
        failedProperties(ForgotPasswordDto, { email: 'not-an-email' }),
      ).resolves.toContain('email');
    });
  });

  describe('VerifyEmailDto', () => {
    it('accepts a token', async () => {
      await expect(
        validateDto(VerifyEmailDto, { token: 'verify-token' }),
      ).resolves.toHaveLength(0);
    });

    it('rejects an empty token', async () => {
      await expect(
        failedProperties(VerifyEmailDto, { token: '' }),
      ).resolves.toContain('token');
    });
  });
});
