import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import { PrismaService } from '../prisma/prisma.service';
import { EmailService } from '../email/email.service';
import { AuthProvider } from '../generated/prisma/client';
import { LoginDto, ChangePasswordDto, ForgotPasswordDto } from './dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  private readonly googleClient: OAuth2Client;

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private emailService: EmailService,
  ) {
    this.googleClient = new OAuth2Client(
      this.configService.get<string>('GOOGLE_CLIENT_ID'),
    );
  }

  async me(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      profileImageUrl: user.profileImageUrl,
      mustChangePassword: user.mustChangePassword,
    };
  }

  async login(loginDto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: loginDto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    const isPasswordValid = await bcrypt.compare(
      loginDto.password,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    const tokens = await this.generateTokens(user.id, user.email, user.role);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        profileImageUrl: user.profileImageUrl,
        mustChangePassword: user.mustChangePassword,
      },
    };
  }

  async refreshToken(
    userId: string,
    email: string,
    role: string,
    rawRefreshToken: string,
  ) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawRefreshToken)
      .digest('hex');

    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
    });

    if (!storedToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (storedToken.revoked) {
      await this.prisma.refreshToken.updateMany({
        where: { familyId: storedToken.familyId },
        data: { revoked: true },
      });
      throw new UnauthorizedException('Refresh token reuse detected');
    }

    await this.prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: { revoked: true },
    });

    const tokens = await this.generateTokens(
      userId,
      email,
      role,
      storedToken.familyId,
    );

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async changePassword(userId: string, dto: ChangePasswordDto) {
    if (dto.newPassword !== dto.confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.mustChangePassword && dto.currentPassword) {
      const isCurrentValid = await bcrypt.compare(
        dto.currentPassword,
        user.password,
      );
      if (!isCurrentValid) {
        throw new BadRequestException('Current password is incorrect');
      }
    } else if (!user.mustChangePassword && !dto.currentPassword) {
      throw new BadRequestException('Current password is required');
    }

    const hashedPassword = await bcrypt.hash(dto.newPassword, 10);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        password: hashedPassword,
        mustChangePassword: false,
      },
    });

    return { message: 'Password changed successfully' };
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (user && user.isActive) {
      const temporaryPassword = this.generateTemporaryPassword();
      const hashedPassword = await bcrypt.hash(temporaryPassword, 10);

      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashedPassword,
          mustChangePassword: true,
        },
      });

      try {
        await this.emailService.sendPasswordRecoveryEmail(
          user.email,
          user.firstName,
          temporaryPassword,
        );
      } catch (error) {
        this.logger.error(
          `Failed to send recovery email to ${dto.email}`,
          error,
        );
      }
    }

    return {
      message:
        'If the email exists, you will receive a password recovery email',
    };
  }

  async verifyGoogleIdToken(idToken: string) {
    try {
      const ticket = await this.googleClient.verifyIdToken({
        idToken,
        audience: this.configService.get<string>('GOOGLE_CLIENT_ID'),
      });

      const payload = ticket.getPayload();
      if (!payload || !payload.email) {
        throw new UnauthorizedException('Invalid Google ID token');
      }

      return this.googleLogin({
        googleId: payload.sub,
        email: payload.email,
        firstName: payload.given_name ?? '',
        lastName: payload.family_name ?? '',
        profileImageUrl: payload.picture ?? null,
      });
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;
      this.logger.error('Google ID token verification failed', error);
      throw new UnauthorizedException('Invalid Google ID token');
    }
  }

  async upsertGoogleUser(googleUser: {
    googleId: string;
    email: string;
    firstName: string;
    lastName: string;
    profileImageUrl?: string | null;
  }) {
    let user = await this.prisma.user.findFirst({
      where: {
        OR: [{ googleId: googleUser.googleId }, { email: googleUser.email }],
      },
    });

    if (user && !user.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    if (user) {
      user = await this.prisma.user.update({
        where: { id: user.id },
        data: {
          googleId: user.googleId ?? googleUser.googleId,
          profileImageUrl: googleUser.profileImageUrl ?? user.profileImageUrl,
          lastLoginAt: new Date(),
        },
      });
    } else {
      const randomPassword = crypto.randomBytes(32).toString('hex');
      const hashedPassword = await bcrypt.hash(randomPassword, 10);

      user = await this.prisma.user.create({
        data: {
          email: googleUser.email,
          password: hashedPassword,
          firstName: googleUser.firstName,
          lastName: googleUser.lastName,
          googleId: googleUser.googleId,
          profileImageUrl: googleUser.profileImageUrl ?? null,
          authProvider: AuthProvider.GOOGLE,
          mustChangePassword: false,
          lastLoginAt: new Date(),
        },
      });
    }

    return user;
  }

  async googleLogin(googleUser: {
    googleId: string;
    email: string;
    firstName: string;
    lastName: string;
    profileImageUrl?: string | null;
  }) {
    const user = await this.upsertGoogleUser(googleUser);

    const tokens = await this.generateTokens(user.id, user.email, user.role);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        profileImageUrl: user.profileImageUrl,
        mustChangePassword: user.mustChangePassword,
      },
    };
  }

  async createAuthCode(userId: string): Promise<string> {
    const code = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 1000);

    await this.prisma.authCode.create({
      data: { code, userId, expiresAt },
    });

    return code;
  }

  async exchangeAuthCode(code: string) {
    const authCode = await this.prisma.authCode.findUnique({
      where: { code },
    });

    if (!authCode || authCode.used || authCode.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired auth code');
    }

    await this.prisma.authCode.update({
      where: { id: authCode.id },
      data: { used: true },
    });

    const user = await this.prisma.user.findUnique({
      where: { id: authCode.userId },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const tokens = await this.generateTokens(user.id, user.email, user.role);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        profileImageUrl: user.profileImageUrl,
        mustChangePassword: user.mustChangePassword,
      },
    };
  }

  async revokeRefreshToken(rawToken: string) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');
    await this.prisma.refreshToken.updateMany({
      where: { tokenHash },
      data: { revoked: true },
    });
  }

  private async storeRefreshToken(
    token: string,
    userId: string,
    familyId: string,
    expiresAt: Date,
  ) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await this.prisma.refreshToken.create({
      data: { tokenHash, userId, familyId, expiresAt, revoked: false },
    });
  }

  private async generateTokens(
    userId: string,
    email: string,
    role: string,
    familyId?: string,
  ) {
    const payload = { sub: userId, email, role };
    const family = familyId ?? crypto.randomUUID();

    const refreshExpiresIn =
      this.configService.get('JWT_REFRESH_EXPIRES_IN') ?? '7d';

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_SECRET'),
        expiresIn: this.configService.get('JWT_EXPIRES_IN') ?? '15m',
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: refreshExpiresIn,
      }),
    ]);

    const ms = this.parseExpiresIn(refreshExpiresIn);
    const expiresAt = new Date(Date.now() + ms);
    await this.storeRefreshToken(refreshToken, userId, family, expiresAt);

    return { accessToken, refreshToken, familyId: family };
  }

  private parseExpiresIn(value: string): number {
    const match = value.match(/^(\d+)([smhd])$/);
    if (!match) return 7 * 24 * 60 * 60 * 1000;
    const num = parseInt(match[1], 10);
    const unit = match[2];
    const multipliers: Record<string, number> = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
    };
    return num * (multipliers[unit] ?? 24 * 60 * 60 * 1000);
  }

  generateTemporaryPassword(): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    const special = '!@#$%&*';
    const result: string[] = [];

    for (let i = 0; i < 8; i++) {
      result.push(chars.charAt(crypto.randomInt(chars.length)));
    }

    result.push(special.charAt(crypto.randomInt(special.length)));
    result.push(String(crypto.randomInt(10)));

    // Fisher-Yates shuffle
    for (let i = result.length - 1; i > 0; i--) {
      const j = crypto.randomInt(i + 1);
      [result[i], result[j]] = [result[j], result[i]];
    }

    return result.join('');
  }
}
