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

  async refreshToken(userId: string, email: string, role: string) {
    const tokens = await this.generateTokens(userId, email, role);
    return {
      accessToken: tokens.accessToken,
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

  async googleLogin(googleUser: {
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

  private async generateTokens(userId: string, email: string, role: string) {
    const payload = { sub: userId, email, role };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_SECRET'),
        expiresIn: this.configService.get('JWT_EXPIRES_IN') ?? '15m',
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get('JWT_REFRESH_EXPIRES_IN') ?? '7d',
      }),
    ]);

    return { accessToken, refreshToken };
  }

  generateTemporaryPassword(): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    const special = '!@#$%&*';
    let password = '';

    for (let i = 0; i < 8; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    password += special.charAt(Math.floor(Math.random() * special.length));
    password += Math.floor(Math.random() * 10);

    return password
      .split('')
      .sort(() => Math.random() - 0.5)
      .join('');
  }
}
