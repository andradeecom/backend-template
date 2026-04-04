import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Req,
  Res,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import {
  LoginDto,
  ChangePasswordDto,
  ForgotPasswordDto,
  GoogleLoginDto,
  ExchangeCodeDto,
} from './dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { CurrentUser } from '../common/decorators';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get current user' })
  async me(@CurrentUser('id') userId: string) {
    return this.authService.me(userId);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login with email and password' })
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(loginDto);

    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @Post('refresh')
  @UseGuards(JwtRefreshGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  async refresh(
    @CurrentUser()
    user: { id: string; email: string; role: string; rawRefreshToken: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.refreshToken(
      user.id,
      user.email,
      user.role,
      user.rawRefreshToken,
    );

    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return { accessToken: result.accessToken };
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Change user password' })
  async changePassword(
    @CurrentUser('id') userId: string,
    @Body() dto: ChangePasswordDto,
  ) {
    return this.authService.changePassword(userId, dto);
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Request password reset via email' })
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout and clear refresh token' })
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const rawToken = req.cookies?.['refresh_token'];
    if (rawToken) {
      await this.authService.revokeRefreshToken(rawToken);
    }

    res.clearCookie('access_token', {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    });
    res.clearCookie('user_data', {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    });
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    });

    return { message: 'Logged out successfully' };
  }

  // ─── Google Social Login ────────────────────────────────────────────

  @Post('google/token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[Mobile] Google login via ID token',
    description:
      'For mobile clients (React Native / Expo). ' +
      'The client obtains a Google ID token using the native Google Sign-In SDK ' +
      'and sends it here. The backend verifies the token with Google and issues JWT tokens.',
  })
  async googleTokenLogin(
    @Body() dto: GoogleLoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.verifyGoogleIdToken(dto.idToken);

    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @Get('google')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({
    summary: '[Web] Initiate Google OAuth2 redirect',
    description:
      'For web clients. Redirects the user to the Google consent screen. ' +
      'After granting permission, Google redirects back to GET /auth/google/callback.',
  })
  async googleRedirect() {
    // Guard redirects to Google automatically
  }

  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({
    summary: '[Web] Google OAuth2 callback',
    description:
      'Handles the redirect from Google after user consent. ' +
      'Generates a single-use auth code and redirects to the frontend.',
  })
  async googleCallback(@Req() req: Request, @Res() res: Response) {
    const googleUser = req.user as {
      googleId: string;
      email: string;
      firstName: string;
      lastName: string;
      profileImageUrl?: string | null;
    };

    const user = await this.authService.upsertGoogleUser(googleUser);
    const authCode = await this.authService.createAuthCode(user.id);

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const allowedLocales = ['en', 'es', 'pt'];
    const state = (req.query as Record<string, string>).state;
    const lang = allowedLocales.includes(state) ? state : 'en';

    res.redirect(
      `${frontendUrl}/${lang}/auth/google/callback?code=${authCode}`,
    );
  }

  @Post('google/exchange')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[Web] Exchange auth code for tokens',
    description:
      'Exchanges a single-use authorization code (from Google OAuth callback) ' +
      'for access and refresh tokens.',
  })
  async exchangeGoogleCode(
    @Body() dto: ExchangeCodeDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.exchangeAuthCode(dto.code);

    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }
}
