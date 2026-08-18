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
import { ApiTags, ApiOperation, ApiCookieAuth } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { SessionService } from './session/session.service';
import {
  LoginDto,
  RegisterDto,
  ChangePasswordDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  VerifyEmailDto,
  ResendVerificationDto,
  GoogleLoginDto,
  ExchangeCodeDto,
} from './dto';
import { SessionGuard } from './guards/session.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { CurrentUser, Public } from '../common/decorators';
import { Throttle } from '@nestjs/throttler';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly sessionService: SessionService,
  ) {}

  /**
   * Mints a fresh session and plants the opaque id in an httpOnly cookie.
   *
   * The id is always newly generated and never taken from the incoming
   * request, which is what defeats session fixation.
   */
  private async startSession(
    userId: string,
    req: Request,
    res: Response,
  ): Promise<void> {
    const { rawId, expiresAt } = await this.sessionService.create(userId, req);
    this.sessionService.writeCookie(res, rawId, expiresAt);
  }

  @Get('me')
  @UseGuards(SessionGuard)
  @ApiCookieAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get current user' })
  async me(@CurrentUser('id') userId: string) {
    return this.authService.me(userId);
  }

  @Post('register')
  @Public()
  @Throttle({ default: { ttl: 60000, limit: 5 } })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Register a new account',
    description:
      'Creates a STUDENT account and sends a confirmation email. ' +
      'The role is fixed server-side — elevated roles are assigned by an admin via POST /users.',
  })
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  @Public()
  @Throttle({ default: { ttl: 60000, limit: 5 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Login with email and password',
    description:
      'On success the session id is returned only as an httpOnly cookie. ' +
      'No token is present in the response body — the client cannot read the credential.',
  })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(loginDto);
    await this.startSession(result.user.id, req, res);

    return { user: result.user };
  }

  @Post('change-password')
  @UseGuards(SessionGuard)
  @ApiCookieAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Change user password',
    description:
      'Signs out every other device and issues the caller a fresh session id.',
  })
  async changePassword(
    @CurrentUser('id') userId: string,
    @Body() dto: ChangePasswordDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.changePassword(userId, dto);

    // The service revoked every session for this user, including this one.
    // Re-issue so the caller is not logged out by their own password change.
    await this.startSession(userId, req, res);

    return result;
  }

  @Post('forgot-password')
  @Public()
  @Throttle({ default: { ttl: 60000, limit: 3 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Request a password reset link via email',
    description:
      'Always returns the same response whether or not the email exists.',
  })
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  @Post('reset-password')
  @Public()
  @Throttle({ default: { ttl: 60000, limit: 5 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reset password using the emailed token',
    description:
      'Consumes the single-use token and revokes all existing sessions.',
  })
  async resetPassword(
    @Body() dto: ResetPasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.resetPassword(dto);
    // Every session for this user is gone; drop the caller's stale cookie too.
    this.sessionService.clearCookie(res);
    return result;
  }

  @Post('verify-email')
  @Public()
  @Throttle({ default: { ttl: 60000, limit: 10 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Confirm an email address using the emailed token' })
  async verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.authService.verifyEmail(dto.token);
  }

  @Post('resend-verification')
  @Public()
  @Throttle({ default: { ttl: 60000, limit: 3 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Resend the email confirmation link',
    description:
      'Always returns the same response whether or not the email exists.',
  })
  async resendVerification(@Body() dto: ResendVerificationDto) {
    return this.authService.resendVerificationEmail(dto.email);
  }

  @Post('logout')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Logout',
    description:
      'Deletes the session row, so the credential dies instantly and everywhere ' +
      'rather than waiting for a token to expire.',
  })
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const cookies = req.cookies as Record<string, string | undefined>;
    const rawId = cookies?.[this.sessionService.cookieName];

    if (rawId) {
      await this.sessionService.revoke(rawId);
    }

    this.sessionService.clearCookie(res);

    return { message: 'Logged out successfully' };
  }

  @Post('logout-all')
  @UseGuards(SessionGuard)
  @ApiCookieAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Logout from every device',
    description: 'Deletes every session row belonging to the current user.',
  })
  async logoutAll(
    @CurrentUser('id') userId: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.sessionService.revokeAllForUser(userId);
    this.sessionService.clearCookie(res);
    return { message: 'Logged out from all devices' };
  }

  // ─── Google Social Login ────────────────────────────────────────────

  @Post('google/token')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[Mobile] Google login via ID token',
    description:
      'For mobile clients (React Native / Expo). ' +
      'The client obtains a Google ID token using the native Google Sign-In SDK ' +
      'and sends it here. The backend verifies it with Google and starts a session.',
  })
  async googleTokenLogin(
    @Body() dto: GoogleLoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.verifyGoogleIdToken(dto.idToken);
    await this.startSession(result.user.id, req, res);

    return { user: result.user };
  }

  @Get('google')
  @Public()
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
  @Public()
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
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[Web] Exchange auth code for a session',
    description:
      'Exchanges a single-use authorization code (from the Google OAuth callback) ' +
      'for an httpOnly session cookie.',
  })
  async exchangeGoogleCode(
    @Body() dto: ExchangeCodeDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.exchangeAuthCode(dto.code);
    await this.startSession(result.user.id, req, res);

    return { user: result.user };
  }
}
