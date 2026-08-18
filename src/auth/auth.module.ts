import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { SessionService } from './session/session.service';
import { SessionGuard } from './guards/session.guard';
import { GoogleStrategy } from './strategies/google.strategy';
import { EmailModule } from '../email/email.module';

@Module({
  imports: [PassportModule, EmailModule],
  controllers: [AuthController],
  providers: [AuthService, SessionService, SessionGuard, GoogleStrategy],
  exports: [AuthService, SessionService, SessionGuard],
})
export class AuthModule {}
