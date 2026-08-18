import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { EmailModule } from './email/email.module';
import { CsrfGuard, OriginGuard, SessionThrottlerGuard } from './common/guards';

@Module({
  imports: [
    ConfigModule.forRoot({ envFilePath: ['.env'], isGlobal: true }),
    // Generous by design: this is the catch-all ceiling, and behind a BFF a
    // single page view can mean several calls. The endpoints that actually need
    // tight limits (login, password reset) set their own via @Throttle.
    ThrottlerModule.forRoot([{ ttl: 60000, limit: 120 }]),
    PrismaModule,
    AuthModule,
    UsersModule,
    EmailModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: SessionThrottlerGuard,
    },
    {
      // CSRF layer 3: browsers stamp Sec-Fetch-Site themselves and a page
      // cannot forge it, which closes the sibling-subdomain gap SameSite leaves.
      provide: APP_GUARD,
      useClass: OriginGuard,
    },
    {
      // CSRF layer 1: double-submit token. Registered globally so a new
      // controller cannot forget it.
      provide: APP_GUARD,
      useClass: CsrfGuard,
    },
  ],
})
export class AppModule {}
