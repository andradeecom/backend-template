import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { Logger, ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const logger = new Logger('Bootstrap');

  app.use(cookieParser());
  app.setGlobalPrefix('api');

  /*
   * Which upstream proxies may be believed when they say who the client is.
   *
   * `X-Forwarded-For` is client-supplied and *appended to* by each proxy, so
   * only the right-most entries are trustworthy. Express walks it right-to-left
   * and stops at the first untrusted address, which becomes `req.ip` — the key
   * anonymous rate limiting uses. Never parse that header by hand.
   *
   * Accepts a CIDR/IP allow-list (preferred: trust pinned to addresses, immune
   * to hop-count drift) or a hop count. Unset means no proxy — the header is
   * ignored, which is the safe default. `true` is deliberately unsupported: it
   * lands on the left-most, attacker-controlled entry.
   *
   * Setup, and the firewall rules this all depends on: docs/deployment.md
   */
  const trustedProxies = process.env.TRUSTED_PROXIES?.trim();

  if (trustedProxies) {
    const asHopCount = Number(trustedProxies);
    app.set(
      'trust proxy',
      Number.isInteger(asHopCount) && asHopCount > 0
        ? asHopCount
        : trustedProxies,
    );
  }

  /*
   * Catch the silent misconfiguration: a proxy is forwarding, but this app was
   * told to expect none, so every anonymous caller shares the proxy's address
   * and the rate limits fire far sooner than intended. Warn rather than throw —
   * a stray header should not take the service down.
   */
  if (!trustedProxies) {
    app.use((req, _res, next) => {
      if (req.headers['x-forwarded-for']) {
        logger.warn(
          'X-Forwarded-For received but TRUSTED_PROXIES is unset — anonymous ' +
            'rate limits will bucket every client under the proxy address. ' +
            'Set TRUSTED_PROXIES if this app runs behind a proxy.',
        );
      }
      next();
    });
  }

  // `credentials: true` is what lets the browser send the session cookie, so
  // the allow-list must stay explicit — a wildcard origin would be rejected by
  // the browser here anyway.
  const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
  if (!allowedOrigins.includes(frontendUrl)) allowedOrigins.push(frontendUrl);

  app.enableCors({
    origin: allowedOrigins,
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const config = new DocumentBuilder()
    .setTitle('Backend Template API')
    .setDescription('Template for all backend operations')
    .setVersion('1.0.0')
    // Auth travels as an httpOnly session cookie, never as a bearer token the
    // client could read, so Swagger authenticates by cookie too.
    .addCookieAuth(
      process.env.NODE_ENV === 'production' ? '__Host-session' : 'session',
    )
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  await app.listen(process.env.PORT ?? 3001);

  if (process.env.NODE_ENV === 'development') {
    console.log(
      `Application is running on: http://localhost:${process.env.PORT}`,
    );
    console.log(
      `Swagger is running on: http://localhost:${process.env.PORT}/api/docs`,
    );
  }
}

void bootstrap();
