import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(cookieParser());
  app.setGlobalPrefix('api');

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
    .setVersion('0.1.0')
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
