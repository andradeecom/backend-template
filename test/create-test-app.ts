import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import { AppModule } from '../src/app.module';
import { EmailService } from '../src/email/email.service';
import { PrismaService } from '../src/prisma/prisma.service';
import { PrismaMock, asPrismaService } from './prisma.mock';

/**
 * Boots the real application graph with only its two external edges replaced:
 * Postgres (PrismaMock) and Resend (a no-op stub). Everything the e2e suite
 * actually asserts on — guards, pipes, cookie handling, routing — is the
 * production code path.
 *
 * The global prefix and ValidationPipe are applied here to match main.ts.
 * They live in bootstrap() rather than AppModule, so a test app that skipped
 * them would exercise different middleware than production and quietly pass
 * while real requests failed.
 */
export interface TestApp {
  app: INestApplication;
  prisma: PrismaMock;
  email: { [K in keyof EmailService]?: jest.Mock };
}

export const createTestApp = async (): Promise<TestApp> => {
  const prisma = new PrismaMock();

  // Names must match EmailService exactly. A stub with a wrong name silently
  // fails to intercept, and the real Resend client would be constructed and
  // called instead — so these are asserted against the class below.
  const email = {
    sendWelcomeEmail: jest.fn().mockResolvedValue(undefined),
    sendPasswordResetEmail: jest.fn().mockResolvedValue(undefined),
    sendEmailVerificationEmail: jest.fn().mockResolvedValue(undefined),
    sendPasswordRecoveryEmail: jest.fn().mockResolvedValue(undefined),
  };

  const moduleFixture = await Test.createTestingModule({
    imports: [AppModule],
  })
    .overrideProvider(PrismaService)
    .useValue(asPrismaService(prisma))
    .overrideProvider(EmailService)
    .useValue(email)
    .compile();

  const app = moduleFixture.createNestApplication();

  app.use(cookieParser());
  app.setGlobalPrefix('api');
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  await app.init();

  return { app, prisma, email };
};
