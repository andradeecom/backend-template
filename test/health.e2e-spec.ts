import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { createTestApp } from './create-test-app';

describe('Health check (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    ({ app } = await createTestApp());
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /api/healthcheck returns 200', async () => {
    const res = await request(app.getHttpServer() as App).get(
      '/api/healthcheck',
    );

    expect(res.status).toBe(200);
    expect(res.body).toBeDefined();
  });

  // The global prefix is applied in bootstrap(), not in AppModule. A test that
  // only ever hits prefixed paths would not notice if it were dropped.
  it('serves nothing at the unprefixed path', async () => {
    await request(app.getHttpServer() as App)
      .get('/healthcheck')
      .expect(404);
  });
});
