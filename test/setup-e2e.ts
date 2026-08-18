/**
 * Runs before any module under test is imported (jest-e2e.json `setupFiles`).
 *
 * The suite needs exactly one environment value. GoogleStrategy builds a
 * passport-oauth2 strategy in its constructor, and that constructor throws
 * `OAuth2Strategy requires a clientID option` when clientID is absent — so
 * AppModule cannot be instantiated without it. clientSecret and callbackURL
 * are not validated, and nothing else in the suite reads env: Prisma and
 * Resend are replaced with test doubles before any call reaches them.
 *
 * If a new test needs another value, set it here rather than reintroducing a
 * .env.test — this way the list stays honest about what is actually required.
 */
process.env.GOOGLE_CLIENT_ID ??= 'test-google-client-id';
