import { PrismaService } from '../src/prisma/prisma.service';

/**
 * In-memory stand-in for PrismaService.
 *
 * The e2e suite exercises the HTTP surface — guards, pipes, cookies, status
 * codes — not Prisma's query planner. Running it against a real database would
 * mean CI provisions Postgres, applies migrations, and cleans between tests,
 * all to assert things that have nothing to do with storage.
 *
 * So the store is a Map per model. It implements only the operations the app
 * actually calls, and deliberately throws on anything else rather than
 * returning undefined — a silent undefined turns into a confusing failure three
 * layers away, while a throw names the missing method immediately.
 */

type Row = Record<string, unknown>;

interface Where {
  [key: string]: unknown;
}

const matches = (row: Row, where: Where | undefined): boolean => {
  if (!where) return true;

  return Object.entries(where).every(([key, expected]) => {
    if (expected === undefined) return true;

    // Nested operators we actually use: { lt: date }, { not: null }, { in: [] }.
    if (expected !== null && typeof expected === 'object') {
      const op = expected as Record<string, unknown>;
      const actual = row[key];

      if ('lt' in op) return (actual as number) < (op.lt as number);
      if ('gt' in op) return (actual as number) > (op.gt as number);
      if ('not' in op) return actual !== op.not;
      if ('in' in op) return (op.in as unknown[]).includes(actual);
      return false;
    }

    return row[key] === expected;
  });
};

class ModelStore {
  private rows: Row[] = [];
  private seq = 0;

  constructor(private readonly name: string) {}

  private id(): string {
    this.seq += 1;
    return `${this.name}-${this.seq}`;
  }

  create({ data }: { data: Row }): Row {
    const row = { id: this.id(), createdAt: new Date(), ...data };
    this.rows.push(row);
    return { ...row };
  }

  findUnique({ where }: { where: Where }): Row | null {
    const found = this.rows.find((r) => matches(r, where));
    return found ? { ...found } : null;
  }

  findFirst({ where }: { where?: Where } = {}): Row | null {
    const found = this.rows.find((r) => matches(r, where));
    return found ? { ...found } : null;
  }

  findMany({ where }: { where?: Where } = {}): Row[] {
    return this.rows.filter((r) => matches(r, where)).map((r) => ({ ...r }));
  }

  update({ where, data }: { where: Where; data: Row }): Row {
    const row = this.rows.find((r) => matches(r, where));
    if (!row) {
      // Mirrors Prisma: updating a missing row is an error, not a no-op.
      throw new Error(
        `${this.name}.update: no row matching ${JSON.stringify(where)}`,
      );
    }
    Object.assign(row, data);
    return { ...row };
  }

  updateMany({ where, data }: { where?: Where; data: Row }): { count: number } {
    const found = this.rows.filter((r) => matches(r, where));
    found.forEach((r) => Object.assign(r, data));
    return { count: found.length };
  }

  delete({ where }: { where: Where }): Row {
    const index = this.rows.findIndex((r) => matches(r, where));
    if (index === -1) {
      throw new Error(
        `${this.name}.delete: no row matching ${JSON.stringify(where)}`,
      );
    }
    return { ...this.rows.splice(index, 1)[0] };
  }

  deleteMany({ where }: { where?: Where } = {}): { count: number } {
    const before = this.rows.length;
    this.rows = this.rows.filter((r) => !matches(r, where));
    return { count: before - this.rows.length };
  }

  count({ where }: { where?: Where } = {}): number {
    return this.rows.filter((r) => matches(r, where)).length;
  }

  /** Test helpers — not part of the Prisma surface. */
  seed(rows: Row[]): void {
    rows.forEach((row) => this.rows.push({ ...row }));
  }

  reset(): void {
    this.rows = [];
    this.seq = 0;
  }
}

export class PrismaMock {
  readonly user = new ModelStore('user');
  readonly session = new ModelStore('session');
  readonly passwordResetToken = new ModelStore('passwordResetToken');
  readonly emailVerificationToken = new ModelStore('emailVerificationToken');

  private readonly stores = [
    this.user,
    this.session,
    this.passwordResetToken,
    this.emailVerificationToken,
  ];

  /**
   * SessionService.rotate() relies on $transaction for its race handling, so it
   * has to exist. There is no isolation to simulate here — the mock is
   * single-threaded and synchronous — so it just runs the callback, or resolves
   * the array form.
   */
  async $transaction<T>(
    arg: ((tx: PrismaMock) => Promise<T>) | Promise<T>[],
  ): Promise<T | T[]> {
    if (Array.isArray(arg)) return Promise.all(arg);
    return arg(this);
  }

  async $disconnect(): Promise<void> {}

  /** Clear every table. Called between tests so they cannot leak into each other. */
  reset(): void {
    this.stores.forEach((s) => s.reset());
  }
}

/**
 * ModelStore methods are synchronous but the app awaits them. Awaiting a
 * non-promise is fine, so no wrapping is needed — this alias just keeps the
 * cast in one place and documents why it is safe.
 */
export const asPrismaService = (mock: PrismaMock): PrismaService =>
  mock as unknown as PrismaService;
