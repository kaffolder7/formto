import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
const url = process.env.TEST_DATABASE_URL;
test(
  "fresh and existing databases migrate safely",
  { skip: !url },
  async (t) => {
    assert.match(new URL(url).pathname, /test/);
    process.env.DATABASE_URL = url;
    const { default: postgres } = await import("postgres");
    const { migrate } = await import("../utils/migrations.js");
    const { default: defaultPool } = await import("../utils/db.js");
    const admin = postgres(url);
    t.after(async () => {
      await admin.end();
      await defaultPool.end();
    });
    const schema = await readFile(
      new URL("../migrations/001_init.sql", import.meta.url),
      "utf8",
    );
    for (const legacy of [false, true])
      await t.test(
        legacy
          ? "upgrade preserves data and preserves legacy integrations"
          : "fresh bootstrap and concurrent repeated startup",
        async () => {
          const name = `formto_test_${randomBytes(6).toString("hex")}`;
          await admin.unsafe(`CREATE DATABASE ${name}`);
          const target = new URL(url);
          target.pathname = `/${name}`;
          const db = postgres(target.href, { onnotice: () => {} });
          try {
            if (legacy) {
              await db.unsafe(schema);
              const [u] =
                await db`INSERT INTO users(username,password_hash) VALUES('migration-test','unused') RETURNING id`;
              const [f] =
                await db`INSERT INTO forms(user_id,name,endpoint) VALUES(${u.id},'Original','original') RETURNING id`;
              await db`INSERT INTO submissions(form_id,form_endpoint,data) VALUES(${f.id},'original','{"message":"preserved"}')`;
            }
            await Promise.all([migrate(db), migrate(db)]);
            await migrate(db);
            const [version] =
              await db`SELECT COUNT(*)::int AS n FROM schema_migrations`;
            assert.equal(version.n, 1);
            if (legacy) {
              const [f] = await db`SELECT * FROM forms`;
              assert.equal(f.active, true);
              assert.equal(f.submission_mode, "legacy");
              assert.equal(f.hosted_enabled, true);
              assert.equal(f.security_configured, false);
              const [s] = await db`SELECT data FROM submissions`;
              assert.equal(s.data.message, "preserved");
            }
            await db`UPDATE schema_migrations SET checksum='changed'`;
            await assert.rejects(() => migrate(db), /checksum mismatch/);
          } finally {
            await db.end();
            await admin.unsafe(`DROP DATABASE ${name}`);
          }
        },
      );
    await t.test("failed upgrade rolls back schema changes", async () => {
      const name = `formto_test_${randomBytes(6).toString("hex")}`;
      await admin.unsafe(`CREATE DATABASE ${name}`);
      const target = new URL(url);
      target.pathname = `/${name}`;
      const db = postgres(target.href, { onnotice: () => {} });
      try {
        await db.unsafe(schema);
        await db`CREATE TABLE form_daily_usage (conflict BOOLEAN)`;
        await assert.rejects(() => migrate(db));
        const cols =
          await db`SELECT column_name FROM information_schema.columns WHERE table_name='forms' AND column_name='submission_mode'`;
        assert.equal(cols.length, 0);
        const [row] =
          await db`SELECT to_regclass('public.schema_migrations') AS name`;
        assert.equal(row.name, null);
      } finally {
        await db.end();
        await admin.unsafe(`DROP DATABASE ${name}`);
      }
    });
  },
);
