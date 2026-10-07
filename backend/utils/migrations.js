import { readFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import sql from "./db.js";

// Initdb runs only 001 on fresh volumes. This runner owns all upgrades.
export async function migrate(database = sql) {
  await database.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(824617203)`;
    await tx`CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`;
    const [existing] = await tx`SELECT to_regclass('public.users') AS users`;
    if (!existing.users) {
      await tx.unsafe(
        await readFile(
          new URL("../migrations/001_init.sql", import.meta.url),
          "utf8",
        ),
      );
    }
    const directory = new URL("../migrations/upgrades/", import.meta.url);
    const files = (await readdir(directory))
      .filter((name) => /^\d+.*\.sql$/.test(name))
      .sort();
    for (const version of files) {
      const source = await readFile(new URL(version, directory), "utf8");
      const checksum = createHash("sha256").update(source).digest("hex");
      const [applied] =
        await tx`SELECT checksum FROM schema_migrations WHERE version = ${version}`;
      if (applied) {
        if (applied.checksum !== checksum)
          throw new Error(`Migration checksum mismatch: ${version}`);
        continue;
      }
      await tx.unsafe(source);
      await tx`INSERT INTO schema_migrations (version, checksum) VALUES (${version}, ${checksum})`;
    }
  });
}
