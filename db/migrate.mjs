#!/usr/bin/env node
// Applies db/migrations/*.sql in filename order and records each one in the
// signudoc_migrations table. Safe to run repeatedly: applied files are skipped.
//
// Each applied file is recorded with a checksum of its content. A published
// migration is never edited (a change goes in a new one), so when an applied
// file no longer matches its checksum the run stops and names it, before
// anything else is applied.
//
//   node db/migrate.mjs             apply pending migrations (fails without a database URL)
//   node db/migrate.mjs --optional  same, but exits cleanly when no database URL is set
//
// On Vercel this runs inside the build (see vercel.json). It only touches the
// database for production builds unless MIGRATE_ON_PREVIEW=1 is set, because
// preview deployments share the production database unless each preview has
// its own database branch.
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import pg from "pg";

import {
  DATABASE_URL_VARIABLES,
  normalizeDatabaseUrl,
  resolveMigrationDatabaseUrl,
} from "./database-url.mjs";

const DEFAULT_MIGRATIONS_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "migrations",
);

// Arbitrary constant shared by every migrator so two builds cannot run at once.
const ADVISORY_LOCK_ID = 746108321;

export async function listMigrationFiles(
  migrationsDir = DEFAULT_MIGRATIONS_DIR,
) {
  const entries = await readdir(migrationsDir);

  return entries.filter((entry) => entry.endsWith(".sql")).sort();
}

/**
 * What a migration file contained. Line endings are left out of it, so a
 * checkout that turns them into CRLF is still the same file.
 */
export function migrationChecksum(sql) {
  return createHash("sha256").update(sql.replace(/\r\n/g, "\n")).digest("hex");
}

export async function runMigrations({
  connectionString,
  log = console.log,
  migrationsDir = DEFAULT_MIGRATIONS_DIR,
}) {
  const client = new pg.Client({
    application_name: "signudoc-migrate",
    connectionString: normalizeDatabaseUrl(connectionString),
    connectionTimeoutMillis: 15_000,
  });

  await client.connect();

  try {
    await client.query("select pg_advisory_lock($1)", [ADVISORY_LOCK_ID]);
    await client.query(`
      create table if not exists public.signudoc_migrations (
        version text primary key,
        applied_at timestamptz not null default now()
      )
    `);

    // Databases migrated before checksums were kept have rows without one.
    await client.query(
      "alter table public.signudoc_migrations add column if not exists checksum text",
    );

    const appliedResult = await client.query(
      "select version, checksum from public.signudoc_migrations",
    );
    const appliedChecksums = new Map(
      appliedResult.rows.map((row) => [row.version, row.checksum]),
    );
    const files = await listMigrationFiles(migrationsDir);
    const pending = [];
    const withoutChecksum = [];

    // Every applied file is checked before anything is applied.
    for (const file of files) {
      const version = file.replace(/\.sql$/, "");
      const sql = await readFile(path.join(migrationsDir, file), "utf8");
      const checksum = migrationChecksum(sql);

      if (!appliedChecksums.has(version)) {
        pending.push({ checksum, file, sql, version });
        continue;
      }

      const recorded = appliedChecksums.get(version);

      if (recorded === null) {
        withoutChecksum.push({ checksum, version });
      } else if (recorded !== checksum) {
        throw new Error(
          `Migration ${file} was changed after it was applied to this database (recorded checksum ${recorded}, the file now has ${checksum}). A published migration is never edited: put the file back as it was and make the change in a new migration.`,
        );
      }
    }

    // Applied by a runner that kept no checksum: what the file holds now is
    // taken as what ran, so later edits are caught.
    for (const { checksum, version } of withoutChecksum) {
      await client.query(
        "update public.signudoc_migrations set checksum = $2 where version = $1 and checksum is null",
        [version, checksum],
      );
    }

    const applied = [];

    for (const { checksum, file, sql, version } of pending) {
      await client.query("begin");

      try {
        await client.query(sql);
        await client.query(
          "insert into public.signudoc_migrations (version, checksum) values ($1, $2)",
          [version, checksum],
        );
        await client.query("commit");
      } catch (error) {
        await client.query("rollback").catch(() => undefined);
        throw new Error(
          `Migration ${file} failed: ${error instanceof Error ? error.message : String(error)}`,
          { cause: error },
        );
      }

      log(`[migrate] applied ${file}`);
      applied.push(version);
    }

    return { applied, total: files.length };
  } finally {
    await client
      .query("select pg_advisory_unlock($1)", [ADVISORY_LOCK_ID])
      .catch(() => undefined);
    await client.end().catch(() => undefined);
  }
}

function loadLocalEnvFiles() {
  // Next.js loads these for the app; do the same for the CLI. Values already
  // present in the environment win.
  for (const fileName of [".env.local", ".env"]) {
    const filePath = path.join(process.cwd(), fileName);

    if (existsSync(filePath)) {
      process.loadEnvFile(filePath);
    }
  }
}

async function main() {
  const optional = process.argv.includes("--optional");

  loadLocalEnvFiles();

  if (
    process.env.VERCEL === "1" &&
    process.env.VERCEL_ENV !== "production" &&
    process.env.MIGRATE_ON_PREVIEW !== "1"
  ) {
    console.log(
      "[migrate] skipped: not a production build. Set MIGRATE_ON_PREVIEW=1 if previews have their own database.",
    );
    return;
  }

  const target = resolveMigrationDatabaseUrl();

  if (!target) {
    const message = `[migrate] no database URL found (looked for ${DATABASE_URL_VARIABLES.join(", ")}).`;

    if (optional) {
      console.warn(
        `${message} Skipping. Run "npm run db:migrate" once a database is connected, or deploy again.`,
      );
      return;
    }

    console.error(message);
    process.exitCode = 1;
    return;
  }

  const result = await runMigrations({ connectionString: target.value });

  console.log(
    result.applied.length > 0
      ? `[migrate] done: applied ${String(result.applied.length)} of ${String(result.total)} migration(s) using ${target.name}.`
      : `[migrate] done: database is up to date (${String(result.total)} migration(s), ${target.name}).`,
  );
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  main().catch((error) => {
    console.error("[migrate] failed:", error);
    process.exitCode = 1;
  });
}
