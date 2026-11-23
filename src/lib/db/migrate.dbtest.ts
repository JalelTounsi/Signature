import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";

import type pg from "pg";

import { runMigrations } from "../../../db/migrate.mjs";
import { openTestDatabase } from "./test-database.ts";

// The migration runner against a real Postgres: it remembers what each
// applied file contained and refuses to go on when one has been edited
// since. Each test uses migrations of its own, in a folder of its own.
// Run with `npm run test:db`.

let database: pg.Pool;
const connectionString =
  process.env.E2E_DATABASE_URL ??
  "postgres://signudoc:signudoc@127.0.0.1:5432/signudoc_e2e";
const madeTables: string[] = [];
const madeVersions: string[] = [];
const madeDirs: string[] = [];

before(async () => {
  database = await openTestDatabase();
});

after(async () => {
  for (const table of madeTables) {
    await database.query(`drop table if exists public."${table}"`);
  }

  await database.query(
    "delete from public.signudoc_migrations where version = any($1)",
    [madeVersions],
  );
  await database.end();
  await Promise.all(
    madeDirs.map((dir) => rm(dir, { force: true, recursive: true })),
  );
});

/** A folder with one migration in it, which makes a table of its own. */
async function migrationFolder() {
  const dir = await mkdtemp(path.join(tmpdir(), "signudoc-migrate-"));
  const tag = randomUUID().replaceAll("-", "");
  const first = `00000000000001_checksum_${tag}`;
  const table = `checksum_test_${tag}`;

  madeDirs.push(dir);
  madeTables.push(table, `${table}_second`);
  madeVersions.push(first, `00000000000002_checksum_${tag}`);
  await writeFile(
    path.join(dir, `${first}.sql`),
    `create table public."${table}" (id text primary key);\n`,
  );

  return {
    dir,
    first,
    firstFile: path.join(dir, `${first}.sql`),
    second: `00000000000002_checksum_${tag}`,
    secondFile: path.join(dir, `00000000000002_checksum_${tag}.sql`),
    table,
  };
}

function run(dir: string) {
  return runMigrations({
    connectionString,
    log: () => undefined,
    migrationsDir: dir,
  });
}

async function storedChecksum(version: string) {
  const result = await database.query<{ checksum: string | null }>(
    "select checksum from public.signudoc_migrations where version = $1",
    [version],
  );

  return result.rows[0]?.checksum;
}

async function tableExists(table: string) {
  const result = await database.query<{ found: string | null }>(
    "select to_regclass($1)::text as found",
    [`public."${table}"`],
  );

  return result.rows[0]?.found !== null;
}

test("an applied migration is recorded with a checksum of its file", async () => {
  const folder = await migrationFolder();

  assert.deepEqual((await run(folder.dir)).applied, [folder.first]);
  assert.match((await storedChecksum(folder.first)) ?? "", /^[0-9a-f]{64}$/);

  // Unchanged, it is skipped as before.
  assert.deepEqual((await run(folder.dir)).applied, []);

  // The same file checked out with Windows line endings is the same file.
  await writeFile(
    folder.firstFile,
    `create table public."${folder.table}" (id text primary key);\r\n`,
  );
  assert.deepEqual((await run(folder.dir)).applied, []);
});

test("an applied migration that was edited stops the run and is named", async () => {
  const folder = await migrationFolder();

  await run(folder.dir);
  await writeFile(
    folder.firstFile,
    `create table public."${folder.table}" (id text primary key, added text);\n`,
  );
  await writeFile(
    folder.secondFile,
    `create table public."${folder.table}_second" (id text primary key);\n`,
  );

  await assert.rejects(run(folder.dir), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.ok(error.message.includes(`${folder.first}.sql`));
    assert.match(error.message, /changed after it was applied/);

    return true;
  });

  // Nothing else ran: the database is as it was.
  assert.equal(await tableExists(`${folder.table}_second`), false);
  assert.equal(await storedChecksum(folder.second), undefined);
});

test("a migration applied before checksums were kept is given one, not refused", async () => {
  const folder = await migrationFolder();

  // As an earlier version of the runner left it: applied, no checksum.
  await run(folder.dir);
  await database.query(
    "update public.signudoc_migrations set checksum = null where version = $1",
    [folder.first],
  );

  assert.deepEqual((await run(folder.dir)).applied, []);
  assert.match((await storedChecksum(folder.first)) ?? "", /^[0-9a-f]{64}$/);

  // From then on an edit is caught like any other.
  await writeFile(folder.firstFile, "select 1;\n");
  await assert.rejects(run(folder.dir), /changed after it was applied/);
});
