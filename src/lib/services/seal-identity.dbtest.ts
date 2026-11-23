import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";

import type pg from "pg";

import { openTestDatabase } from "../db/test-database.ts";
import {
  getSealIdentity,
  getSealKeyStatus,
  replaceUnreadableSealKey,
  resetSealIdentityCache,
  SealKeyError,
} from "./seal-identity.ts";

// What happens to the install's own seal key when the auth secret it is
// encrypted with changes, against a real Postgres. Run with
// `npm run test:db`.

const FIRST_SECRET = { BETTER_AUTH_SECRET: "first-secret-".padEnd(40, "1") };
const SECOND_SECRET = { BETTER_AUTH_SECRET: "second-secret-".padEnd(40, "2") };
const ADMIN = { email: "ada@example.test", userId: "admin-1" };

let database: pg.Pool;

async function clear() {
  await database.query("delete from seal_keys");
  await database.query(
    "delete from system_audit_events where event like 'seal_key_%'",
  );
  resetSealIdentityCache();
}

before(async () => {
  database = await openTestDatabase();
  // The seal's name comes from the install's settings, read through the
  // shared pool.
  globalThis.__signudocPgPool = database;
});

beforeEach(clear);

after(async () => {
  // The other tests seal with their own secret: leave them no key of ours.
  await clear();
  await database.end();
});

async function sealKeys() {
  const result = await database.query<{ id: string; retired: boolean }>(
    `select id, retired_at is not null as retired from seal_keys order by created_at, id`,
  );

  return result.rows;
}

async function sealEvents() {
  const result = await database.query<{
    actor_email: string | null;
    event: string;
    metadata: Record<string, unknown> | null;
  }>(
    `
      select event, actor_email, metadata from system_audit_events
      where event like 'seal_key_%' order by sequence
    `,
  );

  return result.rows;
}

test("a changed auth secret stops sealing instead of making a new key", async () => {
  const first = await getSealIdentity({ database, env: FIRST_SECRET });
  const [made] = await sealKeys();

  assert.ok(made);
  assert.equal(await getSealKeyStatus({ database, env: FIRST_SECRET }), "ok");
  resetSealIdentityCache();

  await assert.rejects(
    getSealIdentity({ database, env: SECOND_SECRET }),
    (error: unknown) =>
      error instanceof SealKeyError &&
      /BETTER_AUTH_SECRET/.test(error.message) &&
      /administrator/.test(error.message),
  );

  // The stored key is untouched, and no other was made beside it.
  assert.deepEqual(await sealKeys(), [{ id: made.id, retired: false }]);
  assert.equal(
    await getSealKeyStatus({ database, env: SECOND_SECRET }),
    "unreadable",
  );

  // Every failed sealing says so, but the site's trail notes it once.
  await assert.rejects(
    getSealIdentity({ database, env: SECOND_SECRET }),
    SealKeyError,
  );

  const events = await sealEvents();

  assert.deepEqual(
    events.map((event) => event.event),
    ["seal_key_unreadable"],
  );
  assert.equal(events[0]?.metadata?.sealKeyId, made.id);

  // With the old secret back, the same key seals again.
  const again = await getSealIdentity({ database, env: FIRST_SECRET });

  assert.equal(again.privateKeyPem, first.privateKeyPem);
});

test("an administrator makes a new key in place of one that cannot be read", async () => {
  const first = await getSealIdentity({ database, env: FIRST_SECRET });
  const [made] = await sealKeys();

  assert.ok(made);
  resetSealIdentityCache();
  await assert.rejects(
    getSealIdentity({ database, env: SECOND_SECRET }),
    SealKeyError,
  );

  await replaceUnreadableSealKey(ADMIN, { database, env: SECOND_SECRET });

  const keys = await sealKeys();

  assert.equal(keys.length, 2);
  assert.deepEqual(
    keys.find((key) => key.id === made.id),
    { id: made.id, retired: true },
  );

  const next = await getSealIdentity({ database, env: SECOND_SECRET });

  assert.notEqual(next.privateKeyPem, first.privateKeyPem);
  assert.equal(await getSealKeyStatus({ database, env: SECOND_SECRET }), "ok");

  const events = await sealEvents();
  const replaced = events.find((event) => event.event === "seal_key_replaced");

  assert.equal(replaced?.actor_email, ADMIN.email);
  assert.equal(replaced?.metadata?.retiredSealKeyId, made.id);
});

test("a key that can still be read is not replaced", async () => {
  const first = await getSealIdentity({ database, env: FIRST_SECRET });

  await assert.rejects(
    replaceUnreadableSealKey(ADMIN, { database, env: FIRST_SECRET }),
    (error: unknown) =>
      error instanceof SealKeyError && error.statusCode === 409,
  );

  resetSealIdentityCache();
  assert.equal(
    (await getSealIdentity({ database, env: FIRST_SECRET })).privateKeyPem,
    first.privateKeyPem,
  );
  assert.equal((await sealKeys()).length, 1);
});
