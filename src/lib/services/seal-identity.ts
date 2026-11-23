import {
  X509Certificate,
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomUUID,
} from "node:crypto";

import { PDFDocument } from "pdf-lib";

import { getDb, withTransaction, type DbPool } from "../db/connection.ts";
import type { Branding } from "../branding.ts";
import { getBranding } from "../settings.ts";
import { recordSystemAuditEvent } from "./system-audit.ts";
import {
  isProduction,
  readEnv,
  resolveAuthSecret,
  type EnvSource,
} from "../utils/env.ts";
import {
  addLongTermValidation,
  isSelfSigned,
  parseCertificate,
  type ValidationFetch,
} from "./pdf-ltv.ts";
import {
  createSelfSignedSealIdentity,
  requestDocumentTimestamp,
  saveSealedPdf,
  sealIdentityFromPkcs12,
  type SealIdentity,
  type SealOptions,
} from "./pdf-seal.ts";

// Where the install's seal key comes from:
//
// 1. SEAL_P12_BASE64 (+ SEAL_P12_PASSWORD): a certificate the organization
//    bought from a certificate authority, so readers show its name as
//    verified. Used as given, never stored.
// 2. Otherwise a key the install makes for itself the first time it seals a
//    document. The private key is kept in the seal_keys table, encrypted with
//    a key derived from the auth secret. If that secret changes and the
//    stored key can no longer be read, sealing stops with SealKeyError and
//    the site's audit trail notes it. Nothing replaces the key by itself: an
//    administrator either puts the earlier secret back or makes a new key
//    (replaceUnreadableSealKey). Documents sealed before still verify,
//    because each carries its own certificate.

const KEY_CONTEXT = "signudoc/seal-key/v1";
const SEAL_KEY_LOCK_ID = 746108325;

type CachedIdentity = { identity: SealIdentity; source: string };

declare global {
  var __signudocSealIdentity: CachedIdentity | undefined;
}

function encryptionKey(env: EnvSource, context: string = KEY_CONTEXT): Buffer {
  const secret = resolveAuthSecret(env);

  if (!secret) {
    if (isProduction(env)) {
      throw new Error(
        "Sealing documents needs BETTER_AUTH_SECRET, or a database password of at least 12 characters.",
      );
    }

    // Local development without a password: nothing worth protecting.
    return Buffer.from(
      hkdfSync("sha256", "signudoc-development", "", context, 32),
    );
  }

  return Buffer.from(hkdfSync("sha256", secret, "", context, 32));
}

/**
 * A key for keeping something else secret in the database, derived from the
 * auth secret the same way as the seal key's, for its own purpose.
 */
export function secretKeyFor(
  context: string,
  env: EnvSource = process.env,
): Buffer {
  return encryptionKey(env, context);
}

export function encryptPrivateKey(pem: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(pem, "utf8"), cipher.final()]);

  return [
    "v1",
    iv.toString("base64"),
    cipher.getAuthTag().toString("base64"),
    body.toString("base64"),
  ].join(".");
}

export function decryptPrivateKey(value: string, key: Buffer): string | null {
  const [version, iv, tag, body] = value.split(".");

  if (version !== "v1" || !iv || !tag || !body) {
    return null;
  }

  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(iv, "base64"),
    );

    decipher.setAuthTag(Buffer.from(tag, "base64"));

    return Buffer.concat([
      decipher.update(Buffer.from(body, "base64")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}

function identityFromEnvironment(env: EnvSource): SealIdentity | null {
  const bundle = readEnv(env, "SEAL_P12_BASE64");

  if (!bundle) {
    return null;
  }

  return sealIdentityFromPkcs12(
    new Uint8Array(Buffer.from(bundle, "base64")),
    readEnv(env, "SEAL_P12_PASSWORD") ?? "",
  );
}

type SealKeyRow = {
  certificatePem: string;
  encryptedPrivateKey: string;
  id: string;
};

/** A seal key problem an administrator has to settle. */
export class SealKeyError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode = 500) {
    super(message);
    this.name = "SealKeyError";
    this.statusCode = statusCode;
  }
}

export const SEAL_KEY_UNREADABLE_MESSAGE =
  "The key this site seals documents with cannot be read: it was stored under a different BETTER_AUTH_SECRET (or database password) than the one set now. Put the earlier secret back, or have an administrator make a new sealing key in Settings. No document can be sealed until then.";

type DbTransaction = Parameters<Parameters<typeof withTransaction>[0]>[0];

async function readActiveSealKey(
  tx: DbTransaction,
): Promise<SealKeyRow | undefined> {
  // One instance makes the key; any other waits here and then reads it.
  await tx.query("SELECT pg_advisory_xact_lock($1)", [SEAL_KEY_LOCK_ID]);

  const existing = await tx.query<SealKeyRow>(
    `
      SELECT
        id,
        certificate_pem AS "certificatePem",
        encrypted_private_key AS "encryptedPrivateKey"
      FROM seal_keys
      WHERE retired_at IS NULL
      LIMIT 1
    `,
  );

  return existing.rows[0];
}

/** Makes a key, stores it as the active one and retires any before it. */
async function storeNewSealKey(
  tx: DbTransaction,
  key: Buffer,
  branding: Branding,
): Promise<CachedIdentity> {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 3072,
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const generated = createSelfSignedSealIdentity({
    commonName: `${branding.organizationName ?? branding.productName} document seal`,
    organization: branding.organizationName,
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
  });
  const now = Math.floor(Date.now() / 1000);
  const id = randomUUID();

  await tx.query(
    `UPDATE seal_keys SET retired_at = $1 WHERE retired_at IS NULL`,
    [now],
  );
  await tx.query(
    `
      INSERT INTO seal_keys (id, certificate_pem, encrypted_private_key, created_at)
      VALUES ($1, $2, $3, $4)
    `,
    [id, generated.certificatePem, encryptPrivateKey(privateKey, key), now],
  );

  return { identity: generated, source: `database:${id}` };
}

/**
 * Notes in the site's audit trail that the stored key cannot be read. Once
 * per key: every sealing fails until it is settled, and the trail does not
 * need a row for each.
 */
async function noteUnreadableSealKey(sealKeyId: string, database: DbPool) {
  try {
    await withTransaction(async (tx) => {
      // The site's trail is written under this same lock, so two instances
      // cannot both find the note missing.
      await tx.query("SELECT pg_advisory_xact_lock($1)", [SEAL_KEY_LOCK_ID]);

      const noted = await tx.query(
        `
          SELECT 1 FROM system_audit_events
          WHERE event = 'seal_key_unreadable'
            AND metadata->>'sealKeyId' = $1
          LIMIT 1
        `,
        [sealKeyId],
      );

      if (noted.rowCount === 0) {
        await recordSystemAuditEvent(
          {
            actorType: "system",
            event: "seal_key_unreadable",
            metadata: { sealKeyId },
          },
          tx,
        );
      }
    }, database);
  } catch (error) {
    console.error(
      "[seal] Could not note the unreadable seal key in the audit trail:",
      error,
    );
  }
}

async function identityFromDatabase(
  env: EnvSource,
  database: DbPool,
): Promise<CachedIdentity> {
  const key = encryptionKey(env);
  // Read before the transaction: settings come through another connection,
  // which a full pool could not give while this one waits on the lock.
  const branding = await getBranding(env);

  const resolved = await withTransaction(async (tx) => {
    const row = await readActiveSealKey(tx);

    if (!row) {
      return storeNewSealKey(tx, key, branding);
    }

    const privateKeyPem = decryptPrivateKey(row.encryptedPrivateKey, key);

    if (!privateKeyPem) {
      return { unreadableSealKeyId: row.id };
    }

    return {
      identity: {
        certificateChainPem: [row.certificatePem],
        privateKeyPem,
      },
      source: `database:${row.id}`,
    };
  }, database);

  if ("unreadableSealKeyId" in resolved) {
    console.error(`[seal] ${SEAL_KEY_UNREADABLE_MESSAGE}`);
    await noteUnreadableSealKey(resolved.unreadableSealKeyId, database);

    throw new SealKeyError(SEAL_KEY_UNREADABLE_MESSAGE);
  }

  return resolved;
}

export type SealKeyStatus = "environment" | "none" | "ok" | "unreadable";

/** Where the seal key stands, for the administrator's settings page. */
export async function getSealKeyStatus({
  database = getDb(),
  env = process.env,
}: { database?: DbPool; env?: EnvSource } = {}): Promise<SealKeyStatus> {
  if (readEnv(env, "SEAL_P12_BASE64")) {
    return "environment";
  }

  const key = encryptionKey(env);
  const stored = await database.query<{ encryptedPrivateKey: string }>(
    `
      SELECT encrypted_private_key AS "encryptedPrivateKey"
      FROM seal_keys
      WHERE retired_at IS NULL
      LIMIT 1
    `,
  );
  const row = stored.rows[0];

  if (!row) {
    return "none";
  }

  return decryptPrivateKey(row.encryptedPrivateKey, key) ? "ok" : "unreadable";
}

/**
 * Makes a new seal key in place of a stored one that can no longer be read,
 * which only an administrator decides. The old key is retired, not deleted,
 * and the change is written to the site's audit trail with who made it.
 */
export async function replaceUnreadableSealKey(
  actor: {
    email: string;
    ipAddress?: string | null;
    userAgent?: string | null;
    userId: string;
  },
  {
    database = getDb(),
    env = process.env,
  }: { database?: DbPool; env?: EnvSource } = {},
): Promise<void> {
  if (readEnv(env, "SEAL_P12_BASE64")) {
    throw new SealKeyError(
      "This site seals with the certificate in SEAL_P12_BASE64, so it has no key of its own to replace.",
      409,
    );
  }

  const key = encryptionKey(env);
  const branding = await getBranding(env);

  await withTransaction(async (tx) => {
    const row = await readActiveSealKey(tx);

    if (!row || decryptPrivateKey(row.encryptedPrivateKey, key)) {
      throw new SealKeyError(
        "The sealing key can be read, so there is nothing to replace.",
        409,
      );
    }

    const made = await storeNewSealKey(tx, key, branding);

    await recordSystemAuditEvent(
      {
        actorEmail: actor.email,
        actorUserId: actor.userId,
        event: "seal_key_replaced",
        ipAddress: actor.ipAddress ?? null,
        metadata: {
          retiredSealKeyId: row.id,
          sealKeyId: made.source.replace(/^database:/, ""),
        },
        userAgent: actor.userAgent ?? null,
      },
      tx,
    );
  }, database);

  resetSealIdentityCache();
}

export async function getSealIdentity({
  database = getDb(),
  env = process.env,
}: { database?: DbPool; env?: EnvSource } = {}): Promise<SealIdentity> {
  const cached = globalThis.__signudocSealIdentity;

  if (cached) {
    return cached.identity;
  }

  const fromEnvironment = identityFromEnvironment(env);
  const resolved = fromEnvironment
    ? { identity: fromEnvironment, source: "environment" }
    : await identityFromDatabase(env, database);

  globalThis.__signudocSealIdentity = resolved;

  return resolved.identity;
}

/** Forgets the loaded key, for tests. */
export function resetSealIdentityCache() {
  globalThis.__signudocSealIdentity = undefined;
}

export type SealPurpose = "signed-document" | "certificate";

/**
 * Saves a finished PDF sealed with the install's key, so any later change to
 * it shows in a PDF reader.
 */
export async function saveInstallSealedPdf(
  pdfDocument: PDFDocument,
  purpose: SealPurpose,
  {
    branding: givenBranding,
    database,
    env = process.env,
    identity,
  }: {
    branding?: Branding;
    database?: DbPool;
    env?: EnvSource;
    identity?: SealIdentity;
  } = {},
): Promise<Uint8Array> {
  const sealIdentity = identity ?? (await getSealIdentity({ database, env }));
  const branding = givenBranding ?? (await getBranding(env));
  const timestampUrl = readEnv(env, "SEAL_TIMESTAMP_URL") ?? null;
  const options: SealOptions = {
    contactInfo: branding.supportAddress ?? "",
    name: branding.organizationName ?? branding.productName,
    reason:
      purpose === "signed-document"
        ? `Signed with ${branding.productName}; sealed so that later changes are detectable`
        : `${branding.productName} audit certificate`,
    timestampUrl,
  };

  return sealForTheLongTerm(pdfDocument, sealIdentity, options);
}

/**
 * Seals the document (PAdES B-B, or B-T with a time-stamping service), then
 * adds what keeps the seal checkable for years: the certificates and
 * revocation answers (B-LT) and an archive timestamp over them (B-LTA).
 * Each step after the first only adds to the file, and is skipped with a
 * logged reason when a service it needs cannot be reached.
 */
export async function sealForTheLongTerm(
  pdfDocument: PDFDocument,
  identity: SealIdentity,
  options: SealOptions,
  { fetch }: { fetch?: ValidationFetch } = {},
): Promise<Uint8Array> {
  const timestampUrl = options.timestampUrl ?? null;
  // A self-made certificate has no issuer to ask about, so without a
  // timestamp there is nothing to add for it.
  const fromAuthority = isCertificateAuthoritySeal(identity);

  if (!timestampUrl) {
    const sealed = await saveSealedPdf(pdfDocument, identity, options);

    return fromAuthority ? withLongTermValidation(sealed, null, fetch) : sealed;
  }

  let sealed: Uint8Array;

  try {
    sealed = await saveSealedPdf(
      await clonePdf(pdfDocument),
      identity,
      options,
    );
  } catch (error) {
    // A time-stamping service that is down must not stop a signing. The
    // document is still sealed, only without the independent time.
    console.error("[seal] Timestamping failed; sealing without it.", error);
    sealed = await saveSealedPdf(pdfDocument, identity, {
      ...options,
      timestampUrl: null,
    });

    return fromAuthority ? withLongTermValidation(sealed, null, fetch) : sealed;
  }

  return withLongTermValidation(sealed, timestampUrl, fetch);
}

/** Whether the seal certificate was issued by someone else. */
function isCertificateAuthoritySeal(identity: SealIdentity): boolean {
  try {
    return !isSelfSigned(
      parseCertificate(
        new X509Certificate(identity.certificateChainPem[0]!).raw,
      ),
    );
  } catch {
    return false;
  }
}

/**
 * Adds long-term validation (PAdES B-LT) and, with a time-stamping service,
 * an archive timestamp (B-LTA). It only adds to a seal already made, so
 * when a certificate authority or the time-stamping service cannot be
 * reached the document keeps the seal it has, and the reason is logged.
 */
async function withLongTermValidation(
  sealed: Uint8Array,
  timestampUrl: string | null,
  fetch: ValidationFetch | undefined,
  whose: "seal" | "signers" = "seal",
): Promise<Uint8Array> {
  try {
    const result = await addLongTermValidation(sealed, {
      fetch,
      timestamp: timestampUrl
        ? (digest) => requestDocumentTimestamp(digest, timestampUrl)
        : null,
    });

    if (result.revoked.length > 0) {
      console.error(
        whose === "seal"
          ? `[seal] A certificate authority says these certificates are revoked: ${result.revoked.join("; ")}. Readers will not accept the seal. Replace SEAL_P12_BASE64.`
          : `[seal] A certificate authority says these signers' certificates are revoked: ${result.revoked.join("; ")}. Readers will not accept those signatures.`,
      );
    }

    if (result.problems.length > 0) {
      console.warn(
        `[seal] Long-term validation is incomplete: ${result.problems.join(" ")}`,
      );
    }

    return result.bytes;
  } catch (error) {
    console.error(
      "[seal] Adding long-term validation failed; keeping the seal without it.",
      error,
    );
    return sealed;
  }
}

/**
 * The finished PDF of an envelope whose signers signed with certificates in
 * their own names: the last signer's revision, with the validation data of
 * every signature in it (PAdES B-LT), and with SEAL_TIMESTAMP_URL an archive
 * timestamp over all of it (B-LTA). The signers' signatures already protect
 * the document, so the install adds no seal of its own here.
 */
export async function finishSignerSignedPdf(
  revision: Uint8Array,
  {
    env = process.env,
    fetch,
  }: { env?: EnvSource; fetch?: ValidationFetch } = {},
): Promise<Uint8Array> {
  return withLongTermValidation(
    revision,
    readEnv(env, "SEAL_TIMESTAMP_URL") ?? null,
    fetch,
    "signers",
  );
}

async function clonePdf(pdfDocument: PDFDocument): Promise<PDFDocument> {
  return PDFDocument.load(await pdfDocument.save({ useObjectStreams: false }));
}
