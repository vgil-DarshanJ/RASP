import { Router } from "express";
import { nanoid } from "nanoid";
import { Prisma } from "@prisma/client";
import { prisma } from "../db/prisma";
import { AuthedRequest, requireAuth } from "../middleware/auth";
import { SDK_CATALOG } from "../sdk-distribution/catalog";
import { encryptSecret } from "../crypto/secretBox";
import { publicIngestionUrl } from "./ingestionUrl";
import { ensureAccountHashSalt } from "../risk/accountHashSalt";
import { maskEncryptedSecret, maskSecret } from "../security/secretFields";

export const credentialsRouter = Router();
credentialsRouter.use(requireAuth);

/** Every credential ever issued across every application in the caller's
 *  org — active and revoked, but never soft-deleted (`deletedAt: null`)
 *  — for a real "Licenses" list. Never returns the secret or the
 *  account-hash salt (both were a one-time reveal at issuance): only their
 *  masked prefixes, `apiSecretMasked` and `application.accountHashSaltMasked`,
 *  so a user can tell which credential file they hold.
 *
 *  Also attaches each credential's application's live `deviceCount` —
 *  a distinct-device tally straight from `SecurityEvent`, the same
 *  source of truth the Devices page itself reads — so the Licenses page
 *  can answer "how many devices are actually using this app's
 *  credential" without a separate round trip per row.
 *
 *  Includes `ingestionUrl` (same value `POST .../credentials` stamps
 *  onto the one-time-reveal JSON at issuance) so the Licenses page's
 *  "copy config" action can reassemble everything BUT the secret for an
 *  already-issued credential — the secret itself is never recoverable
 *  here, on purpose; see that route's own doc. */
credentialsRouter.get("/", async (req: AuthedRequest, res) => {
  const credentials = await prisma.apiCredential.findMany({
    where: { application: { organizationId: req.user!.organizationId }, deletedAt: null },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      apiKey: true,
      status: true,
      createdAt: true,
      rotatedAt: true,
      revokedAt: true,
      // Read only to build the masked prefixes below; never returned.
      apiSecretEncrypted: true,
      application: { select: { id: true, name: true, platform: true, accountHashSalt: true } },
    },
  });

  const applicationIds = [...new Set(credentials.map((c) => c.application.id))];
  const deviceCounts = applicationIds.length
    ? await prisma.$queryRaw<{ applicationId: string; deviceCount: bigint }[]>`
        SELECT "applicationId", COUNT(DISTINCT "deviceId")::bigint AS "deviceCount"
        FROM security_events
        WHERE "applicationId" IN (${Prisma.join(applicationIds)}) AND "deviceId" IS NOT NULL
        GROUP BY "applicationId"
      `
    : [];
  const deviceCountByApp = new Map(deviceCounts.map((d) => [d.applicationId, Number(d.deviceCount)]));

  res.json({
    organizationId: req.user!.organizationId,
    ingestionUrl: publicIngestionUrl(),
    credentials: credentials.map(({ apiSecretEncrypted, application: { accountHashSalt, ...application }, ...c }) => ({
      ...c,
      apiSecretMasked: maskEncryptedSecret(apiSecretEncrypted),
      application: {
        ...application,
        accountHashSaltMasked: maskSecret(accountHashSalt),
        deviceCount: deviceCountByApp.get(application.id) ?? 0,
      },
    })),
  });
});

/** Org-wide credential lifecycle audit trail — every `CredentialAuditLog`
 *  row across every application, not just one (the per-application
 *  version already exists below). `performedByUserId` has no Prisma
 *  relation to `User` (kept as a plain foreign id so this table stays
 *  append-only and immune to a user being renamed/deleted), so the email
 *  is resolved here with one extra batched lookup instead of a join. */
credentialsRouter.get("/audit-log", async (req: AuthedRequest, res) => {
  const logs = await prisma.credentialAuditLog.findMany({
    where: { credential: { application: { organizationId: req.user!.organizationId } } },
    orderBy: { performedAt: "desc" },
    take: 200,
    include: {
      credential: {
        select: { apiKey: true, application: { select: { id: true, name: true } } },
      },
    },
  });

  const userIds = [...new Set(logs.map((l) => l.performedByUserId))];
  const users = await prisma.user.findMany({
    where: { id: { in: userIds } },
    select: { id: true, email: true },
  });
  const emailById = new Map(users.map((u) => [u.id, u.email]));

  res.json({
    logs: logs.map((l) => ({
      ...l,
      performedByEmail: emailById.get(l.performedByUserId) ?? "(deleted user)",
    })),
  });
});

/** Generates a new API key + secret pair. The secret's plaintext is
 *  returned in THIS response only — its AES-256-GCM-encrypted form is
 *  what's persisted (see `crypto/secretBox.ts` for why this is
 *  reversible encryption, not a one-way hash: the ingestion endpoint's
 *  HMAC verification needs the raw secret back at request time). Losing
 *  the plaintext still means it can never be displayed again — only
 *  rotated (issue a new credential) — this backend just doesn't lose the
 *  ABILITY to verify signatures the way a bcrypt hash would have. */
function generateKeyPair() {
  const apiKey = `rasp_live_${nanoid(32)}`;
  const apiSecret = nanoid(48);
  return { apiKey, apiSecret };
}

/** `archivedAt: null` is load-bearing, not incidental — a "deleted"
 *  application (see `apps/routes.ts`'s archive endpoint) must become
 *  invisible through every scoped route, not just its own listing, so
 *  its credentials/events/webhooks are hidden without a single row
 *  actually being touched. */
async function assertOwnedApplication(applicationId: string, organizationId: string) {
  return prisma.application.findFirst({
    where: { id: applicationId, organizationId, archivedAt: null },
  });
}

/** Issues a credential for an application this org owns, and returns the
 *  full downloadable JSON credential shape in one response — the FE's
 *  "download JSON key" button is a direct save of this response body.
 *  Writes a `CredentialAuditLog` row so who-issued-what-when is never
 *  reconstructed after the fact from application logs alone.
 *
 *  The ONLY endpoint that returns `api_secret` and `account_hash_salt` in
 *  full (issuing a new credential is also how a credential is rotated).
 *  Everything else shows masked prefixes — see security/secretFields.ts. */
credentialsRouter.post("/applications/:applicationId/credentials", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const { apiKey, apiSecret } = generateKeyPair();
  const apiSecretEncrypted = encryptSecret(apiSecret);

  const credential = await prisma.$transaction(async (tx) => {
    const created = await tx.apiCredential.create({
      data: { applicationId: app.id, apiKey, apiSecretEncrypted },
    });
    await tx.credentialAuditLog.create({
      data: {
        credentialId: created.id,
        action: "ISSUED",
        performedByUserId: req.user!.userId,
        ipAddress: req.ip,
      },
    });
    return created;
  });

  const catalogEntry = SDK_CATALOG.find((s) => s.platform === app.platform);
  // Generated here for applications created before salts existed.
  const accountHashSalt = await ensureAccountHashSalt(app.id, { userId: req.user!.userId, ipAddress: req.ip });

  res.status(201).json({
    organization_id: req.user!.organizationId,
    application_id: app.id,
    application_name: app.name,
    platform: app.platform,
    api_key: apiKey,
    api_secret: apiSecret, // shown ONCE — not retrievable again after this response
    // Key for the SDK's account/session/beneficiary hashes (HMAC-SHA256);
    // same for every credential of the application.
    account_hash_salt: accountHashSalt,
    ingestion_url: publicIngestionUrl(),
    sdk_min_version: catalogEntry?.minVersion ?? null,
    issued_at: credential.createdAt.toISOString(),
  });
});

// There is deliberately no endpoint that returns the account-hash salt of an
// existing application: it comes only with a newly issued credential (above).

credentialsRouter.post(
  "/applications/:applicationId/credentials/:credentialId/revoke",
  async (req: AuthedRequest, res) => {
    const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
    if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

    const credential = await prisma.apiCredential.findFirst({
      where: { id: req.params.credentialId, applicationId: app.id, deletedAt: null },
    });
    if (!credential) return res.status(404).json({ error: "CREDENTIAL_NOT_FOUND" });

    await prisma.$transaction([
      prisma.apiCredential.update({
        where: { id: credential.id },
        data: { status: "REVOKED", revokedAt: new Date() },
      }),
      prisma.credentialAuditLog.create({
        data: {
          credentialId: credential.id,
          action: "REVOKED",
          performedByUserId: req.user!.userId,
          ipAddress: req.ip,
        },
      }),
    ]);

    res.json({ ok: true });
  },
);

/** Un-revokes a credential back to ACTIVE — the reverse of `/revoke`.
 *  Only works on a credential that is currently REVOKED and not
 *  soft-deleted; re-activating a credential that was already deleted
 *  isn't offered here (delete already required revoke-first, and
 *  restoring a deleted row is a different, bigger decision than
 *  reversing a revoke, kept out of scope for this action on purpose).
 *  The secret was never touched by revoke and stays the same one the
 *  app already has — nothing to re-issue or re-download. */
credentialsRouter.post(
  "/applications/:applicationId/credentials/:credentialId/unrevoke",
  async (req: AuthedRequest, res) => {
    const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
    if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

    const credential = await prisma.apiCredential.findFirst({
      where: { id: req.params.credentialId, applicationId: app.id, deletedAt: null },
    });
    if (!credential) return res.status(404).json({ error: "CREDENTIAL_NOT_FOUND" });
    if (credential.status !== "REVOKED") {
      return res.status(400).json({ error: "CREDENTIAL_NOT_REVOKED" });
    }

    await prisma.$transaction([
      prisma.apiCredential.update({
        where: { id: credential.id },
        data: { status: "ACTIVE", revokedAt: null },
      }),
      prisma.credentialAuditLog.create({
        data: {
          credentialId: credential.id,
          action: "REACTIVATED",
          performedByUserId: req.user!.userId,
          ipAddress: req.ip,
        },
      }),
    ]);

    res.json({ ok: true });
  },
);

/** Soft-deletes a credential — hides it from `GET /v1/credentials`
 *  forever, but the row and its full `CredentialAuditLog` history stay
 *  in Postgres (see the `deletedAt` field's schema doc for why this is
 *  not a hard delete). Only allowed once a credential is already
 *  REVOKED: deleting an ACTIVE credential straight away would let
 *  someone skip the "did we mean to actually cut this off" step that
 *  revoke exists for, and would remove it from view while an app might
 *  still be signing requests with it. */
credentialsRouter.delete(
  "/applications/:applicationId/credentials/:credentialId",
  async (req: AuthedRequest, res) => {
    const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
    if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

    const credential = await prisma.apiCredential.findFirst({
      where: { id: req.params.credentialId, applicationId: app.id, deletedAt: null },
    });
    if (!credential) return res.status(404).json({ error: "CREDENTIAL_NOT_FOUND" });
    if (credential.status !== "REVOKED") {
      return res.status(400).json({ error: "CREDENTIAL_MUST_BE_REVOKED_FIRST" });
    }

    await prisma.$transaction([
      prisma.apiCredential.update({
        where: { id: credential.id },
        data: { deletedAt: new Date() },
      }),
      prisma.credentialAuditLog.create({
        data: {
          credentialId: credential.id,
          action: "DELETED",
          performedByUserId: req.user!.userId,
          ipAddress: req.ip,
        },
      }),
    ]);

    res.status(204).send();
  },
);

/** The credential lifecycle audit trail for one application — who issued
 *  or revoked which credential, when, from where. */
credentialsRouter.get(
  "/applications/:applicationId/credentials/audit-log",
  async (req: AuthedRequest, res) => {
    const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
    if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

    const logs = await prisma.credentialAuditLog.findMany({
      where: { credential: { applicationId: app.id } },
      orderBy: { performedAt: "desc" },
      include: { credential: { select: { apiKey: true } } },
    });

    res.json({ logs });
  },
);
