import { Router } from "express";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { AuthedRequest, requireAuth } from "../middleware/auth";
import { normalizeCertHash } from "../ingestion/tamperAlerts";
import { countrySet, toCountryCode } from "../ipRisk/ipRisk";
import { userRateLimiter } from "../redis/userRateLimit";
import { generateAccountHashSalt } from "../risk/accountHashSalt";
import { PUBLIC_APPLICATION_SELECT, isSecretFieldName, maskEncryptedSecret, maskSecret } from "../security/secretFields";
import { isAdminRole, requireAdminRole } from "../auth/roles";
import {
  DEFAULT_RISK_RULES,
  RISK_RULE_LIMITS,
  RiskRulesConfig,
  RiskRulesPatch,
  effectiveRiskRules,
  mergeRiskRules,
  riskRulesPatchSchema,
} from "../risk/rules";

export const appsRouter = Router();
appsRouter.use(requireAuth);

const createAppSchema = z.object({
  name: z.string().min(1).max(120),
  platform: z.enum(["ANDROID_NATIVE", "FLUTTER", "IOS", "REACT_NATIVE"]),
});

/** ANDROID_NATIVE, FLUTTER and REACT_NATIVE have a real SDK today — see
 *  sdk-distribution for the catalog metadata the FE renders as "available" vs
 *  "coming soon" cards. Registration itself is not blocked for IOS (an org
 *  may want to reserve/plan an integration ahead of the SDK shipping), the
 *  download step is what's gated. */
appsRouter.post("/", async (req: AuthedRequest, res) => {
  const parsed = createAppSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_INPUT", details: parsed.error.flatten() });
  }

  // The account-hash salt is created with the app; it is returned in full
  // only in an issued credential's JSON — here only its masked prefix.
  const accountHashSalt = generateAccountHashSalt();
  const app = await prisma.application.create({
    data: {
      name: parsed.data.name,
      platform: parsed.data.platform,
      organizationId: req.user!.organizationId,
      accountHashSalt,
      settingsAuditLogs: {
        create: {
          action: "ACCOUNT_HASH_SALT_GENERATED",
          field: "accountHashSalt",
          performedByUserId: req.user!.userId,
          ipAddress: req.ip,
        },
      },
    },
    select: PUBLIC_APPLICATION_SELECT,
  });

  res.status(201).json({ application: { ...app, accountHashSaltMasked: maskSecret(accountHashSalt) } });
});

appsRouter.get("/", async (req: AuthedRequest, res) => {
  const apps = await prisma.application.findMany({
    where: { organizationId: req.user!.organizationId, archivedAt: null },
    orderBy: { createdAt: "desc" },
    select: {
      ...PUBLIC_APPLICATION_SELECT,
      credentials: {
        where: { status: "ACTIVE" },
        select: { id: true, apiKey: true, createdAt: true },
      },
    },
  });
  res.json({ applications: apps });
});

/** One application with all its credentials. The API secret and the
 *  account-hash salt appear only as masked prefixes (`apiSecretMasked`,
 *  `accountHashSaltMasked`); the full values are in the credential JSON
 *  issued by `POST /v1/credentials/applications/:id/credentials` only. */
appsRouter.get("/:id", async (req: AuthedRequest, res) => {
  const app = await prisma.application.findFirst({
    where: { id: req.params.id, organizationId: req.user!.organizationId, archivedAt: null },
    select: {
      ...PUBLIC_APPLICATION_SELECT,
      accountHashSalt: true,
      credentials: {
        select: {
          id: true, apiKey: true, status: true, createdAt: true, rotatedAt: true, revokedAt: true, deletedAt: true,
          apiSecretEncrypted: true,
        },
      },
    },
  });
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });
  const { accountHashSalt, credentials, ...application } = app;
  res.json({
    application: {
      ...application,
      accountHashSaltMasked: maskSecret(accountHashSalt),
      credentials: credentials.map(({ apiSecretEncrypted, ...credential }) => ({
        ...credential,
        apiSecretMasked: maskEncryptedSecret(apiSecretEncrypted),
      })),
    },
  });
});

/** Roles allowed to change an application's security settings (see auth/roles.ts). */
export function canEditAppSecurity(role: string | undefined): boolean {
  return isAdminRole(role);
}

const securityPatchSchema = z
  .object({
    /** 64 hex (':' separators allowed); null or "" clears it. */
    expectedSigningCertSha256: z.string().max(200).nullable().optional(),
    /** ISO 3166-1 alpha-2 codes; [] = use the server default blocked list. */
    ipBlockedCountries: z.array(z.string().max(10)).max(250).optional(),
    /** ISO 3166-1 alpha-2 codes; [] = no allow-list. */
    ipAllowedCountries: z.array(z.string().max(10)).max(250).optional(),
    /** Fraud-risk rule thresholds: any subset (merged over the current ones); null resets to defaults. */
    riskRules: riskRulesPatchSchema.nullable().optional(),
    /** RECORD | REQUIRE_HARDWARE — see src/devices/attestationPolicy.ts. */
    attestationPolicy: z.enum(["RECORD", "REQUIRE_HARDWARE"]).optional(),
    /** Whether POST /v1/events still accepts legacy HMAC batches. */
    legacyIngestionEnabled: z.boolean().optional(),
  })
  .strict();

export type AppSecurityPatch = {
  expectedSigningCertSha256?: string | null;
  ipBlockedCountries?: string[];
  ipAllowedCountries?: string[];
  riskRules?: RiskRulesPatch | null;
  attestationPolicy?: "RECORD" | "REQUIRE_HARDWARE";
  legacyIngestionEnabled?: boolean;
};

/**
 * Validates and normalizes a PATCH body: the hash to uppercase hex without
 * separators, country codes to unique uppercase ISO alpha-2, risk-rule
 * thresholds to integers within RISK_RULE_LIMITS. Pure.
 */
export function parseAppSecurityPatch(body: unknown):
  | { ok: true; data: AppSecurityPatch }
  | { ok: false; error: string; details?: unknown } {
  const parsed = securityPatchSchema.safeParse(body);
  if (!parsed.success) return { ok: false, error: "INVALID_INPUT", details: parsed.error.flatten() };
  const input = parsed.data;
  if (Object.keys(input).length === 0) return { ok: false, error: "NOTHING_TO_UPDATE" };

  const data: AppSecurityPatch = {};
  if (input.expectedSigningCertSha256 !== undefined) {
    const raw = input.expectedSigningCertSha256;
    if (raw === null || raw.trim() === "") {
      data.expectedSigningCertSha256 = null;
    } else {
      const hash = normalizeCertHash(raw);
      if (!hash) return { ok: false, error: "INVALID_SIGNING_CERT" };
      data.expectedSigningCertSha256 = hash;
    }
  }
  for (const field of ["ipBlockedCountries", "ipAllowedCountries"] as const) {
    const list = input[field];
    if (list === undefined) continue;
    const invalid = list.filter((code) => toCountryCode(code) === null);
    if (invalid.length > 0) return { ok: false, error: "INVALID_COUNTRY_CODE", details: { field, invalid } };
    data[field] = [...countrySet(list)];
  }
  if (input.riskRules !== undefined) data.riskRules = input.riskRules;
  if (input.attestationPolicy !== undefined) data.attestationPolicy = input.attestationPolicy;
  if (input.legacyIngestionEnabled !== undefined) data.legacyIngestionEnabled = input.legacyIngestionEnabled;
  return { ok: true, data };
}

/** The security settings of one application, risk rules with defaults filled in. */
export interface AppSecuritySettings {
  expectedSigningCertSha256: string | null;
  ipBlockedCountries: string[];
  ipAllowedCountries: string[];
  riskRules: RiskRulesConfig;
  attestationPolicy: "RECORD" | "REQUIRE_HARDWARE";
  legacyIngestionEnabled: boolean;
}

export interface SettingsChange {
  field: keyof AppSecuritySettings;
  oldValue: unknown;
  newValue: unknown;
}

/**
 * Applies a validated patch to the current settings. Returns the new
 * settings and one change per field whose value actually changed — the
 * audit rows. Risk rules are merged field by field over the current ones;
 * `riskRules: null` resets them to the defaults. Pure.
 */
export function applySecurityPatch(current: AppSecuritySettings, patch: AppSecurityPatch) {
  const next: AppSecuritySettings = {
    ...current,
    ...(patch.expectedSigningCertSha256 !== undefined && { expectedSigningCertSha256: patch.expectedSigningCertSha256 }),
    ...(patch.ipBlockedCountries !== undefined && { ipBlockedCountries: patch.ipBlockedCountries }),
    ...(patch.ipAllowedCountries !== undefined && { ipAllowedCountries: patch.ipAllowedCountries }),
    ...(patch.riskRules !== undefined && {
      riskRules: patch.riskRules === null ? structuredClone(DEFAULT_RISK_RULES) : mergeRiskRules(current.riskRules, patch.riskRules),
    }),
    ...(patch.attestationPolicy !== undefined && { attestationPolicy: patch.attestationPolicy }),
    ...(patch.legacyIngestionEnabled !== undefined && { legacyIngestionEnabled: patch.legacyIngestionEnabled }),
  };
  const changes: SettingsChange[] = [];
  for (const field of Object.keys(next) as (keyof AppSecuritySettings)[]) {
    if (JSON.stringify(current[field]) !== JSON.stringify(next[field])) {
      changes.push({ field, oldValue: current[field], newValue: next[field] });
    }
  }
  return { next, changes };
}

const settingsSelect = {
  id: true, expectedSigningCertSha256: true, ipBlockedCountries: true, ipAllowedCountries: true, riskRules: true,
  attestationPolicy: true, legacyIngestionEnabled: true,
} as const;

function currentSettings(row: {
  expectedSigningCertSha256?: string | null;
  ipBlockedCountries?: string[];
  ipAllowedCountries?: string[];
  riskRules?: unknown;
  attestationPolicy?: "RECORD" | "REQUIRE_HARDWARE";
  legacyIngestionEnabled?: boolean;
}): AppSecuritySettings {
  return {
    expectedSigningCertSha256: row.expectedSigningCertSha256 ?? null,
    ipBlockedCountries: row.ipBlockedCountries ?? [],
    ipAllowedCountries: row.ipAllowedCountries ?? [],
    riskRules: effectiveRiskRules(row.riskRules),
    attestationPolicy: row.attestationPolicy ?? "RECORD",
    legacyIngestionEnabled: row.legacyIngestionEnabled ?? false,
  };
}

/** Per signed-in user and per IP, for the settings endpoints below. */
const settingsRateLimit = userRateLimiter({ scope: "app_settings", perUser: 120, perIp: 300, windowSeconds: 60 });

/**
 * GET /v1/apps/:id/security-settings — what the settings page shows: the
 * current values, the rule defaults and allowed ranges, and whether the
 * caller may edit (OWNER/ADMIN). Never the account-hash salt.
 */
appsRouter.get("/:id/security-settings", settingsRateLimit, async (req: AuthedRequest, res) => {
  const app = await prisma.application.findFirst({
    where: { id: req.params.id, organizationId: req.user!.organizationId, archivedAt: null },
    select: settingsSelect,
  });
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });
  res.json({
    settings: currentSettings(app),
    riskRuleDefaults: DEFAULT_RISK_RULES,
    riskRuleLimits: RISK_RULE_LIMITS,
    canEdit: canEditAppSecurity(req.user?.role),
  });
});

/**
 * GET /v1/apps/:id/settings-audit — who changed which setting when, with
 * old and new values. Rows about a secret field (salt generation) never
 * carry a value, even if one was stored.
 */
appsRouter.get("/:id/settings-audit", settingsRateLimit, async (req: AuthedRequest, res) => {
  const app = await prisma.application.findFirst({
    where: { id: req.params.id, organizationId: req.user!.organizationId, archivedAt: null },
    select: { id: true },
  });
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });
  const logs = await prisma.applicationSettingsAuditLog.findMany({
    where: { applicationId: app.id },
    orderBy: { performedAt: "desc" },
    take: 100,
  });
  const userIds = [...new Set(logs.map((l) => l.performedByUserId).filter((id): id is string => id !== null))];
  const users = userIds.length
    ? await prisma.user.findMany({ where: { id: { in: userIds } }, select: { id: true, email: true } })
    : [];
  const emailById = new Map(users.map((u) => [u.id, u.email]));
  res.json({
    logs: logs.map((l) => ({
      id: l.id,
      applicationId: l.applicationId,
      action: l.action,
      field: l.field,
      oldValue: isSecretFieldName(l.field) ? null : l.oldValue,
      newValue: isSecretFieldName(l.field) ? null : l.newValue,
      performedByUserId: l.performedByUserId,
      performedAt: l.performedAt,
      ipAddress: l.ipAddress,
      performedByEmail: l.performedByUserId ? emailById.get(l.performedByUserId) ?? "(deleted user)" : null,
    })),
  });
});

/**
 * PATCH /v1/apps/:id — security settings an OWNER/ADMIN sets per application:
 * - `expectedSigningCertSha256`: a tamper result reporting another hash
 *   raises a "tamper_signing_mismatch" alert (high);
 * - `ipBlockedCountries` / `ipAllowedCountries`: GET /v1/ip-risk policy;
 * - `riskRules`: fraud-risk rule thresholds (risk/rules.ts), validated ranges;
 * - `attestationPolicy`: RECORD | REQUIRE_HARDWARE (devices/attestationPolicy.ts);
 * - `legacyIngestionEnabled`: whether legacy HMAC event batches are accepted.
 * Every changed field is written to the settings audit log (who, when, old,
 * new) in the same transaction. MEMBER → 403 FORBIDDEN_ROLE.
 */
appsRouter.patch("/:id", settingsRateLimit, async (req: AuthedRequest, res) => {
  if (!canEditAppSecurity(req.user?.role)) return res.status(403).json({ error: "FORBIDDEN_ROLE" });
  const patch = parseAppSecurityPatch(req.body);
  if (!patch.ok) return res.status(400).json({ error: patch.error, details: patch.details });

  const app = await prisma.application.findFirst({
    where: { id: req.params.id, organizationId: req.user!.organizationId, archivedAt: null },
    select: settingsSelect,
  });
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const { next, changes } = applySecurityPatch(currentSettings(app), patch.data);
  const data = {
    ...(patch.data.expectedSigningCertSha256 !== undefined && { expectedSigningCertSha256: next.expectedSigningCertSha256 }),
    ...(patch.data.ipBlockedCountries !== undefined && { ipBlockedCountries: next.ipBlockedCountries }),
    ...(patch.data.ipAllowedCountries !== undefined && { ipAllowedCountries: next.ipAllowedCountries }),
    // A reset stores null (= defaults), so later changes to the defaults apply.
    ...(patch.data.riskRules !== undefined && {
      riskRules: patch.data.riskRules === null ? Prisma.DbNull : (next.riskRules as unknown as Prisma.InputJsonValue),
    }),
    ...(patch.data.attestationPolicy !== undefined && { attestationPolicy: next.attestationPolicy }),
    ...(patch.data.legacyIngestionEnabled !== undefined && { legacyIngestionEnabled: next.legacyIngestionEnabled }),
  };
  const [updated] = await prisma.$transaction([
    prisma.application.update({
      where: { id: app.id },
      data,
      select: {
        id: true, name: true, platform: true,
        expectedSigningCertSha256: true, ipBlockedCountries: true, ipAllowedCountries: true, riskRules: true,
        attestationPolicy: true, legacyIngestionEnabled: true,
      },
    }),
    prisma.applicationSettingsAuditLog.createMany({
      data: changes.map((c) => ({
        applicationId: app.id,
        action: "SETTINGS_UPDATED",
        field: c.field,
        oldValue: c.oldValue === null ? Prisma.JsonNull : (c.oldValue as Prisma.InputJsonValue),
        newValue: c.newValue === null ? Prisma.JsonNull : (c.newValue as Prisma.InputJsonValue),
        performedByUserId: req.user!.userId,
        ipAddress: req.ip,
      })),
    }),
  ]);
  res.json({
    application: { ...updated, riskRules: effectiveRiskRules(updated.riskRules) },
    changed: changes.map((c) => c.field),
  });
});

/**
 * Archives an application — never a hard delete. Every route scoped to
 * one application (`assertOwnedApplication` in dashboard/credentials/
 * webhooks routes, plus the ingestion middleware) additionally requires
 * `archivedAt: null`, so this single timestamp is what makes the app —
 * and, transitively, every `SecurityEvent`/`ApiCredential`/
 * `WebhookConfig` row it owns — disappear from the product without one
 * row actually being touched. The SDK's own credential also stops being
 * able to ship new events immediately (see `middleware/apiKey.ts`).
 */
appsRouter.delete("/:id", requireAdminRole, async (req: AuthedRequest, res) => {
  const app = await prisma.application.findFirst({
    where: { id: req.params.id, organizationId: req.user!.organizationId, archivedAt: null },
  });
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  await prisma.application.update({
    where: { id: app.id },
    data: { archivedAt: new Date() },
  });

  res.status(204).send();
});
