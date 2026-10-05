import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { AuthedRequest, requireAuth } from "../middleware/auth";
import { normalizeCertHash } from "../ingestion/tamperAlerts";
import { countrySet, toCountryCode } from "../ipRisk/ipRisk";

export const appsRouter = Router();
appsRouter.use(requireAuth);

const createAppSchema = z.object({
  name: z.string().min(1).max(120),
  platform: z.enum(["ANDROID_NATIVE", "FLUTTER", "IOS", "REACT_NATIVE"]),
});

/** Only ANDROID_NATIVE/FLUTTER have a real SDK today — see sdk-distribution
 *  for the catalog metadata the FE renders as "available" vs "coming soon"
 *  cards. Registration itself is not blocked for IOS/REACT_NATIVE (an org
 *  may want to reserve/plan an integration ahead of the SDK shipping), the
 *  download step is what's gated. */
appsRouter.post("/", async (req: AuthedRequest, res) => {
  const parsed = createAppSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_INPUT", details: parsed.error.flatten() });
  }

  const app = await prisma.application.create({
    data: {
      name: parsed.data.name,
      platform: parsed.data.platform,
      organizationId: req.user!.organizationId,
    },
  });

  res.status(201).json({ application: app });
});

appsRouter.get("/", async (req: AuthedRequest, res) => {
  const apps = await prisma.application.findMany({
    where: { organizationId: req.user!.organizationId, archivedAt: null },
    orderBy: { createdAt: "desc" },
    include: {
      credentials: {
        where: { status: "ACTIVE" },
        select: { id: true, apiKey: true, createdAt: true },
      },
    },
  });
  res.json({ applications: apps });
});

appsRouter.get("/:id", async (req: AuthedRequest, res) => {
  const app = await prisma.application.findFirst({
    where: { id: req.params.id, organizationId: req.user!.organizationId, archivedAt: null },
    include: { credentials: true },
  });
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });
  res.json({ application: app });
});

/** Roles allowed to change an application's security settings. */
const SECURITY_ADMIN_ROLES = new Set(["OWNER", "ADMIN"]);

export function canEditAppSecurity(role: string | undefined): boolean {
  return role !== undefined && SECURITY_ADMIN_ROLES.has(role);
}

const securityPatchSchema = z
  .object({
    /** 64 hex (':' separators allowed); null or "" clears it. */
    expectedSigningCertSha256: z.string().max(200).nullable().optional(),
    /** ISO 3166-1 alpha-2 codes; [] = use the server default blocked list. */
    ipBlockedCountries: z.array(z.string().max(10)).max(250).optional(),
    /** ISO 3166-1 alpha-2 codes; [] = no allow-list. */
    ipAllowedCountries: z.array(z.string().max(10)).max(250).optional(),
  })
  .strict();

export type AppSecurityPatch = {
  expectedSigningCertSha256?: string | null;
  ipBlockedCountries?: string[];
  ipAllowedCountries?: string[];
};

/**
 * Validates and normalizes a PATCH body: the hash to uppercase hex without
 * separators, country codes to unique uppercase ISO alpha-2. Pure.
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
  return { ok: true, data };
}

/**
 * PATCH /v1/apps/:id — security settings an OWNER/ADMIN sets per application:
 * - `expectedSigningCertSha256`: a tamper result reporting another hash
 *   raises a "tamper_signing_mismatch" alert (high);
 * - `ipBlockedCountries` / `ipAllowedCountries`: GET /v1/ip-risk policy.
 * MEMBER → 403 FORBIDDEN_ROLE.
 */
appsRouter.patch("/:id", async (req: AuthedRequest, res) => {
  if (!canEditAppSecurity(req.user?.role)) return res.status(403).json({ error: "FORBIDDEN_ROLE" });
  const patch = parseAppSecurityPatch(req.body);
  if (!patch.ok) return res.status(400).json({ error: patch.error, details: patch.details });

  const app = await prisma.application.findFirst({
    where: { id: req.params.id, organizationId: req.user!.organizationId, archivedAt: null },
    select: { id: true },
  });
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const updated = await prisma.application.update({
    where: { id: app.id },
    data: patch.data,
    select: {
      id: true, name: true, platform: true,
      expectedSigningCertSha256: true, ipBlockedCountries: true, ipAllowedCountries: true,
    },
  });
  res.json({ application: updated });
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
appsRouter.delete("/:id", async (req: AuthedRequest, res) => {
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
