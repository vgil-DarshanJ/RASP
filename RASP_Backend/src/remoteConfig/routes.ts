import { Router } from "express";
import { Prisma } from "@prisma/client";
import { prisma } from "../db/prisma";
import { AuthedRequest, requireAuth } from "../middleware/auth";
import { ApiKeyedRequest, requireApiKeyIdentity } from "../middleware/apiKey";
import { requireAdminRole } from "../auth/roles";
import type { RateCheck } from "../redis/deviceRateLimit";
import { checkRateLimit } from "../redis/rateLimit";
import { userRateLimiter } from "../redis/userRateLimit";
import { logError } from "../security/secretFields";
import {
  parsePublishBody,
  normalizeSettings,
  REMOTE_CONFIG_BOUNDS,
  REMOTE_MANAGEABLE_DETECTORS,
  RemoteSettings,
  SETTING_FIELDS,
  settingsChanges,
} from "./settings";
import { configKeyId, configSigningKey, signConfig } from "./signing";

/** The counter the device endpoint uses; tests replace `check`. */
export const configRateLimit: { check: RateCheck } = { check: checkRateLimit };

const WINDOW_SECONDS = 3600;
const limit = (name: string, fallback: number) => Number(process.env[name]) || fallback;
const DEVICE_KEY_ID = /^[A-Za-z0-9_-]{1,100}$/;

// ── Device side ─────────────────────────────────────────────────────────

export const deviceConfigRouter = Router();

/**
 * GET /v1/config — the application's active signed remote configuration.
 *
 * Identified by `X-Api-Key` (an ACTIVE credential of a non-archived app),
 * like GET /v1/reputation/list: the config is not secret, and its Ed25519
 * signature, checked on the phone, is what makes it trustworthy. The SDK
 * also sends `X-Device-Key-Id` (its registered device key id) for the
 * per-device limit, and `If-None-Match: "<version>"` with the version it
 * already has → 304 Not Modified.
 *
 * Limited per client IP, per API key and per device key (hourly windows).
 * 404 REMOTE_CONFIG_NONE: nothing published. 404 REMOTE_CONFIG_EXPIRED: the
 * active version has expired (the phone then keeps its last good config
 * until that one expires too). 503 REMOTE_CONFIG_SIGNING_UNAVAILABLE: the
 * server has no CONFIG_SIGNING_KEY — never an unsigned config.
 */
deviceConfigRouter.get(
  "/",
  async (req, res, next) => {
    const ok = await configRateLimit.check(`config:ip:${req.ip ?? "unknown"}`, limit("CONFIG_RATE_LIMIT_PER_IP", 600), WINDOW_SECONDS);
    if (!ok.allowed) return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED", limit: "ip" });
    next();
  },
  requireApiKeyIdentity,
  async (req: ApiKeyedRequest, res) => {
    const deviceKeyId = req.header("X-Device-Key-Id");
    const buckets: Array<[string, string, number]> = [
      ["api_key", `config:app:${req.applicationId}`, limit("CONFIG_RATE_LIMIT_PER_API_KEY", 50_000)],
    ];
    if (deviceKeyId && DEVICE_KEY_ID.test(deviceKeyId)) {
      buckets.push(["device", `config:device:${req.applicationId}:${deviceKeyId}`, limit("CONFIG_RATE_LIMIT_PER_DEVICE", 30)]);
    }
    for (const [name, key, max] of buckets) {
      if (!(await configRateLimit.check(key, max, WINDOW_SECONDS)).allowed) {
        return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED", limit: name });
      }
    }

    const active = await prisma.remoteConfig.findFirst({
      where: { applicationId: req.applicationId, active: true },
      select: { applicationId: true, version: true, createdAt: true, expiresAt: true, payload: true },
    });
    if (!active) return res.status(404).json({ error: "REMOTE_CONFIG_NONE" });
    const key = configSigningKey();
    if (!key) return res.status(503).json({ error: "REMOTE_CONFIG_SIGNING_UNAVAILABLE" });
    if (active.expiresAt.getTime() <= Date.now()) return res.status(404).json({ error: "REMOTE_CONFIG_EXPIRED" });

    res.setHeader("Cache-Control", "no-store");
    res.setHeader("ETag", `"${active.version}"`);
    if (requestedVersion(req.header("If-None-Match")) === active.version) return res.status(304).end();
    res.json(signConfig(active, key));
  },
);

/** `"7"`, `W/"7"` or `7` → 7; anything else → null. */
function requestedVersion(header: string | undefined): number | null {
  const match = header?.trim().match(/^(?:W\/)?"?(\d{1,10})"?$/);
  return match ? Number(match[1]) : null;
}

// ── Dashboard side ──────────────────────────────────────────────────────

/** Mounted at /v1/apps/:id/remote-config. */
export const remoteConfigAdminRouter = Router({ mergeParams: true });
remoteConfigAdminRouter.use(requireAuth);

const writeRateLimit = userRateLimiter({ scope: "remote_config", perUser: 30, perIp: 120, windowSeconds: 60 });

/** What the dashboard shows next to the editor, so the rules are stated in one place. */
const LIMITS = {
  fields: SETTING_FIELDS,
  detectors: REMOTE_MANAGEABLE_DETECTORS,
  bounds: REMOTE_CONFIG_BOUNDS,
  neverRemote: [
    "ingestion URL", "credential (API key / secret)", "device key and evidence-envelope settings",
    "TLS pins and their enforcement", "request signing", "screenshot and clipboard protection",
    "detectors outside the app's own allowed list (remoteManagedDetectors)",
  ],
};

async function ownedApp(applicationId: string, organizationId: string) {
  return prisma.application.findFirst({ where: { id: applicationId, organizationId, archivedAt: null }, select: { id: true } });
}

const versionSelect = {
  id: true, version: true, payload: true, createdByUserId: true, createdAt: true, expiresAt: true, active: true,
  copiedFromVersion: true,
} as const;

async function emails(userIds: string[]) {
  const users = await prisma.user.findMany({ where: { id: { in: [...new Set(userIds)] } }, select: { id: true, email: true } });
  return new Map(users.map((u) => [u.id, u.email]));
}

/** GET /v1/apps/:id/remote-config — current version, history, audit trail and the rules (OWNER/ADMIN). */
remoteConfigAdminRouter.get("/", requireAdminRole, async (req: AuthedRequest, res) => {
  const app = await ownedApp(req.params.id, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const [versions, audit] = await Promise.all([
    prisma.remoteConfig.findMany({ where: { applicationId: app.id }, orderBy: { version: "desc" }, take: 50, select: versionSelect }),
    prisma.remoteConfigAudit.findMany({
      where: { applicationId: app.id },
      orderBy: { performedAt: "desc" },
      take: 50,
      select: { id: true, action: true, version: true, fromVersion: true, changes: true, performedByUserId: true, performedAt: true, ipAddress: true },
    }),
  ]);
  const byId = await emails([...versions.map((v) => v.createdByUserId), ...audit.map((a) => a.performedByUserId)]);
  const now = Date.now();
  const show = (v: (typeof versions)[number]) => ({
    version: v.version,
    settings: normalizeSettings((v.payload ?? {}) as RemoteSettings),
    active: v.active,
    expired: v.expiresAt.getTime() <= now,
    createdAt: v.createdAt,
    expiresAt: v.expiresAt,
    createdByEmail: byId.get(v.createdByUserId) ?? "(deleted user)",
    copiedFromVersion: v.copiedFromVersion,
  });

  res.json({
    signingConfigured: configSigningKey() !== null,
    keyId: configKeyId(),
    current: versions.find((v) => v.active) ? show(versions.find((v) => v.active)!) : null,
    history: versions.map(show),
    audit: audit.map(({ performedByUserId, ...a }) => ({ ...a, performedByEmail: byId.get(performedByUserId) ?? "(deleted user)" })),
    limits: LIMITS,
  });
});

type PublishOutcome =
  | { ok: true; version: number }
  | { ok: false; status: number; error: string };

/**
 * Publishes [settings] as the next version (one above the highest ever
 * published) and makes it the only active one, with an audit row naming
 * every changed field. Versions never repeat or go down, so a phone that
 * has version N never accepts N or lower again.
 */
async function publish(args: {
  applicationId: string;
  settings: RemoteSettings;
  expiresInDays: number;
  userId: string;
  ip: string | undefined;
  action: "PUBLISHED" | "ROLLED_BACK";
  fromVersion?: number;
}): Promise<PublishOutcome> {
  try {
    const version = await prisma.$transaction(async (tx) => {
      const latest = await tx.remoteConfig.findFirst({ where: { applicationId: args.applicationId }, orderBy: { version: "desc" }, select: { version: true } });
      const previous = await tx.remoteConfig.findFirst({ where: { applicationId: args.applicationId, active: true }, select: { payload: true } });
      const next = (latest?.version ?? 0) + 1;
      await tx.remoteConfig.updateMany({ where: { applicationId: args.applicationId, active: true }, data: { active: false } });
      const created = await tx.remoteConfig.create({
        data: {
          applicationId: args.applicationId,
          version: next,
          payload: args.settings as Prisma.InputJsonValue,
          createdByUserId: args.userId,
          expiresAt: new Date(Date.now() + args.expiresInDays * 86_400_000),
          active: true,
          copiedFromVersion: args.fromVersion ?? null,
        },
        select: { id: true },
      });
      await tx.remoteConfigAudit.create({
        data: {
          applicationId: args.applicationId,
          remoteConfigId: created.id,
          action: args.action,
          version: next,
          fromVersion: args.fromVersion ?? null,
          changes: settingsChanges((previous?.payload ?? null) as RemoteSettings | null, args.settings) as Prisma.InputJsonValue,
          performedByUserId: args.userId,
          ipAddress: args.ip ?? null,
        },
      });
      return next;
    });
    return { ok: true, version };
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
      return { ok: false, status: 409, error: "REMOTE_CONFIG_VERSION_CONFLICT" };
    }
    logError("[remoteConfig] publish failed:", err);
    return { ok: false, status: 500, error: "REMOTE_CONFIG_PUBLISH_FAILED" };
  }
}

/** PUT /v1/apps/:id/remote-config — publish `{ settings, expiresInDays? }` as a new version (OWNER/ADMIN). */
remoteConfigAdminRouter.put("/", requireAdminRole, writeRateLimit, async (req: AuthedRequest, res) => {
  const app = await ownedApp(req.params.id, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });
  const parsed = parsePublishBody(req.body);
  if (!parsed.ok) return res.status(400).json({ error: parsed.error, details: parsed.details });
  // Refuse to publish what no device could verify.
  if (!configSigningKey()) return res.status(503).json({ error: "REMOTE_CONFIG_SIGNING_UNAVAILABLE" });

  const result = await publish({
    applicationId: app.id, settings: parsed.data.settings, expiresInDays: parsed.data.expiresInDays,
    userId: req.user!.userId, ip: req.ip, action: "PUBLISHED",
  });
  if (!result.ok) return res.status(result.status).json({ error: result.error });
  res.status(201).json({ version: result.version });
});

/**
 * POST /v1/apps/:id/remote-config/rollback `{ version, expiresInDays? }` —
 * publishes a copy of an older version's settings as a NEW, higher version
 * (OWNER/ADMIN). The old row itself is never reactivated: phones only accept
 * higher versions.
 */
remoteConfigAdminRouter.post("/rollback", requireAdminRole, writeRateLimit, async (req: AuthedRequest, res) => {
  const app = await ownedApp(req.params.id, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });
  const body = (req.body ?? {}) as { version?: unknown; expiresInDays?: unknown };
  const extra = Object.keys(body).filter((k) => k !== "version" && k !== "expiresInDays");
  const bounds = REMOTE_CONFIG_BOUNDS.expiresInDays;
  const days = body.expiresInDays === undefined ? bounds.default : body.expiresInDays;
  if (extra.length > 0 || !Number.isInteger(body.version) || !Number.isInteger(days) || (days as number) < bounds.min || (days as number) > bounds.max) {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }
  if (!configSigningKey()) return res.status(503).json({ error: "REMOTE_CONFIG_SIGNING_UNAVAILABLE" });

  const source = await prisma.remoteConfig.findFirst({
    where: { applicationId: app.id, version: body.version as number },
    select: { version: true, payload: true },
  });
  if (!source) return res.status(404).json({ error: "REMOTE_CONFIG_VERSION_NOT_FOUND" });

  const result = await publish({
    applicationId: app.id, settings: normalizeSettings((source.payload ?? {}) as RemoteSettings), expiresInDays: days as number,
    userId: req.user!.userId, ip: req.ip, action: "ROLLED_BACK", fromVersion: source.version,
  });
  if (!result.ok) return res.status(result.status).json({ error: result.error });
  res.status(201).json({ version: result.version, copiedFromVersion: source.version });
});

/**
 * The country lists of the application's active, unexpired remote config,
 * when it sets them — GET /v1/ip-risk uses these in place of the
 * application's own lists. `undefined` for a list the config does not set.
 */
export async function activeRemoteCountries(applicationId: string): Promise<{ blocked?: string[]; allowed?: string[] }> {
  const active = await prisma.remoteConfig.findFirst({
    where: { applicationId, active: true, expiresAt: { gt: new Date() } },
    select: { payload: true },
  });
  const s = (active?.payload ?? {}) as RemoteSettings;
  return { blocked: s.blockedCountries, allowed: s.allowedCountries };
}
