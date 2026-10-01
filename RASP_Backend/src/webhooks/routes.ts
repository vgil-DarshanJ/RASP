import { Router } from "express";
import crypto from "node:crypto";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { AuthedRequest, requireAuth } from "../middleware/auth";
import { encryptSecret } from "../crypto/secretBox";
import { deliver } from "./dispatch";

export const webhooksRouter = Router();
webhooksRouter.use(requireAuth);

async function assertOwnedApplication(applicationId: string, organizationId: string) {
  return prisma.application.findFirst({ where: { id: applicationId, organizationId, archivedAt: null } });
}

function serialize(config: {
  id: string;
  url: string;
  minSeverity: string;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastTriggeredAt: Date | null;
  lastStatusCode: number | null;
  lastError: string | null;
}) {
  // Never returns `secretEncrypted` or its plaintext — same one-time-reveal
  // rule as `ApiCredential`'s own secret (see credentials/routes.ts).
  return {
    id: config.id,
    url: config.url,
    minSeverity: config.minSeverity,
    enabled: config.enabled,
    createdAt: config.createdAt,
    updatedAt: config.updatedAt,
    lastTriggeredAt: config.lastTriggeredAt,
    lastStatusCode: config.lastStatusCode,
    lastError: config.lastError,
  };
}

webhooksRouter.get("/applications/:applicationId", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const config = await prisma.webhookConfig.findUnique({ where: { applicationId: app.id } });
  res.json({ webhook: config ? serialize(config) : null });
});

const upsertSchema = z.object({
  url: z.string().url().max(500),
  minSeverity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("HIGH"),
  enabled: z.boolean().default(true),
});

/**
 * Creates or updates the one webhook config for an application. Only a
 * fresh CREATE generates and reveals a new secret (once, in this
 * response, exactly like `POST /credentials`) — updating URL/threshold/
 * enabled on an existing config keeps its current secret untouched, so
 * rotating the secret is a deliberate separate action (`/rotate-secret`
 * below), not a side effect of an unrelated edit.
 */
webhooksRouter.put("/applications/:applicationId", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const parsed = upsertSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "INVALID_BODY", details: parsed.error.flatten() });
  const { url, minSeverity, enabled } = parsed.data;

  const existing = await prisma.webhookConfig.findUnique({ where: { applicationId: app.id } });

  if (existing) {
    const updated = await prisma.webhookConfig.update({
      where: { applicationId: app.id },
      data: { url, minSeverity, enabled },
    });
    return res.json({ webhook: serialize(updated), secret: null });
  }

  const secret = crypto.randomBytes(32).toString("hex");
  const created = await prisma.webhookConfig.create({
    data: { applicationId: app.id, url, minSeverity, enabled, secretEncrypted: encryptSecret(secret) },
  });
  res.status(201).json({ webhook: serialize(created), secret });
});

webhooksRouter.post("/applications/:applicationId/rotate-secret", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const existing = await prisma.webhookConfig.findUnique({ where: { applicationId: app.id } });
  if (!existing) return res.status(404).json({ error: "WEBHOOK_NOT_CONFIGURED" });

  const secret = crypto.randomBytes(32).toString("hex");
  const updated = await prisma.webhookConfig.update({
    where: { applicationId: app.id },
    data: { secretEncrypted: encryptSecret(secret) },
  });
  res.json({ webhook: serialize(updated), secret });
});

webhooksRouter.delete("/applications/:applicationId", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  await prisma.webhookConfig.deleteMany({ where: { applicationId: app.id } });
  res.status(204).send();
});

/** Sends one synthetic delivery through the exact same `deliver()` path
 *  production alerts use — deliberately bypasses the `enabled`/severity
 *  gate (a "test" click should always fire, even while a customer has
 *  the config paused mid-setup) so the FE can offer a "Send test alert"
 *  button that proves the URL/secret actually work end-to-end. */
webhooksRouter.post("/applications/:applicationId/test", async (req: AuthedRequest, res) => {
  const app = await assertOwnedApplication(req.params.applicationId, req.user!.organizationId);
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const config = await prisma.webhookConfig.findUnique({ where: { applicationId: app.id } });
  if (!config) return res.status(404).json({ error: "WEBHOOK_NOT_CONFIGURED" });

  await deliver(config.id, config.url, config.secretEncrypted, {
    applicationId: app.id,
    applicationName: app.name,
    detectorId: "root_jailbreak",
    severity: "critical",
    status: "DETECTED",
    deviceId: "test-device",
    deviceModel: "Test Delivery",
    osPlatform: "android",
    receivedAt: new Date().toISOString(),
    evidence: [{ key: "note", value: "This is a test alert from RASP Shield — no real threat was detected." }],
  });

  const refreshed = await prisma.webhookConfig.findUnique({ where: { applicationId: app.id } });
  res.json({ webhook: refreshed ? serialize(refreshed) : null });
});
