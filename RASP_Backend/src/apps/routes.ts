import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { AuthedRequest, requireAuth } from "../middleware/auth";

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
