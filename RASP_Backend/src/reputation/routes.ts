import { Router } from "express";
import { ApiKeyedRequest, requireApiKeyIdentity } from "../middleware/apiKey";
import { checkRateLimit } from "../redis/rateLimit";
import { currentList } from "./reputationList";

export const reputationRouter = Router();

/**
 * GET /v1/reputation/list — the signed malware reputation list for the
 * SDK (see reputationList.ts). Identified by `X-Api-Key` only: the list is
 * not secret and its signature, checked on the device, is what makes it
 * trustworthy. Limited per API key and per client IP (devices ask once a
 * day). 404 REPUTATION_LIST_NOT_CONFIGURED when the operator has not set
 * one up; 500 REPUTATION_LIST_INVALID when the file is unusable.
 */
reputationRouter.get("/list", requireApiKeyIdentity, async (req: ApiKeyedRequest, res) => {
  const windowSeconds = 3600;
  for (const [bucket, max] of [
    [`reputation:app:${req.applicationId}`, Number(process.env.REPUTATION_RATE_LIMIT_PER_API_KEY) || 20_000],
    [`reputation:ip:${req.ip ?? "unknown"}`, Number(process.env.REPUTATION_RATE_LIMIT_PER_IP) || 600],
  ] as const) {
    if (!(await checkRateLimit(bucket, max, windowSeconds)).allowed) return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED" });
  }
  const result = currentList();
  if (!result.ok) return res.status(result.error === "REPUTATION_LIST_NOT_CONFIGURED" ? 404 : 500).json({ error: result.error });
  res.setHeader("Cache-Control", "no-store");
  res.json(result.list);
});
