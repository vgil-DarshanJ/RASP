import path from "node:path";
import fs from "node:fs";
import { Router } from "express";
import archiver from "archiver";
import { SDK_CATALOG } from "./catalog";

export const sdkDistributionRouter = Router();

/** Public — the FE's platform-picker cards render straight off this,
 *  authenticated or not (it's marketing/reference metadata, not a secret). */
sdkDistributionRouter.get("/catalog", (_req, res) => {
  res.json({ platforms: SDK_CATALOG });
});

/**
 * Streams a zip of the local SDK source for `platform`. This is the
 * **local-dev-only** distribution mechanism — see `catalog.ts`'s doc for
 * why: a real deployment publishes versioned artifacts to a real package
 * registry instead of zipping source on every request. `SDK_SOURCE_ROOT`
 * must point at the `sdk_rasp` checkout (see `.env.example`).
 */
sdkDistributionRouter.get("/download/:platform", async (req, res) => {
  const entry = SDK_CATALOG.find(
    (s) => s.platform === req.params.platform.toUpperCase(),
  );

  if (!entry) return res.status(404).json({ error: "UNKNOWN_PLATFORM" });
  if (!entry.available || !entry.sourcePath) {
    return res.status(404).json({ error: "PLATFORM_NOT_YET_AVAILABLE" });
  }

  const sourceRoot = process.env.SDK_SOURCE_ROOT;
  if (!sourceRoot) {
    return res.status(500).json({ error: "SDK_SOURCE_ROOT_NOT_CONFIGURED" });
  }

  const existingDirs = entry.sourcePath
    .map((rel) => path.join(sourceRoot, rel))
    .filter((abs) => fs.existsSync(abs));

  if (existingDirs.length === 0) {
    return res.status(500).json({ error: "SDK_SOURCE_NOT_FOUND_ON_SERVER" });
  }

  res.setHeader("Content-Type", "application/zip");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="rasp-shield-${entry.platform.toLowerCase()}.zip"`,
  );

  const archive = archiver("zip", { zlib: { level: 9 } });
  archive.on("error", (err) => {
    console.error("[sdk-distribution] archive error:", err);
    if (!res.headersSent) res.status(500).end();
  });
  archive.pipe(res);

  for (const dir of existingDirs) {
    // Excludes build output / node_modules-equivalent clutter so the
    // download is source only, not gigabytes of Gradle/Flutter build cache.
    archive.glob("**/*", {
      cwd: dir,
      ignore: [
        "**/build/**",
        "**/.dart_tool/**",
        "**/.gradle/**",
        "**/node_modules/**",
      ],
    }, { prefix: path.basename(dir) });
  }

  await archive.finalize();
});
