import { NextFunction, Response, Router } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import { verifyAttestationChain } from "../crypto/ecdsa";
import crypto from "node:crypto";

export const devicesRouter = Router();

/**
 * POST /v1/devices/register
 *
 * Registers a device's ECDSA P-256 public key for evidence envelope verification.
 * Called by the SDK on first run (or after key rotation) to register the
 * device's hardware-backed identity key with the backend.
 *
 * Request body:
 * - deviceId: The SDK's device_id (ANDROID_ID or install-scoped UUID)
 * - publicKey: Base64-encoded X.509 SPKI (EC P-256)
 * - attestationChain: Array of Base64-encoded DER certificates (leaf first)
 * - sdkVersion: The SDK version string
 */
const registerSchema = z.object({
  deviceId: z.string().min(1).max(200),
  publicKey: z.string().min(1), // Base64 X.509 SPKI
  attestationChain: z.array(z.string().min(1)).min(1),
  sdkVersion: z.string().min(1).max(50),
});

/** Computes deviceKeyId = SHA-256 of SPKI (Base64-encoded) */
function computeDeviceKeyId(publicKeyBase64: string): string {
  const spki = Buffer.from(publicKeyBase64, "base64");
  const digest = crypto.createHash("sha256").update(spki).digest();
  return digest.toString("base64");
}

devicesRouter.post("/register", async (req, res, next) => {
  // This endpoint uses the same API key auth as ingestion
  const apiKey = req.header("X-Api-Key");
  if (!apiKey) return res.status(401).json({ error: "MISSING_API_KEY" });

  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_REGISTER_BODY", details: parsed.error.flatten() });
  }

  // Look up the application from the API key
  const { prisma } = await import("../db/prisma");
  let credential;
  try {
    credential = await prisma.apiCredential.findUnique({
      where: { apiKey: req.header("X-Api-Key") ?? "" },
      include: { application: { select: { archivedAt: true, id: true } } },
    });
  } catch (err) {
    console.error("[deviceRegister] lookup failed:", err);
    return res.status(503).json({ error: "AUTH_BACKEND_UNAVAILABLE" });
  }

  if (!credential || credential.status !== "ACTIVE") {
    return res.status(401).json({ error: "INVALID_OR_REVOKED_API_KEY" });
  }
  if (credential.application.archivedAt) {
    return res.status(401).json({ error: "APPLICATION_ARCHIVED" });
  }

  const applicationId = credential.application.id;
  const { deviceId, publicKey, attestationChain, sdkVersion } = parsed.data;

  // Compute deviceKeyId (SHA-256 of SPKI)
  const deviceKeyId = computeDeviceKeyId(publicKey);

  // Verify the attestation chain matches the public key
  const chainValid = await import("../crypto/ecdsa").then(m => m.verifyAttestationChain(parsed.data.publicKey, attestationChain));
  const attestationResult = chainValid ? "valid" : "invalid";

  // Upsert the device registration
  try {
    const registration = await prisma.$transaction(async (tx) => {
      const existing = await tx.deviceRegistration.findUnique({
        where: { applicationId_deviceId: { applicationId, deviceId: parsed.data.deviceId } },
      });

      if (existing) {
        return tx.deviceRegistration.update({
          where: { id: existing.id },
          data: {
            publicKey: parsed.data.publicKey,
            attestationChain: parsed.data.attestationChain,
            sdkVersion: parsed.data.sdkVersion,
            lastSeenAt: new Date(),
          },
        });
      }

      return tx.deviceRegistration.create({
        data: {
          applicationId,
          deviceId: parsed.data.deviceId,
          deviceKeyId: computeDeviceKeyId(parsed.data.publicKey),
          publicKey: parsed.data.publicKey,
          attestationChain: parsed.data.attestationChain,
          sdkVersion: parsed.data.sdkVersion,
        },
      });
    });

    return res.status(201).json({ registered: true, attestationResult, deviceKeyId });
  } catch (err) {
    console.error("[deviceRegister] failed:", err);
    return res.status(500).json({ error: "REGISTRATION_FAILED" });
  }
});