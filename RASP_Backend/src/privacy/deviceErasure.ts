import { Router } from "express";
import { Prisma } from "@prisma/client";
import { prisma } from "../db/prisma";
import { AuthedRequest, requireAuth } from "../middleware/auth";
import { requireAdminRole } from "../auth/roles";

/**
 * Erases everything stored about one device of one application (WP-11:
 * deletion requests). DELETE
 * /v1/privacy/applications/:applicationId/devices/:deviceId — OWNER/ADMIN.
 *
 * `deviceId` is the id the dashboard shows: the stable device id from
 * registration, or the device key id, or a legacy SDK's id. Deleted:
 * security events with that id, the device's registrations (keys) found by
 * either id, their envelopes, session and transaction events and
 * account-device bindings, and the device's latest location and trail.
 * The settings audit log records who erased which device and the counts.
 */
export const privacyRouter = Router();
privacyRouter.use(requireAuth);

export interface ErasureCounts {
  securityEvents: number;
  envelopes: number;
  sessionEvents: number;
  transactionEvents: number;
  accountDeviceBindings: number;
  deviceRegistrations: number;
  deviceLocations: number;
  deviceLocationPoints: number;
}

export async function eraseDevice(applicationId: string, deviceId: string, tx: Prisma.TransactionClient): Promise<ErasureCounts> {
  const registrations = await tx.deviceRegistration.findMany({
    where: { applicationId, OR: [{ deviceId }, { deviceKeyId: deviceId }] },
    select: { id: true },
  });
  const registrationIds = registrations.map((r) => r.id);
  const envelopes = registrationIds.length
    ? await tx.evidenceEnvelope.findMany({ where: { deviceRegistrationId: { in: registrationIds } }, select: { id: true } })
    : [];
  const envelopeIds = envelopes.map((e) => e.id);

  const securityEvents =
    (await tx.securityEvent.deleteMany({ where: { applicationId, deviceId } })).count +
    (envelopeIds.length ? (await tx.securityEvent.deleteMany({ where: { envelopeId: { in: envelopeIds } } })).count : 0);
  const byRegistration = { deviceRegistrationId: { in: registrationIds } };
  const counts: ErasureCounts = {
    securityEvents,
    envelopes: registrationIds.length ? (await tx.evidenceEnvelope.deleteMany({ where: byRegistration })).count : 0,
    sessionEvents: registrationIds.length ? (await tx.sessionEvent.deleteMany({ where: byRegistration })).count : 0,
    transactionEvents: registrationIds.length ? (await tx.transactionEvent.deleteMany({ where: byRegistration })).count : 0,
    accountDeviceBindings: registrationIds.length ? (await tx.accountDeviceBinding.deleteMany({ where: byRegistration })).count : 0,
    deviceRegistrations: registrationIds.length ? (await tx.deviceRegistration.deleteMany({ where: { id: { in: registrationIds } } })).count : 0,
    deviceLocations: (await tx.deviceLocation.deleteMany({ where: { applicationId, deviceId } })).count,
    deviceLocationPoints: (await tx.deviceLocationPoint.deleteMany({ where: { applicationId, deviceId } })).count,
  };
  return counts;
}

privacyRouter.delete("/applications/:applicationId/devices/:deviceId", requireAdminRole, async (req: AuthedRequest, res) => {
  const deviceId = req.params.deviceId;
  if (!deviceId || deviceId.length > 200) return res.status(400).json({ error: "INVALID_DEVICE_ID" });
  const app = await prisma.application.findFirst({
    where: { id: req.params.applicationId, organizationId: req.user!.organizationId },
    select: { id: true },
  });
  if (!app) return res.status(404).json({ error: "APPLICATION_NOT_FOUND" });

  const counts = await prisma.$transaction(async (tx) => {
    const result = await eraseDevice(app.id, deviceId, tx);
    if (Object.values(result).some((n) => n > 0)) {
      await tx.applicationSettingsAuditLog.create({
        data: {
          applicationId: app.id,
          action: "DEVICE_DATA_ERASED",
          field: "deviceId",
          newValue: { deviceId, ...result } as unknown as Prisma.InputJsonValue,
          performedByUserId: req.user!.userId,
          ipAddress: req.ip,
        },
      });
    }
    return result;
  });
  if (Object.values(counts).every((n) => n === 0)) return res.status(404).json({ error: "DEVICE_NOT_FOUND" });
  res.json({ erased: counts });
});
