import { Prisma } from "@prisma/client";
import { prisma } from "../db/prisma";
import { EnvelopeRepository, StoreResult } from "./envelope";

/**
 * Postgres-backed [EnvelopeRepository].
 *
 * `storeEnvelope` is one transaction: a compare-and-set on
 * `device_registrations.lastCounter` (only raised if currently lower), then
 * the envelope row, then its events. Two concurrent envelopes from one key
 * cannot both pass the counter rule, and the unique indexes on
 * (key, nonce), (key, counter) and eventId reject a replay that races the
 * pre-checks — the whole transaction rolls back in that case.
 */
export const prismaEnvelopeRepository: EnvelopeRepository = {
  async findDeviceKey(deviceKeyId) {
    return prisma.deviceRegistration.findUnique({
      where: { deviceKeyId },
      select: { id: true, applicationId: true, appId: true, deviceId: true, publicKey: true, lastCounter: true },
    });
  },

  async findEnvelopeByEventId(eventId) {
    return prisma.evidenceEnvelope.findUnique({
      where: { eventId },
      select: { deviceRegistrationId: true, signature: true },
    });
  },

  async isNonceUsed(deviceRegistrationId, nonce) {
    const row = await prisma.evidenceEnvelope.findUnique({
      where: { deviceRegistrationId_nonce: { deviceRegistrationId, nonce } },
      select: { id: true },
    });
    return row !== null;
  },

  async storeEnvelope(input): Promise<StoreResult> {
    const { device, envelope } = input;
    const counter = BigInt(envelope.monotonicCounter);
    try {
      return await prisma.$transaction(async (tx) => {
        const raised = await tx.deviceRegistration.updateMany({
          where: { id: device.id, lastCounter: { lt: counter } },
          data: { lastCounter: counter, lastSeenAt: input.receivedAt },
        });
        if (raised.count !== 1) return { outcome: "counter_not_increasing" as const };

        const stored = await tx.evidenceEnvelope.create({
          data: {
            eventId: envelope.eventId,
            deviceRegistrationId: device.id,
            applicationId: device.applicationId,
            monotonicCounter: counter,
            nonce: envelope.nonce,
            eventTime: new Date(envelope.eventTimeMillis),
            receivedAt: input.receivedAt,
            signedPayload: input.signedPayload,
            signature: envelope.signature,
          },
          select: { id: true },
        });

        const events = await tx.securityEvent.createManyAndReturn({
          data: input.events.map((e) => ({
            applicationId: device.applicationId,
            detectorId: e.detectorId,
            status: e.status,
            evidence: e.evidence == null ? undefined : (e.evidence as Prisma.InputJsonValue),
            reason: e.reason,
            // The registered device id if the SDK sent one, else the key id — stable per key.
            deviceId: device.deviceId ?? envelope.deviceKeyId,
            sdkVersion: envelope.sdkVersion,
            clientObservedAt: e.clientObservedAt,
            receivedAt: input.receivedAt,
            ipAddress: input.ipAddress,
            envelopeId: stored.id,
          })),
          select: {
            id: true, detectorId: true, status: true, deviceId: true,
            deviceModel: true, osPlatform: true, receivedAt: true, evidence: true,
          },
        });
        return { outcome: "stored" as const, events };
      });
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
        const target = JSON.stringify(err.meta?.target ?? "");
        if (target.includes("nonce")) return { outcome: "nonce_reused" };
        if (target.includes("eventId")) return { outcome: "event_id_reused" };
        if (target.includes("monotonicCounter")) return { outcome: "counter_not_increasing" };
      }
      throw err;
    }
  },
};
