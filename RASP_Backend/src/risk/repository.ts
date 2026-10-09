import { Prisma } from "@prisma/client";
import { prisma } from "../db/prisma";
import { POLICY_SELECT, rowMeetsPolicy } from "../devices/attestationPolicy";
import { revocationCheckEnabled } from "../crypto/attestationTrust";
import { RiskEventRepository, StoreRiskEventInput, StoreRiskResult } from "./riskEvents";
import { AccountHistory, historyWindows } from "./rules";

const MINUTE_MS = 60_000;
/** Bounds on history reads, so one busy account cannot make a request expensive. */
const MAX_BINDINGS = 500;
const MAX_RECENT_SESSIONS = 500;

/** Thrown inside the transaction to roll back the counter raise on a replay. */
class ReplayDetected extends Error {
  constructor(public duplicate: boolean) {
    super("replayed");
  }
}

type Tx = Prisma.TransactionClient;

async function loadHistory(tx: Tx, input: StoreRiskEventInput): Promise<AccountHistory> {
  const { facts, rules } = input;
  const applicationId = input.device.applicationId;
  const account = { applicationId, accountHash: facts.accountHash };
  const windows = historyWindows(rules);

  const bindings = await tx.accountDeviceBinding.findMany({
    where: account,
    select: { deviceKeyId: true, firstSeenAt: true },
    orderBy: { firstSeenAt: "desc" },
    take: MAX_BINDINGS,
  });

  const recentSessions = facts.type === "session"
    ? await tx.sessionEvent.findMany({
        where: {
          ...account,
          eventTime: { gte: new Date(facts.eventTime.getTime() - windows.concurrentSessionsMinutes * MINUTE_MS), lte: facts.eventTime },
        },
        select: { deviceKeyId: true, sessionHash: true, sessionEvent: true, eventTime: true },
        orderBy: { eventTime: "desc" },
        take: MAX_RECENT_SESSIONS,
      })
    : [];

  let lastLocated: AccountHistory["lastLocated"] = null;
  if (facts.location) {
    const where = { ...account, locationCapturedAt: { not: null, lt: facts.location.capturedAt }, latitude: { not: null }, longitude: { not: null } };
    const select = { deviceKeyId: true, latitude: true, longitude: true, locationCapturedAt: true } as const;
    const orderBy = { locationCapturedAt: "desc" } as const;
    const candidates = [
      await tx.sessionEvent.findFirst({ where, select, orderBy }),
      await tx.transactionEvent.findFirst({ where, select, orderBy }),
    ].filter((r): r is NonNullable<typeof r> => r !== null);
    const latest = candidates.sort((a, b) => b.locationCapturedAt!.getTime() - a.locationCapturedAt!.getTime())[0];
    if (latest) {
      lastLocated = {
        deviceKeyId: latest.deviceKeyId,
        location: { latitude: latest.latitude!, longitude: latest.longitude!, capturedAt: latest.locationCapturedAt! },
      };
    }
  }

  let lastIpCountry: AccountHistory["lastIpCountry"] = null;
  if (facts.ipCountry) {
    const where = { ...account, ipCountry: { not: null } };
    const select = { deviceKeyId: true, ipCountry: true, receivedAt: true } as const;
    const orderBy = { receivedAt: "desc" } as const;
    const candidates = [
      await tx.sessionEvent.findFirst({ where, select, orderBy }),
      await tx.transactionEvent.findFirst({ where, select, orderBy }),
    ].filter((r): r is NonNullable<typeof r> => r !== null);
    const latest = candidates.sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime())[0];
    if (latest) lastIpCountry = { country: latest.ipCountry!, receivedAt: latest.receivedAt, deviceKeyId: latest.deviceKeyId };
  }

  let recentTransactionCount = 0;
  let beneficiarySeenBefore = false;
  if (facts.type === "transaction") {
    recentTransactionCount = await tx.transactionEvent.count({
      where: {
        ...account,
        eventTime: { gt: new Date(facts.eventTime.getTime() - windows.transactionVelocityMinutes * MINUTE_MS), lte: facts.eventTime },
      },
    });
    beneficiarySeenBefore = (await tx.transactionEvent.findFirst({
      where: { ...account, beneficiaryHash: facts.beneficiaryHash },
      select: { id: true },
    })) !== null;
  }

  return { bindings, recentSessions, lastLocated, lastIpCountry, recentTransactionCount, beneficiarySeenBefore };
}

/**
 * Postgres-backed [RiskEventRepository]. `storeRiskEvent` is one
 * transaction: the compare-and-set on `device_registrations.lastRiskCounter`
 * locks the device row, so two events of one key are processed one after
 * the other; the nonce/eventId re-check across both event tables then
 * cannot race. A replay found there rolls the counter raise back.
 */
export const prismaRiskEventRepository: RiskEventRepository = {
  async findDeviceKey(deviceKeyId) {
    const row = await prisma.deviceRegistration.findUnique({
      where: { deviceKeyId },
      select: { id: true, applicationId: true, deviceId: true, publicKey: true, lastRiskCounter: true, ...POLICY_SELECT },
    });
    if (!row) return null;
    const { application, attestationVerdict, possessionVerified, attestationDetails, ...device } = row;
    return {
      ...device,
      meetsAttestationPolicy: rowMeetsPolicy({ appId: row.appId, attestationVerdict, possessionVerified, attestationDetails, application }, revocationCheckEnabled()),
    };
  },

  async findRiskRules(applicationId) {
    const app = await prisma.application.findUnique({ where: { id: applicationId }, select: { riskRules: true } });
    return app?.riskRules ?? null;
  },

  async findByEventId(deviceRegistrationId, eventId) {
    const where = { deviceRegistrationId_eventId: { deviceRegistrationId, eventId } };
    return (await prisma.sessionEvent.findUnique({ where, select: { signature: true } }))
      ?? (await prisma.transactionEvent.findUnique({ where, select: { signature: true } }));
  },

  async isNonceUsed(deviceRegistrationId, nonce) {
    const where = { deviceRegistrationId_nonce: { deviceRegistrationId, nonce } };
    return (await prisma.sessionEvent.findUnique({ where, select: { id: true } })) !== null
      || (await prisma.transactionEvent.findUnique({ where, select: { id: true } })) !== null;
  },

  async storeRiskEvent(input): Promise<StoreRiskResult> {
    const { device, envelope, facts } = input;
    const counter = BigInt(envelope.monotonicCounter);
    try {
      return await prisma.$transaction(async (tx) => {
        const raised = await tx.deviceRegistration.updateMany({
          where: { id: device.id, lastRiskCounter: { lt: counter } },
          data: { lastRiskCounter: counter, lastSeenAt: facts.receivedAt },
        });
        if (raised.count !== 1) throw new ReplayDetected(false);

        const sameKey = { deviceRegistrationId: device.id, OR: [{ nonce: envelope.nonce }, { eventId: envelope.eventId }] };
        const earlier = (await tx.sessionEvent.findFirst({ where: sameKey, select: { eventId: true, signature: true } }))
          ?? (await tx.transactionEvent.findFirst({ where: sameKey, select: { eventId: true, signature: true } }));
        if (earlier) throw new ReplayDetected(earlier.eventId === envelope.eventId && earlier.signature === envelope.signature);

        const findings = input.evaluate(await loadHistory(tx, input));

        const common = {
          applicationId: device.applicationId,
          deviceRegistrationId: device.id,
          deviceKeyId: envelope.deviceKeyId,
          eventId: envelope.eventId,
          nonce: envelope.nonce,
          monotonicCounter: counter,
          sdkVersion: envelope.sdkVersion,
          accountHash: envelope.accountHash,
          sessionHash: envelope.sessionHash,
          riskScore: envelope.riskScore,
          riskVerdict: envelope.riskVerdict,
          latitude: facts.location?.latitude ?? null,
          longitude: facts.location?.longitude ?? null,
          locationCapturedAt: facts.location?.capturedAt ?? null,
          ipCountry: facts.ipCountry,
          eventTime: facts.eventTime,
          receivedAt: facts.receivedAt,
          signature: envelope.signature,
          riskEvents: findings as unknown as Prisma.InputJsonValue,
        };
        const row = envelope.type === "session"
          ? await tx.sessionEvent.create({ data: { ...common, sessionEvent: envelope.sessionEvent }, select: { id: true } })
          : await tx.transactionEvent.create({
              data: {
                ...common,
                beneficiaryHash: envelope.beneficiaryHash,
                currency: envelope.currency,
                channel: envelope.channel,
                bindingSha256: envelope.bindingSha256,
              },
              select: { id: true },
            });

        await tx.accountDeviceBinding.upsert({
          where: {
            applicationId_accountHash_deviceKeyId: {
              applicationId: device.applicationId,
              accountHash: envelope.accountHash,
              deviceKeyId: envelope.deviceKeyId,
            },
          },
          create: {
            applicationId: device.applicationId,
            accountHash: envelope.accountHash,
            deviceKeyId: envelope.deviceKeyId,
            deviceRegistrationId: device.id,
            firstSeenAt: facts.receivedAt,
            lastSeenAt: facts.receivedAt,
          },
          update: { lastSeenAt: facts.receivedAt },
        });

        return { outcome: "stored" as const, eventRowId: row.id, findings };
      });
    } catch (err) {
      if (err instanceof ReplayDetected) return { outcome: "replayed", duplicate: err.duplicate };
      // A unique index caught a replay that raced the checks.
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
        const target = JSON.stringify(err.meta?.target ?? "");
        if (target.includes("nonce") || target.includes("eventId")) return { outcome: "replayed", duplicate: false };
      }
      throw err;
    }
  },
};
