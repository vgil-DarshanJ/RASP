/**
 * DEVELOPMENT ONLY — inserts fake session and transaction risk events for
 * one application, so Live Threats, the device drawer and the security
 * settings page show fraud-risk data without a phone.
 *
 *   npm run seed:risk-events                  # first application of the first organization
 *   npm run seed:risk-events -- <applicationId>
 *   npm run seed:risk-events -- --remove      # delete the rows this script inserted
 *
 * Refuses to run when NODE_ENV=production. Everything it writes is clearly
 * fake: device ids and key ids start with "seed-risk-", sdkVersion is
 * "seed", accounts / sessions / beneficiaries are hashes of made-up ids
 * ("seed-account-1"...) with a throw-away salt, and coordinates are city
 * centres. The findings come from the real rules engine (src/risk/rules.ts)
 * with the application's thresholds.
 */
import crypto from "node:crypto";
import { Prisma, PrismaClient } from "@prisma/client";
import { accountHash } from "../src/risk/accountHashSalt";
import {
  AccountHistory,
  RiskEventFacts,
  RiskFinding,
  effectiveRiskRules,
  evaluateRiskRules,
} from "../src/risk/rules";
import { riskAlertEvidence } from "../src/risk/alerts";

const SEED_PREFIX = "seed-risk-";
const MIN = 60_000;

type Place = { latitude: number; longitude: number; country: string };
const MUMBAI: Place = { latitude: 19.08, longitude: 72.88, country: "IN" };
const LONDON: Place = { latitude: 51.51, longitude: -0.13, country: "GB" };

/** The scenario: one account, a second device far away, then a burst of transfers. */
interface SeedEvent {
  device: "1" | "2";
  minutesAgo: number;
  place: Place;
  session?: "login" | "resume" | "logout";
  beneficiary?: string;
}
const SCENARIO: SeedEvent[] = [
  { device: "1", minutesAgo: 240, place: MUMBAI, session: "login" },
  { device: "1", minutesAgo: 235, place: MUMBAI, beneficiary: "seed-beneficiary-1" },
  { device: "2", minutesAgo: 180, place: LONDON, session: "login" },
  ...[0, 1, 2, 3, 4, 5].map((i): SeedEvent => ({ device: "2", minutesAgo: 170 - i, place: LONDON, beneficiary: `seed-beneficiary-${2 + (i % 3)}` })),
];

interface Past {
  deviceKeyId: string;
  type: "session" | "transaction";
  sessionHash: string;
  sessionEvent?: string;
  beneficiaryHash?: string;
  eventTime: Date;
  place: Place;
}

function historyFor(facts: RiskEventFacts, past: Past[], bindings: Map<string, Date>, windows: { session: number; tx: number }): AccountHistory {
  const before = past.filter((p) => p.eventTime < facts.eventTime);
  const located = before.at(-1);
  return {
    bindings: [...bindings.entries()].map(([deviceKeyId, firstSeenAt]) => ({ deviceKeyId, firstSeenAt })),
    recentSessions: before
      .filter((p) => p.type === "session" && p.eventTime.getTime() >= facts.eventTime.getTime() - windows.session * MIN)
      .map((p) => ({ deviceKeyId: p.deviceKeyId, sessionHash: p.sessionHash, sessionEvent: p.sessionEvent!, eventTime: p.eventTime })),
    lastLocated: located
      ? { deviceKeyId: located.deviceKeyId, location: { ...located.place, capturedAt: located.eventTime } }
      : null,
    lastIpCountry: located ? { country: located.place.country, receivedAt: located.eventTime, deviceKeyId: located.deviceKeyId } : null,
    recentTransactionCount: before.filter((p) => p.type === "transaction" && p.eventTime.getTime() > facts.eventTime.getTime() - windows.tx * MIN).length,
    beneficiarySeenBefore: before.some((p) => p.beneficiaryHash && p.beneficiaryHash === facts.beneficiaryHash),
  };
}

async function main() {
  if (process.env.NODE_ENV === "production") {
    console.error("seed-risk-events: refusing to run with NODE_ENV=production");
    process.exit(1);
  }
  const prisma = new PrismaClient();
  try {
    const args = process.argv.slice(2);
    if (args.includes("--remove")) {
      const regs = await prisma.deviceRegistration.findMany({ where: { deviceKeyId: { startsWith: SEED_PREFIX } }, select: { id: true } });
      const regIds = regs.map((r) => r.id);
      const removed = await prisma.$transaction([
        prisma.securityEvent.deleteMany({ where: { deviceId: { startsWith: SEED_PREFIX } } }),
        prisma.sessionEvent.deleteMany({ where: { deviceRegistrationId: { in: regIds } } }),
        prisma.transactionEvent.deleteMany({ where: { deviceRegistrationId: { in: regIds } } }),
        prisma.accountDeviceBinding.deleteMany({ where: { deviceKeyId: { startsWith: SEED_PREFIX } } }),
        prisma.deviceRegistration.deleteMany({ where: { id: { in: regIds } } }),
      ]);
      console.log(`seed-risk-events: removed ${removed.map((r) => r.count).join(" / ")} (alerts / sessions / transactions / bindings / devices)`);
      return;
    }

    const applicationId = args.find((a) => !a.startsWith("--"));
    const firstOrg = await prisma.organization.findFirst({ orderBy: { createdAt: "asc" }, select: { id: true } });
    const app = applicationId
      ? await prisma.application.findFirst({ where: { id: applicationId, archivedAt: null }, select: { id: true, name: true, riskRules: true } })
      : await prisma.application.findFirst({
          where: { archivedAt: null, organizationId: firstOrg?.id ?? "" },
          orderBy: { createdAt: "asc" },
          select: { id: true, name: true, riskRules: true },
        });
    if (!app) {
      console.error("seed-risk-events: no application found (create one in the dashboard first, or pass its id)");
      process.exit(1);
    }

    const rules = effectiveRiskRules(app.riskRules);
    const salt = crypto.randomBytes(32).toString("hex"); // throw-away: seeded ids never match real ones
    const run = crypto.randomBytes(3).toString("hex");
    const account = accountHash(salt, `seed-account-1-${run}`);
    const now = Date.now();

    const devices = new Map<string, { id: string; deviceKeyId: string; deviceId: string }>();
    for (const n of ["1", "2"]) {
      const deviceKeyId = `${SEED_PREFIX}${run}-${n}`;
      const reg = await prisma.deviceRegistration.create({
        data: {
          applicationId: app.id,
          appId: "seed.app",
          deviceId: deviceKeyId,
          deviceKeyId,
          publicKey: "seed-not-a-key",
          attestationChain: [],
          attestationStatus: "UNPARSEABLE",
          attestationVerdict: "unverified",
          attestationDetails: { seed: true },
          sdkVersion: "seed",
        },
        select: { id: true },
      });
      devices.set(n, { id: reg.id, deviceKeyId, deviceId: deviceKeyId });
    }

    const past: Past[] = [];
    const bindings = new Map<string, Date>();
    const sessionHashes = new Map<string, string>();
    let sessions = 0;
    let transactions = 0;
    let alerts = 0;

    for (const [i, e] of SCENARIO.entries()) {
      const device = devices.get(e.device)!;
      const at = new Date(now - e.minutesAgo * MIN);
      const sessionHash = sessionHashes.get(e.device) ?? accountHash(salt, `seed-session-${run}-${e.device}`);
      sessionHashes.set(e.device, sessionHash);
      const type = e.session ? "session" : "transaction";
      const beneficiaryHash = e.beneficiary ? accountHash(salt, `${e.beneficiary}-${run}`) : undefined;
      const facts: RiskEventFacts = {
        type,
        deviceKeyId: device.deviceKeyId,
        accountHash: account,
        sessionHash,
        sessionEvent: e.session,
        beneficiaryHash,
        eventTime: at,
        receivedAt: at,
        location: { latitude: e.place.latitude, longitude: e.place.longitude, capturedAt: at },
        ipCountry: e.place.country,
      };
      const findings: RiskFinding[] = evaluateRiskRules(
        facts,
        historyFor(facts, past, bindings, { session: rules.concurrentSessions.windowMinutes, tx: rules.transactionVelocity.windowMinutes }),
        rules,
      );

      const eventId = crypto.randomUUID();
      const common = {
        applicationId: app.id,
        deviceRegistrationId: device.id,
        deviceKeyId: device.deviceKeyId,
        eventId,
        nonce: crypto.randomBytes(16).toString("hex"),
        monotonicCounter: BigInt(i + 1),
        sdkVersion: "seed",
        accountHash: account,
        sessionHash,
        riskScore: null,
        riskVerdict: "UNKNOWN",
        latitude: e.place.latitude,
        longitude: e.place.longitude,
        locationCapturedAt: at,
        ipCountry: e.place.country,
        eventTime: at,
        receivedAt: at,
        signature: "seed",
        riskEvents: findings as unknown as Prisma.InputJsonValue,
      };
      if (type === "session") {
        await prisma.sessionEvent.create({ data: { ...common, sessionEvent: e.session! } });
        sessions++;
      } else {
        await prisma.transactionEvent.create({
          data: { ...common, beneficiaryHash: beneficiaryHash!, currency: "INR", channel: "upi", bindingSha256: accountHash(salt, `binding-${i}`) },
        });
        transactions++;
      }
      if (!bindings.has(device.deviceKeyId)) bindings.set(device.deviceKeyId, at);
      await prisma.accountDeviceBinding.upsert({
        where: { applicationId_accountHash_deviceKeyId: { applicationId: app.id, accountHash: account, deviceKeyId: device.deviceKeyId } },
        create: { applicationId: app.id, accountHash: account, deviceKeyId: device.deviceKeyId, deviceRegistrationId: device.id, firstSeenAt: at, lastSeenAt: at },
        update: { lastSeenAt: at },
      });
      if (findings.length > 0) {
        const source = { applicationId: app.id, deviceId: device.deviceId, sdkVersion: "seed", eventType: type, eventId, receivedAt: at, findings } as const;
        const created = await prisma.securityEvent.createMany({
          data: findings.map((f) => ({
            applicationId: app.id,
            detectorId: f.rule,
            status: "DETECTED",
            reason: f.explanation,
            evidence: [...riskAlertEvidence(source, f), { key: "seed", value: "risk-demo", note: "fake development data" }] as unknown as Prisma.InputJsonValue,
            deviceId: device.deviceId,
            deviceModel: "Seed Phone",
            osPlatform: "android",
            sdkVersion: "seed",
            receivedAt: at,
          })),
        });
        alerts += created.count;
      }
      past.push({ deviceKeyId: device.deviceKeyId, type, sessionHash, sessionEvent: e.session, beneficiaryHash, eventTime: at, place: e.place });
    }

    console.log(
      `seed-risk-events: application "${app.name}" (${app.id}): ${sessions} session events, ${transactions} transaction events, ` +
        `${alerts} rule alerts, devices ${[...devices.values()].map((d) => d.deviceKeyId).join(", ")}`,
    );
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error("seed-risk-events failed:", err);
  process.exit(1);
});
