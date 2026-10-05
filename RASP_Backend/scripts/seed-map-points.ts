/**
 * DEVELOPMENT ONLY — inserts 5 fake opted-in, located security events so the
 * dashboard Map page shows markers without a phone.
 *
 *   npm run seed:map-points                 # first application of the first organization
 *   npm run seed:map-points -- <applicationId>
 *   npm run seed:map-points -- --remove     # delete the rows this script inserted
 *
 * Refuses to run when NODE_ENV=production. The rows are clearly fake: device
 * ids start with "seed-map-", and each event's evidence carries
 * { key: "seed", value: "map-demo" }. Coordinates are city centres, not
 * anyone's location.
 */
import { Prisma, PrismaClient } from "@prisma/client";

const SEED_DEVICE_PREFIX = "seed-map-";

/** Fake points: a city centre, a detector and status, minutes ago. */
const SEED_POINTS: Array<{
  device: string;
  latitude: number;
  longitude: number;
  detectorId: string;
  status: "DETECTED" | "SECURE";
  minutesAgo: number;
}> = [
  { device: "0001", latitude: 19.076, longitude: 72.8777, detectorId: "root_jailbreak", status: "DETECTED", minutesAgo: 5 },
  { device: "0002", latitude: 28.6139, longitude: 77.209, detectorId: "overlay", status: "DETECTED", minutesAgo: 40 },
  { device: "0003", latitude: 12.9716, longitude: 77.5946, detectorId: "vpn", status: "DETECTED", minutesAgo: 90 },
  { device: "0004", latitude: 19.0896, longitude: 72.8656, detectorId: "high_risk_ip", status: "SECURE", minutesAgo: 180 },
  { device: "0005", latitude: 51.5074, longitude: -0.1278, detectorId: "mock_location", status: "DETECTED", minutesAgo: 600 },
];

async function main() {
  if (process.env.NODE_ENV === "production") {
    console.error("seed-map-points: refusing to run with NODE_ENV=production");
    process.exit(1);
  }
  const prisma = new PrismaClient();
  try {
    const args = process.argv.slice(2);
    if (args.includes("--remove")) {
      const removed = await prisma.securityEvent.deleteMany({ where: { deviceId: { startsWith: SEED_DEVICE_PREFIX } } });
      console.log(`seed-map-points: removed ${removed.count} seeded events`);
      return;
    }

    const applicationId = args.find((a) => !a.startsWith("--"));
    const app = applicationId
      ? await prisma.application.findFirst({ where: { id: applicationId, archivedAt: null }, select: { id: true, name: true } })
      : await prisma.application.findFirst({
          where: { archivedAt: null, organization: { id: (await prisma.organization.findFirst({ orderBy: { createdAt: "asc" }, select: { id: true } }))?.id ?? "" } },
          orderBy: { createdAt: "asc" },
          select: { id: true, name: true },
        });
    if (!app) {
      console.error("seed-map-points: no application found (create one in the dashboard first, or pass its id)");
      process.exit(1);
    }

    const now = Date.now();
    const rows = SEED_POINTS.map((p) => {
      const at = new Date(now - p.minutesAgo * 60_000);
      return {
        applicationId: app.id,
        detectorId: p.detectorId,
        status: p.status,
        reason: null,
        deviceId: `${SEED_DEVICE_PREFIX}${p.device}`,
        deviceModel: "Seed Phone",
        manufacturer: "Seed",
        osPlatform: "android",
        sdkVersion: "seed",
        receivedAt: at,
        clientObservedAt: at,
        latitude: p.latitude,
        longitude: p.longitude,
        locationAccuracyM: 50,
        locationCapturedAt: at,
        locationOptIn: true,
        evidence: [
          { key: "seed", value: "map-demo", note: "fake development data" },
          { key: "location_opt_in", value: true, note: null },
          { key: "latitude", value: p.latitude, note: null },
          { key: "longitude", value: p.longitude, note: null },
          { key: "location_accuracy_m", value: 50, note: null },
          { key: "location_captured_at_millis", value: at.getTime(), note: null },
        ] as Prisma.InputJsonValue,
      };
    });
    const created = await prisma.securityEvent.createMany({ data: rows });
    console.log(`seed-map-points: inserted ${created.count} opted-in located events for application "${app.name}" (${app.id})`);
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error("seed-map-points failed:", err);
  process.exit(1);
});
