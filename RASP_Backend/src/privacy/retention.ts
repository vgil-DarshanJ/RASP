import { prisma } from "../db/prisma";

/**
 * Data retention (WP-11 privacy): rows older than the configured number of
 * days are deleted. 0 (the default) keeps everything — the period is the
 * customer's decision (DPIA), set per deployment:
 * - RETENTION_SECURITY_EVENT_DAYS: security events and the signed envelopes
 *   they came in;
 * - RETENTION_RISK_EVENT_DAYS: session and transaction risk events, and
 *   account-device bindings not seen since;
 * - RETENTION_DEVICE_LOCATION_DAYS: each device's latest shared location
 *   (the 20-point trail is already limited to 7 days).
 * Event periods below 8 days are raised to 8: envelopes up to 7 days old are
 * still accepted, and their nonces must stay known until then.
 *
 * Runs once a day inside the server (startRetentionSchedule) and on demand
 * with `npm run retention:run`.
 */
const DAY_MS = 24 * 60 * 60 * 1000;
const MIN_EVENT_DAYS = 8;

export interface RetentionSettings {
  securityEventDays: number;
  riskEventDays: number;
  deviceLocationDays: number;
}

function days(name: string, minimum = 1): number {
  const value = Number(process.env[name]);
  if (!Number.isFinite(value) || value <= 0) return 0;
  return Math.max(minimum, Math.floor(value));
}

export function retentionSettings(): RetentionSettings {
  return {
    securityEventDays: days("RETENTION_SECURITY_EVENT_DAYS", MIN_EVENT_DAYS),
    riskEventDays: days("RETENTION_RISK_EVENT_DAYS", MIN_EVENT_DAYS),
    deviceLocationDays: days("RETENTION_DEVICE_LOCATION_DAYS"),
  };
}

export interface RetentionReport {
  securityEvents: number;
  envelopes: number;
  sessionEvents: number;
  transactionEvents: number;
  accountDeviceBindings: number;
  deviceLocations: number;
}

type Db = Pick<typeof prisma, "securityEvent" | "evidenceEnvelope" | "sessionEvent" | "transactionEvent" | "accountDeviceBinding" | "deviceLocation">;

/** Deletes what is past its period. Events before their envelopes (foreign key). */
export async function runRetention(now = new Date(), settings = retentionSettings(), db: Db = prisma): Promise<RetentionReport> {
  const report: RetentionReport = { securityEvents: 0, envelopes: 0, sessionEvents: 0, transactionEvents: 0, accountDeviceBindings: 0, deviceLocations: 0 };
  const before = (d: number) => new Date(now.getTime() - d * DAY_MS);
  if (settings.securityEventDays > 0) {
    const cutoff = before(settings.securityEventDays);
    report.securityEvents = (await db.securityEvent.deleteMany({ where: { receivedAt: { lt: cutoff } } })).count;
    report.envelopes = (await db.evidenceEnvelope.deleteMany({ where: { receivedAt: { lt: cutoff } } })).count;
  }
  if (settings.riskEventDays > 0) {
    const cutoff = before(settings.riskEventDays);
    report.sessionEvents = (await db.sessionEvent.deleteMany({ where: { receivedAt: { lt: cutoff } } })).count;
    report.transactionEvents = (await db.transactionEvent.deleteMany({ where: { receivedAt: { lt: cutoff } } })).count;
    report.accountDeviceBindings = (await db.accountDeviceBinding.deleteMany({ where: { lastSeenAt: { lt: cutoff } } })).count;
  }
  if (settings.deviceLocationDays > 0) {
    report.deviceLocations = (await db.deviceLocation.deleteMany({ where: { receivedAt: { lt: before(settings.deviceLocationDays) } } })).count;
  }
  return report;
}

/** Daily run inside the server when any period is set; timers never keep the process alive. */
export function startRetentionSchedule(log: (message: string) => void = console.log): () => void {
  const settings = retentionSettings();
  if (settings.securityEventDays === 0 && settings.riskEventDays === 0 && settings.deviceLocationDays === 0) return () => {};
  const run = () => {
    runRetention(new Date(), settings)
      .then((r) => log(`[retention] deleted ${JSON.stringify(r)}`))
      .catch((err) => log(`[retention] failed: ${err instanceof Error ? err.message : String(err)}`));
  };
  const first = setTimeout(run, 60_000);
  const daily = setInterval(run, DAY_MS);
  first.unref();
  daily.unref();
  return () => {
    clearTimeout(first);
    clearInterval(daily);
  };
}
