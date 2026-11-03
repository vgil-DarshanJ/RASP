/**
 * Deletes data past its retention period once, then exits — for a cron job
 * when the server's own daily run is not wanted. Periods: see
 * src/privacy/retention.ts (RETENTION_* in .env; 0 or unset keeps data).
 *
 *   npm run retention:run
 */
import "dotenv/config";
import { prisma } from "../src/db/prisma";
import { retentionSettings, runRetention } from "../src/privacy/retention";

async function main() {
  const settings = retentionSettings();
  console.log(`retention periods (days, 0 = keep): ${JSON.stringify(settings)}`);
  console.log(`deleted: ${JSON.stringify(await runRetention(new Date(), settings))}`);
}

main()
  .catch((err) => {
    console.error(`retention run failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
