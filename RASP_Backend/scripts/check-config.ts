/**
 * Checks this machine's .env against the server's startup rules (F-18)
 * without starting it. Prints only problem descriptions, never values.
 *
 *   npm run check:config
 */
import "dotenv/config";
import { configurationProblems } from "../src/startupChecks";

const problems = configurationProblems();
if (problems.length === 0) {
  console.log("configuration OK");
} else {
  for (const problem of problems) console.log(`- ${problem}`);
  process.exitCode = 1;
}
