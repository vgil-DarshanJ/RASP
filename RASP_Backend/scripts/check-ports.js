#!/usr/bin/env node
/**
 * Checks every port this project uses, before you deploy alongside other
 * projects on the same server. Run this ON THE SERVER (or any machine you
 * want to check) — it needs nothing but Node itself, no OS-specific tools
 * (lsof/netstat/ss), so it behaves identically on Windows, Linux, and macOS.
 *
 * Usage:
 *   node scripts/check-ports.js
 *
 * ## Why this connects instead of trying to bind
 *
 * The first version of this script tried to `listen()` on each port and
 * treated an `EADDRINUSE` error as "in use." That is WRONG on Windows: by
 * default, Windows does not set exclusive address use on a listening
 * socket, so a second process can successfully bind to a port another
 * process is already listening on — verified here with a real dummy
 * listener plus `netstat` as ground truth, which showed the port
 * genuinely occupied while the bind-based check still reported it FREE.
 * That is exactly the false negative this script exists to prevent, so
 * it now checks the way an actual client would: attempt a real TCP
 * *connection* to the port. If something accepts the connection, the
 * port is in use, regardless of platform-specific bind-exclusivity rules.
 *
 * Reads the same env var names as the actual app (PORT, DATABASE_URL's
 * port, REDIS_URL's port) so this stays in sync automatically if you
 * change a port in your .env — it does not duplicate a second hardcoded
 * list to drift out of date.
 */
const net = require("net");

function extractPort(urlLike, fallback) {
  try {
    const url = new URL(urlLike);
    return Number(url.port) || fallback;
  } catch {
    return fallback;
  }
}

const PORTS = [
  { port: Number(process.env.PORT) || 4444, label: "Backend API (Express)" },
  { port: Number(process.env.FRONTEND_PORT) || 5050, label: "Customer portal (Next.js)" },
  { port: Number(process.env.VISITOR_PORT) || 6050, label: "Visitor site (Next.js)" },
  { port: extractPort(process.env.DATABASE_URL, 5432), label: "Postgres" },
  { port: extractPort(process.env.REDIS_URL, 6379), label: "Redis" },
];

const CONNECT_TIMEOUT_MS = 800;

/**
 * Tries to open a real TCP connection to `port` on 127.0.0.1. A successful
 * connect means SOMETHING is listening there (in use); a connection
 * refusal means nothing is (free). A timeout is reported honestly as
 * "could not determine" rather than guessed either way — e.g. a firewall
 * silently dropping the packet looks identical to "nothing there" over
 * the wire, and this script would rather say so than risk a false FREE.
 */
function checkPort(port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(CONNECT_TIMEOUT_MS);

    socket.once("connect", () => {
      finish({ status: "IN USE", detail: "a service accepted a connection on this port" });
    });

    socket.once("timeout", () => {
      finish({ status: "UNKNOWN", detail: "connection attempt timed out — could not determine (firewall?)" });
    });

    socket.once("error", (err) => {
      if (err.code === "ECONNREFUSED") {
        finish({ status: "FREE", detail: "connection refused — nothing is listening" });
      } else {
        finish({ status: "UNKNOWN", detail: err.message });
      }
    });

    socket.connect(port, "127.0.0.1");
  });
}

async function main() {
  console.log("Checking ports this project needs (via real TCP connect, not bind)...\n");
  const results = [];
  for (const { port, label } of PORTS) {
    const result = await checkPort(port);
    results.push({ port, label, ...result });
  }

  const portWidth = 6;
  const labelWidth = Math.max(...results.map((r) => r.label.length)) + 2;
  const statusWidth = 9;

  console.log(
    "PORT".padEnd(portWidth) + "USED FOR".padEnd(labelWidth) + "STATUS".padEnd(statusWidth) + "DETAIL",
  );
  console.log("-".repeat(portWidth + labelWidth + statusWidth + 55));

  let anyConflict = false;
  let anyUnknown = false;
  for (const r of results) {
    if (r.status === "IN USE") anyConflict = true;
    if (r.status === "UNKNOWN") anyUnknown = true;
    console.log(
      String(r.port).padEnd(portWidth) +
        r.label.padEnd(labelWidth) +
        r.status.padEnd(statusWidth) +
        r.detail,
    );
  }

  console.log();
  if (anyConflict) {
    console.log(
      "⚠ One or more ports are already taken on this machine. Either stop " +
        "whatever else is using them, or change this project's port for the " +
        "conflicting service (PORT for the backend, FRONTEND_PORT for the frontend, " +
        "or the port in DATABASE_URL/REDIS_URL) " +
        "before deploying here.",
    );
  }
  if (anyUnknown) {
    console.log(
      "? One or more ports could not be confirmed either way (timeout) — " +
        "check manually before assuming they're free.",
    );
  }
  if (!anyConflict && !anyUnknown) {
    console.log("✓ All 4 ports are free — no conflicts on this machine.");
  }
  process.exitCode = anyConflict ? 1 : 0;
}

main();
