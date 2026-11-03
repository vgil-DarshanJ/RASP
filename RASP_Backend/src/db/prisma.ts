import { PrismaClient } from "@prisma/client";

// Single shared instance — Prisma's own recommendation, avoids exhausting
// the Postgres connection pool under `tsx watch`'s module-reload churn.
export const prisma = new PrismaClient({
  log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
});
