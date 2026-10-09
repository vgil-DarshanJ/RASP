// In-memory stand-in for the Prisma client, for HTTP-level tests that run
// the real routers without Postgres. It follows Prisma's result shape where
// it matters for leak tests: without `select` a query returns EVERY scalar
// column of the row (secrets included), `select` returns only the listed
// fields, `include` adds relations. So a route that forgets an explicit field
// list leaks here exactly as it would in production.
//
// Supported: findMany / findFirst / findUnique / count / create (with nested
// `create`) / createMany / update / updateMany / upsert / delete / deleteMany /
// groupBy (always []), where-filters (equality, null, in, notIn, not, compound
// unique keys such as `applicationId_deviceId`,
// contains + mode, startsWith, gt/gte/lt/lte, AND/OR/NOT, to-one relation
// filters, some/every/none), orderBy, take, skip, cursor, distinct,
// $transaction (callback and array) and $queryRaw (always []).
// Anything else throws, so an unsupported query fails loudly.
import { Prisma } from "@prisma/client";
import { prisma } from "../src/db/prisma";

export type Row = Record<string, unknown>;
type Relation = { model: string; kind: "one" | "many"; from: string; to: string };

const one = (model: string, from: string, to = "id"): Relation => ({ model, kind: "one", from, to });
const many = (model: string, to: string, from = "id"): Relation => ({ model, kind: "many", from, to });

const RELATIONS: Record<string, Record<string, Relation>> = {
  organization: { users: many("user", "organizationId"), applications: many("application", "organizationId") },
  user: { organization: one("organization", "organizationId"), passwordResetTokens: many("passwordResetToken", "userId") },
  passwordResetToken: { user: one("user", "userId") },
  application: {
    organization: one("organization", "organizationId"),
    credentials: many("apiCredential", "applicationId"),
    events: many("securityEvent", "applicationId"),
    webhooks: many("webhookConfig", "applicationId"),
    devices: many("deviceRegistration", "applicationId"),
    settingsAuditLogs: many("applicationSettingsAuditLog", "applicationId"),
    accountDeviceBindings: many("accountDeviceBinding", "applicationId"),
    sessionEvents: many("sessionEvent", "applicationId"),
    transactionEvents: many("transactionEvent", "applicationId"),
    deviceLocations: many("deviceLocation", "applicationId"),
    deviceLocationPoints: many("deviceLocationPoint", "applicationId"),
  },
  apiCredential: { application: one("application", "applicationId"), auditLogs: many("credentialAuditLog", "credentialId") },
  credentialAuditLog: { credential: one("apiCredential", "credentialId") },
  securityEvent: { application: one("application", "applicationId"), envelope: one("evidenceEnvelope", "envelopeId") },
  evidenceEnvelope: { deviceRegistration: one("deviceRegistration", "deviceRegistrationId"), events: many("securityEvent", "envelopeId") },
  webhookConfig: { application: one("application", "applicationId") },
  applicationSettingsAuditLog: { application: one("application", "applicationId") },
  deviceRegistration: { application: one("application", "applicationId"), envelopes: many("evidenceEnvelope", "deviceRegistrationId") },
  accountDeviceBinding: { application: one("application", "applicationId") },
  sessionEvent: { application: one("application", "applicationId") },
  transactionEvent: { application: one("application", "applicationId") },
  deviceLocation: { application: one("application", "applicationId") },
  deviceLocationPoint: { application: one("application", "applicationId") },
};

export const MODELS = Object.keys(RELATIONS);

/** Column defaults the schema would fill in. */
const DEFAULTS: Record<string, () => Row> = {
  organization: () => ({ createdAt: new Date() }),
  user: () => ({ role: "OWNER", createdAt: new Date(), tokenVersion: 0 }),
  passwordResetToken: () => ({ createdAt: new Date(), requestIp: null }),
  application: () => ({
    createdAt: new Date(), archivedAt: null, expectedSigningCertSha256: null, ipBlockedCountries: [],
    ipAllowedCountries: [], accountHashSalt: null, riskRules: null, attestationPolicy: "RECORD", legacyIngestionEnabled: false,
  }),
  apiCredential: () => ({ status: "ACTIVE", createdAt: new Date(), rotatedAt: null, revokedAt: null, deletedAt: null }),
  credentialAuditLog: () => ({ performedAt: new Date(), ipAddress: null }),
  applicationSettingsAuditLog: () => ({
    field: null, oldValue: null, newValue: null, performedByUserId: null, performedAt: new Date(), ipAddress: null,
  }),
  webhookConfig: () => ({
    minSeverity: "HIGH", enabled: true, createdAt: new Date(), updatedAt: new Date(),
    lastTriggeredAt: null, lastStatusCode: null, lastError: null,
  }),
  securityEvent: () => ({ receivedAt: new Date() }),
  deviceRegistration: () => ({ createdAt: new Date(), lastRiskCounter: 0n }),
  accountDeviceBinding: () => ({ firstSeenAt: new Date(), lastSeenAt: new Date() }),
  sessionEvent: () => ({ receivedAt: new Date() }),
  transactionEvent: () => ({ receivedAt: new Date() }),
  deviceLocation: () => ({ latitude: null, longitude: null, accuracyM: null, isMock: null, capturedAt: null, lastCounter: 0n }),
  deviceLocationPoint: () => ({ accuracyM: null, receivedAt: new Date() }),
};

export class FakeDatabase {
  readonly tables: Record<string, Row[]> = Object.fromEntries(MODELS.map((m) => [m, []]));
  private seq = 0;
  /** Set to make one model method throw (e.g. to test error handling). */
  failures: Partial<Record<string, (args: Row) => Error | undefined>> = {};

  rows(model: string): Row[] {
    const rows = this.tables[model];
    if (!rows) throw new Error(`fake prisma: unknown model ${model}`);
    return rows;
  }

  insert(model: string, data: Row): Row {
    const relations = RELATIONS[model] ?? {};
    const scalars: Row = {};
    const nested: [Relation, Row | Row[]][] = [];
    for (const [key, value] of Object.entries(data)) {
      const rel = relations[key];
      if (rel) {
        const create = (value as { create?: Row | Row[] }).create;
        if (!create) throw new Error(`fake prisma: only nested create is supported (${model}.${key})`);
        nested.push([rel, create]);
      } else {
        scalars[key] = normalize(value);
      }
    }
    const row: Row = { ...(DEFAULTS[model]?.() ?? {}), ...scalars };
    if (row.id === undefined) row.id = `${model}-${++this.seq}`;
    this.rows(model).push(row);
    for (const [rel, create] of nested) {
      for (const child of Array.isArray(create) ? create : [create]) this.insert(rel.model, { ...child, [rel.to]: row[rel.from] });
    }
    return row;
  }

  matches(model: string, row: Row, where?: Row): boolean {
    if (!where) return true;
    for (const [key, cond] of Object.entries(where)) {
      if (cond === undefined) continue;
      if (key === "AND") {
        if (!asArray(cond).every((w) => this.matches(model, row, w))) return false;
        continue;
      }
      if (key === "OR") {
        if (!(cond as Row[]).some((w) => this.matches(model, row, w))) return false;
        continue;
      }
      if (key === "NOT") {
        if (asArray(cond).some((w) => this.matches(model, row, w))) return false;
        continue;
      }
      const rel = RELATIONS[model]?.[key];
      if (rel?.kind === "one") {
        const related = this.relatedOne(rel, row);
        if (cond === null) {
          if (related) return false;
        } else if (!related || !this.matches(rel.model, related, cond as Row)) return false;
        continue;
      }
      if (!rel && isCompoundKey(key, cond)) {
        if (!this.matches(model, row, cond as Row)) return false;
        continue;
      }
      if (rel?.kind === "many") {
        const related = this.relatedMany(rel, row);
        const c = cond as { some?: Row; every?: Row; none?: Row };
        if (c.some && !related.some((r) => this.matches(rel.model, r, c.some))) return false;
        if (c.every && !related.every((r) => this.matches(rel.model, r, c.every))) return false;
        if (c.none && related.some((r) => this.matches(rel.model, r, c.none))) return false;
        continue;
      }
      if (!matchValue(row[key], cond)) return false;
    }
    return true;
  }

  relatedOne(rel: Relation, row: Row): Row | undefined {
    return this.rows(rel.model).find((r) => r[rel.to] === row[rel.from]);
  }

  relatedMany(rel: Relation, row: Row): Row[] {
    return this.rows(rel.model).filter((r) => r[rel.to] === row[rel.from]);
  }

  query(model: string, args: Row = {}): Row[] {
    let rows = this.rows(model).filter((r) => this.matches(model, r, args.where as Row | undefined));
    rows = order(rows, args.orderBy);
    if (args.cursor) {
      const cursor = args.cursor as Row;
      const index = rows.findIndex((r) => Object.entries(cursor).every(([k, v]) => r[k] === v));
      rows = index < 0 ? [] : rows.slice(index);
    }
    if (typeof args.skip === "number") rows = rows.slice(args.skip);
    if (Array.isArray(args.distinct)) {
      const seen = new Set<string>();
      rows = rows.filter((r) => {
        const key = JSON.stringify((args.distinct as string[]).map((f) => r[f]));
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    }
    if (typeof args.take === "number") rows = rows.slice(0, args.take);
    return rows;
  }

  /** Prisma's result shape: all scalars, or only `select`ed fields; plus `include`d relations. */
  project(model: string, row: Row, args: Row = {}): Row {
    const relations = RELATIONS[model] ?? {};
    const out: Row = {};
    if (args.select) {
      for (const [key, spec] of Object.entries(args.select as Row)) {
        if (!spec) continue;
        if (key === "_count") throw new Error("fake prisma: _count is not supported");
        const rel = relations[key];
        out[key] = rel ? this.resolve(rel, row, spec === true ? {} : (spec as Row)) : copy(row[key]);
      }
      return out;
    }
    for (const [key, value] of Object.entries(row)) out[key] = copy(value);
    for (const [key, spec] of Object.entries((args.include as Row | undefined) ?? {})) {
      if (!spec) continue;
      const rel = relations[key];
      if (!rel) throw new Error(`fake prisma: unknown relation ${model}.${key}`);
      out[key] = this.resolve(rel, row, spec === true ? {} : (spec as Row));
    }
    return out;
  }

  private resolve(rel: Relation, row: Row, spec: Row): unknown {
    if (rel.kind === "one") {
      const related = this.relatedOne(rel, row);
      return related ? this.project(rel.model, related, spec) : null;
    }
    let rows = this.relatedMany(rel, row).filter((r) => this.matches(rel.model, r, spec.where as Row | undefined));
    rows = order(rows, spec.orderBy);
    if (typeof spec.take === "number") rows = rows.slice(0, spec.take);
    return rows.map((r) => this.project(rel.model, r, spec));
  }

  private fail(model: string, method: string, args: Row) {
    const error = this.failures[`${model}.${method}`]?.(args);
    if (error) throw error;
  }

  delegate(model: string) {
    const db = this;
    const findFirst = async (args: Row = {}) => {
      db.fail(model, "findFirst", args);
      const row = db.query(model, args)[0];
      return row ? db.project(model, row, args) : null;
    };
    return {
      findMany: async (args: Row = {}) => {
        db.fail(model, "findMany", args);
        return db.query(model, args).map((r) => db.project(model, r, args));
      },
      findFirst,
      findUnique: findFirst,
      count: async (args: Row = {}) => db.query(model, args).length,
      groupBy: async () => [],
      create: async (args: Row) => {
        db.fail(model, "create", args);
        return db.project(model, db.insert(model, args.data as Row), args);
      },
      createMany: async (args: Row) => {
        db.fail(model, "createMany", args);
        const data = asArray(args.data);
        for (const d of data) db.insert(model, d);
        return { count: data.length };
      },
      update: async (args: Row) => {
        db.fail(model, "update", args);
        const row = db.rows(model).find((r) => db.matches(model, r, args.where as Row));
        if (!row) throw new Error(`fake prisma: ${model}.update: record not found`);
        applyData(model, row, args.data as Row);
        return db.project(model, row, args);
      },
      updateMany: async (args: Row) => {
        db.fail(model, "updateMany", args);
        const rows = db.rows(model).filter((r) => db.matches(model, r, args.where as Row | undefined));
        for (const row of rows) applyData(model, row, args.data as Row);
        return { count: rows.length };
      },
      upsert: async (args: Row) => {
        db.fail(model, "upsert", args);
        const row = db.rows(model).find((r) => db.matches(model, r, args.where as Row));
        if (row) applyData(model, row, args.update as Row);
        return db.project(model, row ?? db.insert(model, args.create as Row), args);
      },
      delete: async (args: Row) => {
        const table = db.rows(model);
        const index = table.findIndex((r) => db.matches(model, r, args.where as Row));
        if (index < 0) throw new Error(`fake prisma: ${model}.delete: record not found`);
        return table.splice(index, 1)[0];
      },
      deleteMany: async (args: Row = {}) => {
        const table = db.rows(model);
        const keep = table.filter((r) => !db.matches(model, r, args.where as Row | undefined));
        const count = table.length - keep.length;
        table.splice(0, table.length, ...keep);
        return { count };
      },
    };
  }

  /** A plain client object with every delegate — what `$transaction(fn)` hands to `fn`. */
  client(): Row {
    const client: Row = Object.fromEntries(MODELS.map((m) => [m, this.delegate(m)]));
    client.$transaction = async (arg: unknown) =>
      typeof arg === "function" ? (arg as (tx: Row) => Promise<unknown>)(client) : Promise.all(arg as Promise<unknown>[]);
    client.$queryRaw = async () => [];
    return client;
  }
}

/**
 * Points the real `prisma` object at [db] (method by method, like the other
 * tests here do) and returns a function that restores the originals.
 */
export function installFakePrisma(db: FakeDatabase): () => void {
  const real = prisma as unknown as Record<string, Record<string, unknown>>;
  const fake = db.client();
  const restore: (() => void)[] = [];
  for (const model of MODELS) {
    const target = real[model];
    if (!target) throw new Error(`fake prisma: the generated client has no model ${model}; run prisma generate`);
    for (const [method, impl] of Object.entries(fake[model] as Row)) {
      const original = target[method];
      target[method] = impl;
      restore.push(() => { target[method] = original; });
    }
  }
  const client = prisma as unknown as Record<string, unknown>;
  for (const method of ["$transaction", "$queryRaw"]) {
    const original = client[method];
    client[method] = fake[method];
    restore.push(() => { client[method] = original; });
  }
  return () => restore.reverse().forEach((undo) => undo());
}

/** `{ applicationId_deviceId: { applicationId, deviceId } }`: a compound unique key's fields joined by `_`. */
function isCompoundKey(key: string, cond: unknown): boolean {
  if (cond === null || typeof cond !== "object" || Array.isArray(cond) || cond instanceof Date) return false;
  const fields = Object.keys(cond as Row);
  return fields.length > 1 && fields.join("_") === key;
}

function asArray(value: unknown): Row[] {
  return (Array.isArray(value) ? value : [value]) as Row[];
}

function normalize(value: unknown): unknown {
  if (value === Prisma.DbNull || value === Prisma.JsonNull) return null;
  return copy(value);
}

function copy(value: unknown): unknown {
  if (value instanceof Date) return new Date(value.getTime());
  if (Array.isArray(value) || (value !== null && typeof value === "object" && !(value instanceof Buffer))) {
    return structuredClone(value);
  }
  return value;
}

function applyData(model: string, row: Row, data: Row) {
  for (const [key, value] of Object.entries(data)) {
    if (RELATIONS[model]?.[key]) throw new Error(`fake prisma: nested writes in update are not supported (${model}.${key})`);
    if (value !== null && typeof value === "object" && "increment" in (value as Row)) {
      row[key] = ((row[key] as number | undefined) ?? 0) + ((value as Row).increment as number);
      continue;
    }
    row[key] = normalize(value);
  }
  if (model === "webhookConfig") row.updatedAt = new Date();
}

function comparable(value: unknown): number | string {
  if (value instanceof Date) return value.getTime();
  if (typeof value === "bigint") return Number(value);
  return value as number | string;
}

function matchValue(actual: unknown, cond: unknown): boolean {
  if (cond === null) return actual === null || actual === undefined;
  if (cond instanceof Date) return actual instanceof Date && actual.getTime() === cond.getTime();
  if (typeof cond !== "object" || Array.isArray(cond)) return actual === cond;
  const c = cond as Row;
  for (const [op, v] of Object.entries(c)) {
    switch (op) {
      case "equals":
        if (!matchValue(actual, v)) return false;
        break;
      case "in":
        if (!(v as unknown[]).includes(actual)) return false;
        break;
      case "notIn":
        if ((v as unknown[]).includes(actual)) return false;
        break;
      case "not":
        if (matchValue(actual, v)) return false;
        break;
      case "contains":
      case "startsWith": {
        const text = String(actual ?? "");
        const needle = String(v);
        const [a, b] = c.mode === "insensitive" ? [text.toLowerCase(), needle.toLowerCase()] : [text, needle];
        if (op === "contains" ? !a.includes(b) : !a.startsWith(b)) return false;
        break;
      }
      case "mode":
        break;
      case "gt":
        if (!(actual != null && comparable(actual) > comparable(v))) return false;
        break;
      case "gte":
        if (!(actual != null && comparable(actual) >= comparable(v))) return false;
        break;
      case "lt":
        if (!(actual != null && comparable(actual) < comparable(v))) return false;
        break;
      case "lte":
        if (!(actual != null && comparable(actual) <= comparable(v))) return false;
        break;
      default:
        throw new Error(`fake prisma: unsupported filter ${op}`);
    }
  }
  return true;
}

function order(rows: Row[], orderBy: unknown): Row[] {
  if (!orderBy) return rows;
  const keys = (Array.isArray(orderBy) ? orderBy : [orderBy]).flatMap((o) => Object.entries(o as Row)) as [string, string][];
  return [...rows].sort((a, b) => {
    for (const [field, direction] of keys) {
      const x = comparable(a[field]);
      const y = comparable(b[field]);
      if (x === y) continue;
      const result = x < y ? -1 : 1;
      return direction === "desc" ? -result : result;
    }
    return 0;
  });
}
