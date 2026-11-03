import { NextFunction, Response } from "express";
import type { AuthedRequest } from "../middleware/auth";

/**
 * Who may do what in an organization (F-10):
 * - OWNER and ADMIN: everything, including actions that cut an app off or
 *   reveal secrets — archive an application, issue / revoke / restore /
 *   delete credentials, create / change / delete webhooks, rotate their
 *   secret, send a test alert, change security settings, invite people.
 * - MEMBER: read-only (dashboards, devices, events, exports, settings).
 */
export const ADMIN_ROLES = new Set(["OWNER", "ADMIN"]);

export function isAdminRole(role: string | undefined): boolean {
  return role !== undefined && ADMIN_ROLES.has(role);
}

/** After requireAuth: 403 FORBIDDEN_ROLE unless the caller is OWNER or ADMIN. */
export function requireAdminRole(req: AuthedRequest, res: Response, next: NextFunction) {
  if (!isAdminRole(req.user?.role)) return res.status(403).json({ error: "FORBIDDEN_ROLE" });
  next();
}
