// Visitor site / customer portal split. Runs with Node's own test runner and
// type stripping:  node --test lib/sites.test.ts
// Real: lib/sites.ts. Not covered: the redirect itself (components/site-guard.tsx, needs a browser).
import { test } from "node:test";
import assert from "node:assert/strict";

type SitesModule = typeof import("./sites");
const { siteRedirect, isVisitorOnlyPath }: SitesModule = await import(new URL("./sites.ts", import.meta.url).href);

const PORTAL = "http://192.168.2.208:5050";
const VISITOR = "http://192.168.2.208:6050";
const at = (origin: string, pathname: string, search = "", hash = "") => ({ origin, pathname, search, hash });

test("the visitor site keeps its own pages and sends everything else to the portal", () => {
  assert.equal(siteRedirect(at(VISITOR, "/"), PORTAL, VISITOR), null);
  assert.equal(siteRedirect(at(VISITOR, "/capabilities/root-detection"), PORTAL, VISITOR), null);
  assert.equal(siteRedirect(at(VISITOR, "/plans"), PORTAL, VISITOR), null);
  assert.equal(siteRedirect(at(VISITOR, "/login", "?next=1"), PORTAL, VISITOR), `${PORTAL}/login?next=1`);
  assert.equal(siteRedirect(at(VISITOR, "/dashboard"), PORTAL, VISITOR), `${PORTAL}/dashboard`);
  assert.equal(siteRedirect(at(VISITOR, "/status"), PORTAL, VISITOR), `${PORTAL}/status`);
});

test("the portal opens on the dashboard and sends visitor pages to the visitor site", () => {
  assert.equal(siteRedirect(at(PORTAL, "/"), PORTAL, VISITOR), "/dashboard");
  assert.equal(siteRedirect(at(PORTAL, "/capabilities", "", "#runtime"), PORTAL, VISITOR), `${VISITOR}/capabilities#runtime`);
  assert.equal(siteRedirect(at(PORTAL, "/plans"), PORTAL, VISITOR), null);
  assert.equal(siteRedirect(at(PORTAL, "/login"), PORTAL, VISITOR), null);
  assert.equal(siteRedirect(at(PORTAL, "/status"), PORTAL, VISITOR), null);
});

test("nothing is redirected when the sites are not configured or on another origin", () => {
  assert.equal(siteRedirect(at("http://localhost:5050", "/"), null, null), null);
  assert.equal(siteRedirect(at("http://localhost:5050", "/"), PORTAL, VISITOR), null);
  assert.equal(siteRedirect(at(PORTAL, "/"), PORTAL, PORTAL), null);
  assert.equal(isVisitorOnlyPath("/capabilitiesX"), false);
});
