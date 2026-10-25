import assert from "node:assert/strict";
import { test } from "node:test";
import { once } from "node:events";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import Database from "better-sqlite3";
import express from "express";
import { createPortalAuth, createPortalAuthAsync } from "../dist/index.js";

const location = { id: 1, key: "hamilton", name: "Hamilton", is_mule: true };
const nonMule = { id: 2, key: "commissary", name: "Commissary", is_mule: false };
const context = (overrides = {}) => ({
  email: "person@example.invalid", name: "Synthetic Person", role: "manager",
  roles: ["manager", "finance"], is_admin: false, status: "active", active: true,
  locations: [location], apps: ["hr"], app_permissions: { hr: ["processor"] },
  ctx_version: 1, ...overrides,
});
const directory = (overrides = {}) => ({
  syncedAt: new Date().toISOString(), locations: [location],
  people: [{ email: "person@example.invalid", name: "Synthetic Person", role: "manager",
    roles: ["manager", "finance"], status: "active", locations: [location],
    permissions: ["processor"], ctx_version: 1, last_login: null }], ...overrides,
});

async function listen(t, handler) {
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}

async function fixture(t, kind = "sync", config = {}) {
  const state = { context: context(), reads: 0 };
  const portalUrl = await listen(t, async (req, res) => {
    for await (const _ of req) { /* consume synthetic request body */ }
    res.setHeader("Content-Type", "application/json");
    if (req.url.startsWith("/api/redeem-sso")) {
      res.end(JSON.stringify(state.sso ?? { email: state.context.email, context: state.context, revalidation_handle: "synthetic-handle" }));
    } else if (req.url.startsWith("/api/context")) {
      state.reads++;
      const value = structuredClone(state.context);
      if (state.onContext) await state.onContext(value);
      res.statusCode = state.status ?? 200;
      res.end(JSON.stringify(value));
    } else if (req.url.startsWith("/api/app-directory")) {
      state.directoryQuery = new URL(req.url, portalUrl).searchParams;
      res.statusCode = state.status ?? 200;
      res.end(JSON.stringify(state.directory));
    } else { res.end("{}"); }
  });
  const db = new Database(":memory:");
  // The async API uses real SQLite persistence here; cross-repo proofs exercise PostgreSQL.
  db.exec("CREATE TABLE async_sessions (token TEXT PRIMARY KEY, row TEXT NOT NULL)");
  const store = {
    async init() {}, async sweep() {},
    async insert(row) { db.prepare("INSERT INTO async_sessions VALUES (?, ?)").run(row.token, JSON.stringify(row)); },
    async get(token) { const item = db.prepare("SELECT row FROM async_sessions WHERE token = ?").get(token); return item ? JSON.parse(item.row) : null; },
    async delete(token) { db.prepare("DELETE FROM async_sessions WHERE token = ?").run(token); },
    async updateContext(token, ctx, validatedAt, source) {
      const row = await this.get(token);
      if (row) db.prepare("UPDATE async_sessions SET row = ? WHERE token = ?").run(JSON.stringify({ ...row, context: JSON.stringify(ctx), last_validated: validatedAt, source }), token);
    },
  };
  const options = { db, sessionStore: store, appName: "hr", portalUrl, sharedKey: "synthetic-key", credentialProvider: { configured: () => false }, authorityMode: "request", ...config };
  const auth = kind === "sync" ? createPortalAuth(options) : createPortalAuthAsync(options);
  const app = express();
  for (const [method, path] of [["get", "/view"], ["get", "/download"], ["post", "/mutate"]]) {
    app[method](path, auth.requireAuth, (req, res) => res.json(req.portal.context));
  }
  const appUrl = await listen(t, app);
  t.after(() => { auth.close(); db.close(); });
  return { state, auth, store, request: (session, path = "/view", method = "GET") => fetch(`${appUrl}${path}`, { method, headers: { Authorization: `Bearer ${session.token}` } }) };
}

test("unknown authority modes fail configuration instead of falling back to cached trust", () => {
  const db = new Database(":memory:");
  try {
    for (const build of [createPortalAuth, createPortalAuthAsync]) {
      assert.throws(() => build({ db, sessionStore: { init: async () => {} }, appName: "hr", authorityMode: "request " }), /authorityMode/);
    }
  } finally { db.close(); }
});

test("legacy scalar consumers and typed directory declarations compile", () => {
  const result = spawnSync(process.execPath, ["node_modules/typescript/bin/tsc", "--noEmit", "--strict", "--skipLibCheck", "--module", "NodeNext", "test/fixtures/authority-types.ts"], { encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
});

for (const kind of ["sync", "async"]) {
  test(`${kind}: additive roles preserve the primary role and malformed grants fail closed`, async (t) => {
    const { state, auth } = await fixture(t, kind);
    const session = await auth.signInWithPortalToken("synthetic-sso");
    assert.equal(session.role, "manager");
    assert.deepEqual(session.context.roles, ["manager", "finance"]);
    assert.deepEqual(session.context.app_permissions, { hr: ["processor"] });
    for (const patch of [
      { roles: ["finance"] }, { roles: ["manager", "ops"] }, { roles: ["manager", "manager"] },
      { roles: "manager" }, { roles: undefined }, { app_permissions: undefined },
      { app_permissions: { hr: "processor" } }, { app_permissions: { other: ["processor"] } },
      { app_permissions: { hr: ["processor", "processor"] } },
      { locations: [{ ...location, is_mule: "true" }] },
      { locations: [{ id: 1, key: "hamilton", name: "Hamilton" }] },
      { locations: "all" },
    ]) {
      state.context = context(patch);
      await assert.rejects(() => auth.signInWithPortalToken("synthetic-sso"), /invalid context/, JSON.stringify(patch));
    }
  });

  test(`${kind}: malformed SSO email and handle never become sessions`, async (t) => {
    const credentialProvider = {
      configured: () => true,
      getCredentials: async () => [{ schemaVersion: 1, appKey: "hr", credentialId: "synthetic-id", secret: "synthetic-secret", stage: "AWSCURRENT" }],
    };
    const { state, auth } = await fixture(t, kind, { credentialProvider });
    for (const email of ["not-an-email", " person@example.invalid", 13]) {
      state.sso = { email, context: context({ email }), revalidation_handle: "synthetic-handle" };
      await assert.rejects(() => auth.signInWithPortalToken("synthetic-sso"), { name: "PortalError" });
    }
    for (const handle of [undefined, null, {}, 13, "", "  "]) {
      state.sso = { email: "person@example.invalid", context: context(), revalidation_handle: handle };
      await assert.rejects(() => auth.signInWithPortalToken("synthetic-sso"), { name: "PortalError" });
    }
  });

  test(`${kind}: legacy scalar payloads retain cached access but malformed additive claims are rejected`, async (t) => {
    const { state, auth, request } = await fixture(t, kind, { authorityMode: "cached" });
    state.context = context({ roles: undefined, app_permissions: undefined, locations: [{ id: 1, key: "hamilton", name: "Hamilton" }] });
    const session = await auth.signInWithPortalToken("synthetic-sso");
    assert.equal(session.role, "manager");
    assert.deepEqual(session.context.roles, ["manager"]);
    assert.deepEqual(session.context.app_permissions, {});
    state.context = context({ active: false });
    assert.equal((await request(session)).status, 200);
    assert.equal(state.reads, 0);
    state.context = context({ roles: ["ops"] });
    await assert.rejects(() => auth.signInWithPortalToken("synthetic-sso"), /invalid context/);
  });

  test(`${kind}: even ops needs a current app grant and malformed live authority never falls back`, async (t) => {
    const { state, auth, request } = await fixture(t, kind, { allowOfflineAdmin: true, adminEmails: ["person@example.invalid"] });
    const session = await auth.signInWithPortalToken("synthetic-sso");
    state.context = context({ roles: undefined });
    assert.equal((await request(session)).status, 503);
    state.context = context({ role: "ops", roles: ["ops"], is_admin: true, locations: "all", apps: [], app_permissions: {} });
    await assert.rejects(() => auth.signInWithPortalToken("synthetic-sso"), /no longer have access/);
    assert.equal((await request(session)).status, 401);
  });

  test(`${kind}: request authority refreshes views downloads and mutations and refuses offline fallback`, async (t) => {
    const { state, auth, request } = await fixture(t, kind, { allowOfflineAdmin: true, adminEmails: ["person@example.invalid"] });
    const session = await auth.signInWithPortalToken("synthetic-sso");
    for (const [path, method] of [["/view", "GET"], ["/download", "GET"], ["/mutate", "POST"]]) {
      state.context = context({ roles: ["manager"], app_permissions: {}, locations: [nonMule], ctx_version: 2 });
      const response = await request(session, path, method);
      assert.equal(response.status, 200);
      const value = await response.json();
      assert.deepEqual(value.roles, ["manager"]);
      assert.deepEqual(value.app_permissions, {});
      assert.deepEqual(value.locations, [nonMule]);
    }
    assert.equal(state.reads, 3);
    state.status = 503;
    assert.equal((await request(session)).status, 503);
    state.status = 200;
    state.context = context({ apps: [], app_permissions: {} });
    assert.equal((await request(session)).status, 401);
    assert.equal((await request(session)).status, 401);
  });

  test(`${kind}: later requests never share authority fetched before a confirmed revocation`, async (t) => {
    const { state, auth, request } = await fixture(t, kind, { revalidateMs: 0 });
    const session = await auth.signInWithPortalToken("synthetic-sso");
    let releaseFirst;
    const held = new Promise((resolve) => { releaseFirst = resolve; });
    let started;
    const firstStarted = new Promise((resolve) => { started = resolve; });
    state.onContext = async () => {
      if (state.reads === 1) { started(); await held; }
    };
    const first = request(session);
    await firstStarted;
    state.context = context({ active: false, status: "disabled", ctx_version: 2 });
    const second = request(session);
    try {
      const result = await Promise.race([second, new Promise((_, reject) => {
        const timer = setTimeout(() => reject(new assert.AssertionError({ message: "later request reused the held lookup" })), 1000);
        timer.unref();
      })]);
      assert.equal(result.status, 401);
    } finally {
      releaseFirst();
      await second;
    }
    assert.equal((await first).status, 401, "late active response cannot admit a deleted session");
    assert.equal((await request(session)).status, 401);
    assert.equal(state.reads, 2);
  });

  test(`${kind}: typed directory is fresh and non-Mule locations are opt-in`, async (t) => {
    const { state, auth } = await fixture(t, kind);
    state.directory = directory();
    const first = await auth.readAppDirectory();
    assert.deepEqual(first.locations, [location]);
    assert.deepEqual(first.people[0].roles, ["manager", "finance"]);
    assert.equal(state.directoryQuery.has("include_non_mule"), false);
    const changed = { ...first.people[0], roles: ["manager"], permissions: [], status: "disabled", locations: [nonMule], ctx_version: 2 };
    state.directory = directory({ locations: [location, nonMule], people: [changed] });
    const next = await auth.readAppDirectory({ include_non_mule: true });
    assert.equal(state.directoryQuery.get("include_non_mule"), "true");
    assert.deepEqual(next.locations, [location, nonMule]);
    assert.deepEqual(next.people, [changed]);
    state.status = 503;
    await assert.rejects(() => auth.readAppDirectory(), /unavailable/);
    state.status = 200;
    state.directory = directory({ people: [] });
    assert.deepEqual((await auth.readAppDirectory()).people, [], "revoked person must disappear on next read");
  });

  test(`${kind}: missing stale and contradictory directory evidence is refused`, async (t) => {
    const { state, auth } = await fixture(t, kind);
    const person = directory().people[0];
    for (const patch of [
      { syncedAt: undefined }, { syncedAt: new Date(Date.now() - 300_000).toISOString() },
      { syncedAt: new Date(Date.now() + 300_000).toISOString() },
      { locations: [{ id: 1, key: "hamilton", name: "Hamilton" }] },
      { locations: [location, nonMule] }, { locations: [location, location] },
      { people: [{ ...person, roles: undefined }] }, { people: [{ ...person, permissions: undefined }] },
      { people: [{ ...person, ctx_version: 0 }] }, { people: [{ ...person, status: "unknown" }] },
      { people: [{ ...person, locations: "all" }] }, { people: [person, person] },
      ...["id", "key", "name", "is_mule"].map((field) => ({ people: [{ ...person, locations: [{ ...location, [field]: nonMule[field] }] }] })),
    ]) {
      state.directory = directory(patch);
      await assert.rejects(() => auth.readAppDirectory(), /invalid directory/, JSON.stringify(patch));
    }
  });
}

test("async: request authority does not require writing a cached context snapshot", async (t) => {
  const { state, auth, store, request } = await fixture(t, "async");
  const session = await auth.signInWithPortalToken("synthetic-sso");
  store.updateContext = async () => { throw new Error("synthetic context write unavailable"); };
  state.context = context({ ctx_version: 2, app_permissions: {}, roles: ["manager"] });
  const response = await request(session);
  assert.equal(response.status, 200);
  assert.deepEqual((await response.json()).app_permissions, {});
});

test("async: post-fetch session-store failure denies without leaking error content", async (t) => {
  const { state, auth, store, request } = await fixture(t, "async");
  const session = await auth.signInWithPortalToken("synthetic-sso");
  state.onContext = () => { store.get = async () => { throw new Error("synthetic-sensitive-content"); }; };
  const response = await request(session);
  assert.equal(response.status, 503);
  assert.doesNotMatch(await response.text(), /synthetic-sensitive-content/);
});
