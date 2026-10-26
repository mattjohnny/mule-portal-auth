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
// Turns a rejection into a value, so wrongly refusing valid roles fails an assertion.
const settle = (promise) => promise.catch((error) => error);
const context = (overrides = {}) => ({
  email: "person@example.invalid", name: "Synthetic Person", role: "manager",
  roles: ["manager", "finance"], is_admin: false, status: "active", active: true,
  locations: [location], apps: ["hr", "quarterly"], app_permissions: { quarterly: ["admin"] },
  ctx_version: 1, ...overrides,
});
const directory = (overrides = {}) => ({
  syncedAt: new Date().toISOString(), locations: [location],
  people: [{ email: "person@example.invalid", name: "Synthetic Person", role: "manager",
    roles: ["manager", "finance"], status: "active", locations: [location],
    permissions: [], ctx_version: 1, last_login: null }], ...overrides,
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
    const { state, auth, request } = await fixture(t, kind);
    const session = await auth.signInWithPortalToken("synthetic-sso");
    assert.equal(session.role, "manager");
    assert.deepEqual(session.context.roles, ["manager", "finance"]);
    assert.deepEqual(session.context.app_permissions, { quarterly: ["admin"] });
    for (const roles of [["manager", "hr"], ["manager", "finance", "hr"], ["manager", "hr", "finance"], ["gm", "hr"]]) {
      state.context = context({ role: roles[0], roles });
      const additive = await settle(auth.signInWithPortalToken("synthetic-sso"));
      assert.deepEqual(additive?.context?.roles, roles, JSON.stringify(roles));
      assert.equal((await request(additive)).status, 200, JSON.stringify(roles));
    }
    for (const patch of [
      { roles: ["finance"] }, { roles: ["manager", "ops"] }, { roles: ["manager", "manager"] },
      { roles: "manager" }, { roles: undefined }, { app_permissions: undefined },
      { roles: ["manager", "processor"] }, { roles: ["manager", "hr", "hr"] }, { roles: ["manager", "admin"] },
      { roles: ["hr"] }, { roles: ["manager", "HR"] }, { role: "hr", roles: ["hr"] },
      { app_permissions: { quarterly: "admin" } }, { app_permissions: { other: ["admin"] } },
      { app_permissions: { quarterly: ["admin", "admin"] } },
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
    state.context = context({ roles: ["manager", "finance", "hr"] });
    const additive = await settle(auth.signInWithPortalToken("synthetic-sso"));
    assert.deepEqual(additive?.context?.roles, ["manager", "finance", "hr"]);
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
    const changed = { ...first.people[0], roles: ["manager", "finance", "hr"], permissions: [], status: "disabled", locations: [nonMule], ctx_version: 2 };
    state.directory = directory({ locations: [location, nonMule], people: [changed] });
    const next = await settle(auth.readAppDirectory({ include_non_mule: true }));
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
      { people: [{ ...person, roles: ["manager", "processor"] }] }, { people: [{ ...person, roles: ["manager", "hr", "hr"] }] },
      { people: [{ ...person, roles: ["gm", "hr"] }] }, { people: [{ ...person, roles: ["hr"] }] }, { people: [{ ...person, role: "hr", roles: ["hr"] }] },
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

// --- Request-authority release gate -----------------------------------------
// The cases below run over the transport the current Portal serves: an
// app-bound credential, POST /api/redeem-sso issuing a revalidation handle, and
// POST /api/context with {handle}. (The keyed GET used above is answered 410 by
// the live Portal.) Dev rows are always created through a cached-mode instance
// that shares the same SQLite database or async store; request mode never makes
// one itself.
const appCredential = { schemaVersion: 1, appKey: "hr", credentialId: "synthetic-id", secret: "synthetic-secret", stage: "AWSCURRENT" };
const appCredentialProvider = () => ({ configured: () => true, getCredentials: async () => [{ ...appCredential }] });
const unconfiguredPortal = { portalUrl: "", sharedKey: "", credentialProvider: { configured: () => false } };

async function handleFixture(t, kind) {
  const state = { context: context(), contextRequests: [], directoryReads: 0 };
  const portalUrl = await listen(t, async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const url = new URL(req.url, "http://portal.invalid");
    res.setHeader("Content-Type", "application/json");
    if (url.pathname === "/api/redeem-sso") {
      res.end(JSON.stringify({ email: state.context.email, context: state.context, revalidation_handle: "synthetic-handle" }));
    } else if (url.pathname === "/api/context") {
      state.contextRequests.push({
        method: req.method, search: url.search, authorization: req.headers.authorization,
        contentType: req.headers["content-type"], body: Buffer.concat(chunks).toString(),
      });
      const value = structuredClone(state.context);
      if (state.gate) await state.gate();
      res.end(JSON.stringify(value));
    } else if (url.pathname === "/api/app-directory") {
      state.directoryReads++;
      res.end(JSON.stringify(typeof state.directory === "function" ? state.directory() : state.directory));
    } else { res.end("{}"); } // background credential proof
  });
  const db = new Database(":memory:");
  db.exec("CREATE TABLE async_sessions (token TEXT PRIMARY KEY, row TEXT NOT NULL)");
  const contextWrites = [];
  const store = {
    async init() {}, async sweep() {},
    async insert(row) { db.prepare("INSERT INTO async_sessions VALUES (?, ?)").run(row.token, JSON.stringify(row)); },
    async get(token) { const item = db.prepare("SELECT row FROM async_sessions WHERE token = ?").get(token); return item ? JSON.parse(item.row) : null; },
    async delete(token) { db.prepare("DELETE FROM async_sessions WHERE token = ?").run(token); },
    async updateContext(token, ctx, validatedAt, source) {
      contextWrites.push(token);
      const row = await this.get(token);
      if (row) db.prepare("UPDATE async_sessions SET row = ? WHERE token = ?").run(JSON.stringify({ ...row, context: JSON.stringify(ctx), last_validated: validatedAt, source }), token);
    },
  };
  const instances = [];
  t.after(() => { for (const auth of instances) auth.close(); db.close(); });
  async function build(config = {}) {
    const options = { db, sessionStore: store, appName: "hr", portalUrl, sharedKey: "", credentialProvider: appCredentialProvider(), authorityMode: "request", ...config };
    const auth = kind === "sync" ? createPortalAuth(options) : createPortalAuthAsync(options);
    instances.push(auth);
    const app = express();
    app.get("/view", auth.requireAuth, (req, res) => res.json(req.portal.context));
    const appUrl = await listen(t, app);
    return { auth, request: (session) => fetch(`${appUrl}/view`, { headers: { Authorization: `Bearer ${session.token}` } }) };
  }
  const rows = () => kind === "sync"
    ? db.prepare("SELECT token, email, name, context, created_at, expires_at, last_validated, source, revalidation_handle FROM portal_sessions").all()
    : db.prepare("SELECT row FROM async_sessions").all().map((item) => JSON.parse(item.row));
  return { state, store, contextWrites, build, rows };
}

// Holds every Portal context response until `expected` lookups have arrived,
// so a shared in-flight lookup shows up as a missing request, not a hang.
function contextBarrier(expected, ms = 1000) {
  let arrived = 0;
  let release;
  const all = new Promise((resolve) => { release = resolve; });
  const timer = setTimeout(release, ms);
  timer.unref();
  return () => {
    if (++arrived === expected) { clearTimeout(timer); release(); }
    return all;
  };
}

// An operation the contract requires to succeed. A refusal is reported as an
// assertion so a weakened guard is distinguishable from a broken fixture.
async function accepted(operation, label) {
  try { return await operation(); }
  catch (error) { assert.fail(`${label} was refused: ${error?.name}: ${error?.message}`); }
}

for (const kind of ["sync", "async"]) {
  test(`${kind}: request mode refuses a dev session when the Portal is unconfigured`, async (t) => {
    const { build, rows } = await handleFixture(t, kind);
    const cached = await build({ ...unconfiguredPortal, authorityMode: "cached" });
    const strict = await build({ ...unconfiguredPortal, authorityMode: "request" });
    const session = await accepted(() => cached.auth.devSignIn("dev@example.invalid", "Dev"), "cached dev sign-in");
    assert.equal(rows()[0].source, "dev");
    assert.equal((await cached.request(session)).status, 200, "control: cached mode keeps its explicit dev fallback");
    assert.equal((await strict.request(session)).status, 503, "request mode must not admit a dev row without a Portal");
    await assert.rejects(() => strict.auth.revalidateIfStale(session), /verification isn't configured/);
    assert.equal(rows().length, 1, "a configuration denial keeps the local row");
  });

  test(`${kind}: request mode deletes the session when the app grant is revoked`, async (t) => {
    const { state, build, rows } = await handleFixture(t, kind);
    const { auth, request } = await build();
    const session = await accepted(() => auth.signInWithPortalToken("synthetic-sso"), "sign-in");
    assert.equal((await request(session)).status, 200);
    state.context = context({ apps: [], app_permissions: {}, ctx_version: 2 });
    assert.equal((await request(session)).status, 401);
    assert.equal(rows().length, 0, "a revoked app grant deletes the session row");
    const reads = state.contextRequests.length;
    state.context = context({ ctx_version: 3 });
    assert.equal((await request(session)).status, 401, "a later re-grant must not revive the deleted session");
    assert.equal(state.contextRequests.length, reads);
  });

  test(`${kind}: directory allows 30 seconds of clock skew and refuses more`, async (t) => {
    const { state, build } = await handleFixture(t, kind);
    const { auth } = await build();
    const at = (offsetMs) => () => directory({ syncedAt: new Date(Date.now() + offsetMs).toISOString() });
    // One second either side of the 30-second window: a bound moved by more
    // than that in either direction fails one of these four reads.
    for (const offsetMs of [-29_000, 29_000]) {
      state.directory = at(offsetMs);
      const value = await accepted(() => auth.readAppDirectory(), `syncedAt ${offsetMs} ms`);
      assert.deepEqual(value.locations, [location], `syncedAt ${offsetMs} ms`);
    }
    for (const offsetMs of [-31_000, 31_000]) {
      state.directory = at(offsetMs);
      await assert.rejects(() => auth.readAppDirectory(), /invalid directory/, `syncedAt ${offsetMs} ms`);
    }
    assert.equal(state.directoryReads, 4);
  });

  test(`${kind}: request mode revalidates every request through the handle and never rewrites the stored row`, async (t) => {
    const { state, contextWrites, build, rows } = await handleFixture(t, kind);
    const { auth, request } = await build();
    const session = await accepted(() => auth.signInWithPortalToken("synthetic-sso"), "sign-in");
    const before = rows();
    assert.equal(before.length, 1);
    assert.equal(before[0].revalidation_handle, "synthetic-handle");
    const current = context({ roles: ["manager"], app_permissions: {}, locations: [nonMule], ctx_version: 2 });
    state.context = current;
    const concurrent = 4;
    state.gate = contextBarrier(concurrent);
    const responses = await Promise.all(Array.from({ length: concurrent }, () => request(session)));
    state.gate = undefined;
    assert.equal(state.contextRequests.length, concurrent, "each protected request starts its own Portal lookup");
    for (const lookup of state.contextRequests) {
      assert.equal(lookup.method, "POST");
      assert.equal(lookup.search, "");
      assert.equal(lookup.authorization, "PortalCredential synthetic-id.synthetic-secret");
      assert.match(lookup.contentType, /^application\/json/);
      assert.deepEqual(JSON.parse(lookup.body), { handle: "synthetic-handle" });
    }
    for (const response of responses) {
      assert.equal(response.status, 200);
      const value = await response.json();
      assert.equal(value.ctx_version, 2);
      assert.deepEqual(value.roles, ["manager"]);
      assert.deepEqual(value.locations, [nonMule]);
    }
    assert.deepEqual(rows(), before, "request authority never rewrites the stored context");
    assert.deepEqual(contextWrites, []);
    state.context = { active: false, email: current.email };
    assert.equal((await request(session)).status, 401);
    assert.equal(rows().length, 0, "an inactive reply deletes the session row");
    assert.equal((await request(session)).status, 401);
    assert.equal(state.contextRequests.length, concurrent + 1);
  });

  test(`${kind}: cached mode rejects present malformed permissions and location flags`, async (t) => {
    const { state, build } = await handleFixture(t, kind);
    const { auth } = await build({ authorityMode: "cached" });
    const session = await accepted(() => auth.signInWithPortalToken("synthetic-sso"), "well-formed cached sign-in");
    assert.deepEqual(session.context.app_permissions, { quarterly: ["admin"] }, "control: well-formed claims sign in");
    for (const patch of [
      { app_permissions: { other: ["processor"] } },
      { locations: [{ ...location, is_mule: "true" }] },
    ]) {
      state.context = context(patch);
      await assert.rejects(() => auth.signInWithPortalToken("synthetic-sso"), /invalid context/, JSON.stringify(patch));
    }
  });

  test(`${kind}: directory rejects shared location keys, non-boolean options and undated logins`, async (t) => {
    const { state, build } = await handleFixture(t, kind);
    const { auth } = await build();
    const person = directory().people[0];
    state.directory = () => directory({ people: [{ ...person, last_login: new Date().toISOString() }] });
    assert.equal((await accepted(() => auth.readAppDirectory(), "dated last_login")).people.length, 1);
    for (const patch of [
      { locations: [location, { ...location, id: 3, name: "Hamilton Annex" }] },
      { people: [{ ...person, last_login: "yesterday" }] },
    ]) {
      state.directory = () => directory(patch);
      await assert.rejects(() => auth.readAppDirectory(), /invalid directory/, JSON.stringify(patch));
    }
    const reads = state.directoryReads;
    state.directory = () => directory();
    await assert.rejects(async () => auth.readAppDirectory({ include_non_mule: "false" }), { name: "PortalError" });
    assert.equal(state.directoryReads, reads, "a non-boolean option is refused before any Portal request");
  });
}
