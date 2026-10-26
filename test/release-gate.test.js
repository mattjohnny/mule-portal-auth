// Release-gate fixes on top of request authority (PR #10 review): Retry-After
// passthrough, dev sign-in refusal, handle-bounded session expiry, safe error
// names, toContext precedence, row-sourced revalidation, the exposed mode and
// directory error detail. Real localhost HTTP Portal stubs and real Express.
import assert from "node:assert/strict";
import { test } from "node:test";
import { once } from "node:events";
import { createServer } from "node:http";
import Database from "better-sqlite3";
import express from "express";
import {
  createPortalAuth,
  createPortalAuthAsync,
  PortalCredentialError,
  PortalError,
  sessionTokenDigest,
} from "../dist/index.js";
import { safeErrorName } from "../dist/safe-error.js";

const HOUR = 60 * 60 * 1000;
const EMAIL = "person@example.invalid";
const location = { id: 1, key: "hamilton", name: "Hamilton", is_mule: true };
const context = (overrides = {}) => ({
  email: EMAIL, name: "Synthetic Person", role: "manager",
  roles: ["manager", "finance"], is_admin: false, status: "active", active: true,
  locations: [location], apps: ["hr"], app_permissions: { hr: ["processor"] },
  ctx_version: 1, ...overrides,
});
const person = (overrides = {}) => ({
  email: EMAIL, name: "Synthetic Person", role: "manager", roles: ["manager", "finance"],
  status: "active", locations: [location], permissions: ["processor"], ctx_version: 1,
  last_login: null, ...overrides,
});
const directory = (overrides = {}) => ({
  syncedAt: new Date().toISOString(), locations: [location], people: [person()], ...overrides,
});
const credentialProvider = () => ({
  configured: () => true,
  getCredentials: async () => [{ schemaVersion: 1, appKey: "hr", credentialId: "synthetic-id", secret: "synthetic-secret", stage: "AWSCURRENT" }],
});

async function listen(t, handler) {
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}

// An operation the contract requires to succeed. A refusal is reported as an
// assertion so a weakened guard is distinguishable from a broken fixture.
async function accepted(operation, label) {
  try { return await operation(); }
  catch (error) { assert.fail(`${label} was refused: ${error?.name}: ${error?.message}`); }
}

// A caller-supplied Session whose identity fields disagree with the stored row.
const forgedSession = (session) => ({
  ...session, email: "other@example.invalid", revalidationHandle: "forged-handle",
  context: context({ email: "other@example.invalid", role: "ops", roles: ["ops"], is_admin: true, locations: "all" }),
});
function assertStoredSession(result) {
  assert.equal(result?.email, EMAIL);
  assert.equal(result.revalidationHandle, "synthetic-handle");
  assert.equal(result.context.email, EMAIL);
  assert.equal(result.context.is_admin, false);
}

// Collect requireAuth's structured denial lines for the rest of this test.
function denials(t) {
  const events = [];
  const realWarn = console.warn;
  console.warn = (line, ...rest) => {
    try {
      const parsed = JSON.parse(line);
      if (parsed.event === "portal_revalidation_denied") return void events.push(parsed);
    } catch { /* not a structured line */ }
    realWarn(line, ...rest);
  };
  t.after(() => { console.warn = realWarn; });
  return events;
}

function memoryStore() {
  const rows = new Map();
  return {
    rows,
    async init() {}, async sweep() {},
    async insert(row) { rows.set(row.token, { ...row }); },
    async get(token) { const row = rows.get(token); return row ? { ...row } : null; },
    async delete(token) { rows.delete(token); },
    async updateContext(token, ctx, validatedAt, source) {
      const row = rows.get(token);
      if (row) rows.set(token, { ...row, context: JSON.stringify(ctx), name: ctx.name, last_validated: validatedAt, source: source ?? row.source });
    },
  };
}

async function fixture(t, kind, config = {}) {
  const state = { context: context(), contextStatus: 200, contextHeaders: {}, contextRequests: [] };
  const portalUrl = await listen(t, async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    const url = new URL(req.url, "http://portal.invalid");
    res.setHeader("Content-Type", "application/json");
    if (url.pathname === "/api/redeem-sso") {
      if (state.redeemDelayMs) {
        // The Portal stamps the handle's expiry here, before it answers.
        state.issuedAt = Date.now();
        await new Promise((resolve) => setTimeout(resolve, state.redeemDelayMs));
      }
      res.end(JSON.stringify(state.sso ?? { email: EMAIL, context: state.context, revalidation_handle: "synthetic-handle" }));
    } else if (url.pathname === "/api/context") {
      state.contextRequests.push({ email: url.searchParams.get("email"), handle: body ? JSON.parse(body).handle : undefined });
      for (const [name, value] of Object.entries(state.contextHeaders)) res.setHeader(name, value);
      res.statusCode = state.contextStatus;
      res.end(JSON.stringify(state.context));
    } else if (url.pathname === "/api/app-directory") {
      res.end(typeof state.directory === "string" ? state.directory : JSON.stringify(state.directory));
    } else { res.end("{}"); }
  });
  const db = new Database(":memory:");
  const store = memoryStore();
  const options = { db, sessionStore: store, appName: "hr", portalUrl, sharedKey: "synthetic-key", credentialProvider: { configured: () => false }, authorityMode: "request", ...config };
  const auth = kind === "sync" ? createPortalAuth(options) : createPortalAuthAsync(options);
  const app = express();
  app.get("/view", auth.requireAuth, (req, res) => res.json(req.portal.context));
  app.get("/admin", auth.requireAdmin, (req, res) => res.json(req.portal.context));
  app.get("/forged", auth.requireAuth, (req, _res, next) => {
    // Some other middleware decorates the request after authentication.
    req.context = context({ email: "forged@example.invalid", role: "ops", roles: ["ops"], is_admin: true, locations: "all" });
    next();
  }, (req, res) => res.json({ context: auth.getContext(req), keys: auth.locationKeys(req), ids: auth.locationIds(req) }));
  // No requireAuth: whatever other middleware sets, this request has no authority.
  app.get("/unadmitted", (req, _res, next) => {
    req.context = context({ email: "forged@example.invalid", role: "ops", roles: ["ops"], is_admin: true, locations: "all" });
    next();
  }, (req, res) => res.json({ context: auth.getContext(req), keys: auth.locationKeys(req), ids: auth.locationIds(req) }));
  const appUrl = await listen(t, app);
  t.after(() => { auth.close(); db.close(); });
  const row = (session) => kind === "sync"
    ? db.prepare("SELECT * FROM portal_sessions WHERE token = ?").get(sessionTokenDigest(session.token))
    : store.rows.get(sessionTokenDigest(session.token));
  const count = () => kind === "sync" ? db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n : store.rows.size;
  return {
    state, auth, store, row, count, appUrl,
    request: (session, path = "/view") => fetch(`${appUrl}${path}`, { headers: { Authorization: `Bearer ${session.token}` } }),
  };
}

for (const kind of ["sync", "async"]) {
  test(`${kind}: the Portal's delta-seconds Retry-After reaches the 503, clamped to 1..300`, async (t) => {
    denials(t);
    for (const authorityMode of ["request", "cached"]) {
      const { state, auth, request } = await fixture(t, kind, { authorityMode, revalidateMs: 0 });
      const session = await auth.signInWithPortalToken("synthetic-sso");
      for (const [status, header, expected] of [
        [429, "59", "59"], [503, "59", "59"], [503, "900", "300"], [429, "0", "1"],
        [503, undefined, "5"], [429, "Wed, 21 Oct 2026 07:28:00 GMT", "5"], [503, "1.5", "5"],
        [500, "59", "5"],
      ]) {
        state.contextStatus = status;
        state.contextHeaders = header === undefined ? {} : { "Retry-After": header };
        for (const path of ["/view", "/admin"]) {
          const response = await request(session, path);
          const label = `${authorityMode} ${path} ${status} Retry-After ${header}`;
          assert.equal(response.status, 503, label);
          assert.equal(response.headers.get("retry-after"), expected, label);
          assert.equal(response.headers.get("cache-control"), "no-store", label);
          await response.arrayBuffer();
        }
      }
      state.contextStatus = 200;
      state.contextHeaders = {};
      assert.equal((await request(session)).status, 200, `${authorityMode}: recovers without a new sign-in`);
    }
  });

  test(`${kind}: a 429 Retry-After never turns rate limiting into offline-admin access`, async (t) => {
    denials(t);
    const { state, auth, request } = await fixture(t, kind, { authorityMode: "cached", revalidateMs: 0, allowOfflineAdmin: true, adminEmails: [EMAIL] });
    const session = await auth.signInWithPortalToken("synthetic-sso");
    state.contextStatus = 429;
    state.contextHeaders = { "Retry-After": "59" };
    const limited = await request(session);
    assert.equal(limited.status, 503);
    assert.equal(limited.headers.get("retry-after"), "59");
    state.contextStatus = 503;
    assert.equal((await request(session)).status, 200, "a genuine outage still uses the explicit break glass");
  });

  test(`${kind}: devSignIn is refused in request authority mode and unchanged in cached mode`, async (t) => {
    const strict = await fixture(t, kind);
    if (kind === "sync") {
      assert.throws(() => strict.auth.devSignIn("dev@example.invalid"), { name: "PortalError", message: /request authority mode/ });
    } else {
      await assert.rejects(() => strict.auth.devSignIn("dev@example.invalid"), { name: "PortalError", message: /request authority mode/ });
    }
    assert.equal(strict.count(), 0, "no session row may be created");

    const cached = await fixture(t, kind, { authorityMode: "cached" });
    const session = await cached.auth.devSignIn("Dev@Example.invalid", "Dev Admin");
    assert.equal(session.email, "dev@example.invalid");
    assert.equal(session.context.is_admin, true);
    assert.equal(cached.row(session).source, "dev");
    assert.equal((await cached.request(session, "/admin")).status, 200);
  });

  test(`${kind}: a session created with a revalidation handle never outlives the Portal's 8 h handle`, async (t) => {
    for (const [sessionTtlMs, handle, expected] of [
      [24 * HOUR, "synthetic-handle", 8 * HOUR],
      [undefined, "synthetic-handle", 8 * HOUR],
      [1 * HOUR, "synthetic-handle", 1 * HOUR],
      [24 * HOUR, undefined, 24 * HOUR],
    ]) {
      const { state, auth, row } = await fixture(t, kind, { authorityMode: "cached", sessionTtlMs });
      state.sso = { email: EMAIL, context: context(), ...(handle ? { revalidation_handle: handle } : {}) };
      const session = await auth.signInWithPortalToken("synthetic-sso");
      const stored = row(session);
      assert.equal(stored.revalidation_handle, handle ?? "");
      assert.equal(stored.expires_at - stored.created_at, expected, `ttl ${sessionTtlMs} handle ${handle}`);
    }
    const { auth, row } = await fixture(t, kind, { authorityMode: "cached", sessionTtlMs: 24 * HOUR });
    const dev = await auth.devSignIn("dev@example.invalid");
    assert.equal(row(dev).expires_at - row(dev).created_at, 24 * HOUR, "handle-less sessions keep sessionTtlMs");
  });

  test(`${kind}: revalidation denials log the allow-listed PortalError name and no message`, async (t) => {
    const { state, auth, request } = await fixture(t, kind);
    const session = await auth.signInWithPortalToken("synthetic-sso");
    const events = denials(t);
    state.contextStatus = 503;
    assert.equal((await request(session)).status, 503);
    state.contextStatus = 200;
    state.context = context({ roles: undefined });
    assert.equal((await request(session)).status, 503);
    assert.deepEqual(events.map((event) => [event.error_name, event.portal_unavailable]), [["PortalError", true], ["PortalError", false]]);
    for (const event of events) assert.doesNotMatch(JSON.stringify(event), /temporarily unavailable|invalid context|example\.invalid/);
  });

  test(`${kind}: a request's own authority wins over a req.context set by other middleware`, async (t) => {
    const { auth, request } = await fixture(t, kind);
    const session = await auth.signInWithPortalToken("synthetic-sso");
    const response = await request(session, "/forged");
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.context.email, EMAIL);
    assert.equal(body.context.is_admin, false);
    assert.deepEqual(body.keys, ["hamilton"]);
    assert.deepEqual(body.ids, [1]);
    // Session and Context objects still resolve as before.
    assert.equal(auth.getContext(session).email, EMAIL);
    assert.deepEqual(auth.locationKeys(session), ["hamilton"]);
    assert.deepEqual(auth.locationIds(session.context), [1]);
    assert.equal(auth.getContext({}), null);
  });

  test(`${kind}: revalidateIfStale looks up the stored row's email and handle, not the caller's`, async (t) => {
    // Credential-backed lookups send the handle; legacy lookups send the email.
    for (const [authorityMode, provider] of [["request", credentialProvider()], ["cached", credentialProvider()], ["request", undefined]]) {
      const { state, auth } = await fixture(t, kind, { authorityMode, revalidateMs: 0, ...(provider ? { credentialProvider: provider } : {}) });
      const session = await auth.signInWithPortalToken("synthetic-sso");
      const label = `${authorityMode} ${provider ? "handle" : "legacy"}`;
      // A refusal here means the forged caller fields were used for the lookup:
      // report it as an assertion, not as an escaping PortalError.
      const result = await auth.revalidateIfStale({ ...session, email: "other@example.invalid", revalidationHandle: "forged-handle" })
        .catch((error) => assert.fail(`${label}: revalidation was refused: ${error?.name}: ${error?.message}`));
      assert.equal(result?.email, EMAIL, label);
      assert.equal(result.revalidationHandle, "synthetic-handle", label);
      assert.deepEqual(state.contextRequests.at(-1), provider ? { email: null, handle: "synthetic-handle" } : { email: EMAIL, handle: undefined }, label);
    }
  });

  test(`${kind}: offline-admin break glass is decided by the stored row's email`, async (t) => {
    const { state, auth } = await fixture(t, kind, { authorityMode: "cached", revalidateMs: 0, allowOfflineAdmin: true, adminEmails: ["admin@example.invalid"] });
    const session = await auth.signInWithPortalToken("synthetic-sso");
    state.contextStatus = 503;
    await assert.rejects(() => auth.revalidateIfStale({ ...session, email: "admin@example.invalid" }), { name: "PortalError" });
  });

  test(`${kind}: the connector exposes its validated authority mode read-only`, async (t) => {
    for (const [configured, expected] of [[undefined, "cached"], ["cached", "cached"], ["request", "request"]]) {
      const { auth } = await fixture(t, kind, { authorityMode: configured });
      assert.equal(auth.authorityMode, expected);
      assert.throws(() => { auth.authorityMode = expected === "cached" ? "request" : "cached"; }, TypeError);
      assert.equal(auth.authorityMode, expected);
    }
  });

  test(`${kind}: a refused directory names the failed check and position, never a value`, async (t) => {
    const { state, auth } = await fixture(t, kind);
    const other = { id: 2, key: "westdale", name: "Westdale", is_mule: true };
    for (const [patch, detail] of [
      [{ people: [person(), person({ email: "not-an-email" })] }, "people[1].email"],
      [{ people: [person(), person()] }, "people[1].email duplicate"],
      [{ people: [person({ roles: ["finance"] })] }, "people[0].roles"],
      [{ locations: [location, { ...other, key: "hamilton" }] }, "locations[1].key duplicate"],
      [{ locations: [location, { ...other, is_mule: false }] }, "locations[1].is_mule non-Mule"],
      [{ people: [person({ locations: [{ ...location, name: "Renamed" }] })] }, "people[0].locations[0] not canonical"],
      [{ people: [person({ locations: [location, { ...location, key: "" }] })] }, "people[0].locations[1].key"],
      [{ syncedAt: new Date(Date.now() - 300_000).toISOString() }, "syncedAt skew"],
    ]) {
      state.directory = directory(patch);
      const error = await auth.readAppDirectory().then(() => assert.fail(`accepted ${detail}`), (e) => e);
      assert.ok(error instanceof PortalError, detail);
      assert.equal(error.message, "The Portal returned an invalid directory response.");
      assert.equal(error.detail, detail);
      assert.doesNotMatch(error.detail, /@|hamilton|westdale|Renamed|Synthetic/i);
    }
    state.directory = "not json";
    const unreadable = await auth.readAppDirectory().then(() => assert.fail("accepted non-JSON"), (e) => e);
    assert.equal(unreadable.message, "The Portal returned an invalid directory response.");
    assert.equal(unreadable.detail, undefined);
    state.directory = directory();
    assert.equal((await auth.readAppDirectory()).people.length, 1);
  });

  // --- PR #12 review fixes ------------------------------------------------------
  test(`${kind}: locations sharing an id are refused in contexts and directories`, async (t) => {
    const { state, auth } = await fixture(t, kind, { authorityMode: "cached" });
    const twin = { id: 1, key: "westdale", name: "Westdale", is_mule: true };
    await accepted(() => auth.signInWithPortalToken("synthetic-sso"), "control: distinct locations sign in");
    state.context = context({ locations: [location, twin] });
    await assert.rejects(() => auth.signInWithPortalToken("synthetic-sso"), /invalid context/);
    state.directory = directory({ locations: [location, twin] });
    const error = await auth.readAppDirectory().then(() => assert.fail("accepted a shared location id"), (e) => e);
    assert.equal(error.detail, "locations[1].id duplicate");
  });

  test(`${kind}: only a plain delta-seconds Retry-After on a 429 or 503 is passed through`, async (t) => {
    denials(t);
    const { state, auth, request } = await fixture(t, kind);
    const session = await auth.signInWithPortalToken("synthetic-sso");
    for (const [status, header, expected] of [
      ...["-5", "+59", "1e2", "0x3C", "Infinity", "59abc"].flatMap((value) => [[503, value, "5"], [429, value, "5"]]),
      [503, "1", "1"], [429, "1", "1"], [503, "300", "300"], [429, "300", "300"],
      [502, "59", "5"], [504, "59", "5"], [403, "59", "5"],
    ]) {
      state.contextStatus = status;
      state.contextHeaders = { "Retry-After": header };
      const response = await request(session);
      const label = `${status} Retry-After ${header}`;
      assert.equal(response.status, 503, label);
      assert.equal(response.headers.get("retry-after"), expected, label);
      await response.arrayBuffer();
    }
  });

  test(`${kind}: a fresh cached revalidation returns the stored row, not the caller's Session`, async (t) => {
    const { state, auth } = await fixture(t, kind, { authorityMode: "cached", revalidateMs: HOUR });
    const session = await auth.signInWithPortalToken("synthetic-sso");
    const result = await auth.revalidateIfStale(forgedSession(session));
    assertStoredSession(result);
    assert.equal(state.contextRequests.length, 0, "the fresh path makes no Portal call");
  });

  test(`${kind}: a request requireAuth has not admitted has no context, whatever req.context says`, async (t) => {
    const { auth, appUrl } = await fixture(t, kind);
    const response = await fetch(`${appUrl}/unadmitted`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { context: null, keys: [], ids: [] });
    const forged = { headers: {}, context: context({ role: "ops", roles: ["ops"], is_admin: true, locations: "all" }) };
    assert.equal(auth.getContext(forged), null);
    assert.deepEqual(auth.locationKeys(forged), []);
    assert.deepEqual(auth.locationIds(forged), []);
    // Controls: an admitted request, a Session and a Context still resolve.
    const session = await auth.signInWithPortalToken("synthetic-sso");
    assert.equal(auth.getContext({ headers: {}, portal: session }).email, EMAIL);
    assert.equal(auth.getContext(session).email, EMAIL);
    assert.deepEqual(auth.locationKeys(session.context), ["hamilton"]);
  });

  test(`${kind}: an SSO session is measured from before the Portal issued its handle`, async (t) => {
    const { state, auth, row } = await fixture(t, kind, { authorityMode: "cached", sessionTtlMs: 24 * HOUR });
    state.redeemDelayMs = 200;
    const before = Date.now();
    const session = await auth.signInWithPortalToken("synthetic-sso");
    const stored = row(session);
    assert.ok(state.issuedAt >= before, "fixture: the handle was issued during this sign-in");
    assert.ok(stored.created_at >= before, "the session starts during this sign-in");
    assert.ok(stored.created_at <= state.issuedAt, "the session starts no later than the Portal issued its handle");
    assert.ok(stored.expires_at <= state.issuedAt + 8 * HOUR, "the session never outlives the handle");
    assert.equal(stored.expires_at - stored.created_at, 8 * HOUR);
  });
}

test("async: request mode refuses a dev row when Portal configuration disappears under the lock", async (t) => {
  denials(t);
  const portalUrl = await listen(t, async (req, res) => {
    for await (const _ of req) { /* consume synthetic request body */ }
    res.setHeader("Content-Type", "application/json");
    res.end("{}"); // background credential proof only; no lookup may happen
  });
  const store = memoryStore();
  const cached = createPortalAuthAsync({ sessionStore: store, appName: "hr", portalUrl: "", sharedKey: "", credentialProvider: { configured: () => false }, authorityMode: "cached" });
  let configured = true;
  let refusedReads = 0;
  const provider = {
    configured: () => { if (!configured) refusedReads++; return configured; },
    getCredentials: async () => credentialProvider().getCredentials(),
  };
  const strict = createPortalAuthAsync({ sessionStore: store, appName: "hr", portalUrl, sharedKey: "", credentialProvider: provider, authorityMode: "request" });
  t.after(() => { cached.close(); strict.close(); });
  const session = await cached.devSignIn("dev@example.invalid", "Dev");
  assert.equal((await cached.revalidateIfStale(session))?.email, "dev@example.invalid", "control: cached mode keeps its dev row");
  const app = express();
  app.get("/view", strict.requireAuth, (req, res) => res.json(req.portal.context));
  const appUrl = await listen(t, app);
  // requireAuth reads the row once, revalidateOnce once (configuration still
  // present), and revalidateUnderLock a third time: configuration goes there.
  let reads = 0;
  const get = store.get;
  store.get = async (token) => { if (++reads === 3) configured = false; return get(token); };
  const response = await fetch(`${appUrl}/view`, { headers: { Authorization: `Bearer ${session.token}` } });
  assert.equal(reads, 3, "fixture: the row was read by requireAuth, revalidateOnce and revalidateUnderLock");
  assert.ok(refusedReads > 0, "fixture: revalidateUnderLock saw the configuration gone");
  assert.equal(response.status, 503, "request mode must not admit a dev row once configuration is gone");
  assert.equal(store.rows.size, 1, "a configuration denial keeps the local row");
});

test("async: a session store's PortalError cannot set an out-of-range Retry-After", async (t) => {
  denials(t);
  const { auth, store, request } = await fixture(t, "async");
  const session = await auth.signInWithPortalToken("synthetic-sso");
  const get = store.get;
  for (const [retryAfterSeconds, expected] of [[86400, "5"], [0, "5"], [1.5, "5"], [NaN, "5"], [undefined, "5"], [42, "42"]]) {
    store.get = async () => { throw new PortalError("synthetic store failure", false, false, { retryAfterSeconds }); };
    const response = await request(session);
    assert.equal(response.status, 503, String(retryAfterSeconds));
    assert.equal(response.headers.get("retry-after"), expected, String(retryAfterSeconds));
    await response.arrayBuffer();
  }
  store.get = get;
  assert.equal((await request(session)).status, 200, "control: the session is intact");
});

test("async: a row a peer validated under the lock is returned from the store, not the caller's Session", async (t) => {
  const { state, auth, store } = await fixture(t, "async", { authorityMode: "cached", revalidateMs: HOUR });
  const session = await auth.signInWithPortalToken("synthetic-sso");
  const digest = sessionTokenDigest(session.token);
  store.rows.get(digest).last_validated = 0; // stale when this instance first reads it
  let locked = 0;
  store.withRevalidationLock = async (_token, callback) => {
    locked++;
    store.rows.get(digest).last_validated = Date.now(); // a peer validated it meanwhile
    return callback();
  };
  const result = await auth.revalidateIfStale(forgedSession(session));
  assert.equal(locked, 1, "fixture: revalidation went through the lock");
  assertStoredSession(result);
  assert.equal(state.contextRequests.length, 0, "the peer's validation is reused without a Portal call");
});

test("Portal error classes have allow-listed log names", () => {
  assert.equal(new PortalError("synthetic").name, "PortalError");
  assert.equal(new PortalCredentialError().name, "PortalCredentialError");
  assert.equal(safeErrorName(new PortalError("synthetic sensitive message")), "PortalError");
  assert.equal(safeErrorName(new PortalCredentialError("synthetic sensitive message")), "PortalCredentialError");
  const custom = new Error("synthetic");
  custom.name = "credential_secret_abc";
  assert.equal(safeErrorName(custom), "Error");
});
