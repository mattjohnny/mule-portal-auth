// SEC-13 (Daily Close audit): a failed Portal sign-in redemption exposes the
// Portal's HTTP status as `PortalError.portalStatus`, and its delta-seconds
// Retry-After on a 429/503 as `retryAfterSeconds`, so a consumer can tell a
// throttled sign-in from a bad or expired link. Everything a v0.3.0 consumer
// already reads is unchanged: the message, the type, `name`, `signedOut` and
// `unavailable` (a 429 is still not an outage). Nothing retries.
// Real localhost HTTP Portal stub and real Express; both connector factories.
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
} from "../dist/index.js";

const EMAIL = "person@example.invalid";
const location = { id: 1, key: "hamilton", name: "Hamilton", is_mule: true };
const context = () => ({
  email: EMAIL, name: "Synthetic Person", role: "manager", roles: ["manager"],
  is_admin: false, status: "active", active: true, locations: [location],
  apps: ["daily-close"], app_permissions: {}, ctx_version: 1,
});

const INVALID_LINK = "That sign-in link is invalid or has expired.";
const UNAVAILABLE = "The Portal is temporarily unavailable. Please try again.";
const DISABLED = "That account has been disabled.";

async function listen(t, handler) {
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}

// One connector against a Portal stub whose redemption answer is set per case.
async function fixture(t, kind, { credentialProvider } = {}) {
  const state = { redeemCalls: 0, status: 200, headers: {}, body: undefined, directoryStatus: 200 };
  const portalUrl = await listen(t, async (req, res) => {
    for await (const _ of req) { /* consume synthetic request body */ }
    res.setHeader("Content-Type", "application/json");
    if (req.url.startsWith("/api/redeem-sso")) {
      state.redeemCalls++;
      res.statusCode = state.status;
      for (const [name, value] of Object.entries(state.headers)) res.setHeader(name, value);
      res.end(state.body ?? JSON.stringify(
        state.status === 200
          ? { email: EMAIL, context: context(), revalidation_handle: "synthetic-handle" }
          : { error: "synthetic refusal" }
      ));
    } else if (req.url.startsWith("/api/app-directory")) {
      res.statusCode = state.directoryStatus;
      res.setHeader("Retry-After", "30");
      res.end("{}");
    } else { res.statusCode = 404; res.end("{}"); }
  });
  const db = new Database(":memory:");
  const rows = new Map();
  const sessionStore = {
    async init() {}, async sweep() {},
    async insert(row) { rows.set(row.token, row); },
    async get(token) { return rows.get(token) ?? null; },
    async delete(token) { rows.delete(token); },
    async updateContext() {},
  };
  const options = {
    db, sessionStore, appName: "daily-close", portalUrl, sharedKey: "synthetic-key",
    credentialProvider: credentialProvider ?? { configured: () => false },
  };
  const auth = kind === "sync" ? createPortalAuth(options) : createPortalAuthAsync(options);
  t.after(() => { auth.close(); db.close(); });
  const sessionCount = () =>
    kind === "sync" ? db.prepare("SELECT count(*) AS n FROM portal_sessions").get().n : rows.size;
  return { state, auth, sessionCount };
}

async function refusal(auth) {
  try {
    await auth.signInWithPortalToken("synthetic-sso");
  } catch (error) {
    return error;
  }
  assert.fail("sign-in was accepted");
}

// The fields a v0.3.0 consumer reads, plus the two this release exposes.
function shape(error) {
  return {
    isPortalError: error instanceof PortalError,
    isCredentialError: error instanceof PortalCredentialError,
    name: error.name,
    message: error.message,
    signedOut: error.signedOut,
    unavailable: error.unavailable,
    portalStatus: error.portalStatus,
    retryAfterSeconds: error.retryAfterSeconds,
    detail: error.detail,
  };
}
const expected = (fields) => ({
  isPortalError: true, isCredentialError: false, name: "PortalError",
  signedOut: false, unavailable: false, portalStatus: undefined, retryAfterSeconds: undefined, detail: undefined,
  ...fields,
});

// status, Retry-After header (or none), then the error a caller must see.
const CASES = [
  // Throttled: same refusal as before, now distinguishable by status.
  [429, "30", { message: INVALID_LINK, portalStatus: 429, retryAfterSeconds: 30 }],
  [429, undefined, { message: INVALID_LINK, portalStatus: 429 }],
  [429, "0", { message: INVALID_LINK, portalStatus: 429, retryAfterSeconds: 1 }],
  [429, "86400", { message: INVALID_LINK, portalStatus: 429, retryAfterSeconds: 300 }],
  [429, "Wed, 21 Oct 2026 07:28:00 GMT", { message: INVALID_LINK, portalStatus: 429 }],
  [429, "1.5", { message: INVALID_LINK, portalStatus: 429 }],
  // Bad, expired or replayed link: Retry-After is ignored outside 429/503.
  [401, "30", { message: INVALID_LINK, portalStatus: 401 }],
  [404, "30", { message: INVALID_LINK, portalStatus: 404 }],
  [400, undefined, { message: INVALID_LINK, portalStatus: 400 }],
  [410, undefined, { message: INVALID_LINK, portalStatus: 410 }],
  // Redirects are never followed, so a 3xx is a refusal with its own status.
  [302, undefined, { message: INVALID_LINK, portalStatus: 302 }],
  // Disabled person: still signedOut, still not an outage.
  [403, "30", { message: DISABLED, signedOut: true, portalStatus: 403 }],
  // Outage statuses keep `unavailable`; only 503 carries Retry-After.
  [408, undefined, { message: UNAVAILABLE, unavailable: true, portalStatus: 408 }],
  [425, undefined, { message: UNAVAILABLE, unavailable: true, portalStatus: 425 }],
  [500, "30", { message: UNAVAILABLE, unavailable: true, portalStatus: 500 }],
  [502, undefined, { message: UNAVAILABLE, unavailable: true, portalStatus: 502 }],
  [503, "45", { message: UNAVAILABLE, unavailable: true, portalStatus: 503, retryAfterSeconds: 45 }],
  [503, undefined, { message: UNAVAILABLE, unavailable: true, portalStatus: 503 }],
  [504, undefined, { message: UNAVAILABLE, unavailable: true, portalStatus: 504 }],
  // A 5xx outside the outage set is a refusal, as in v0.3.0.
  [501, undefined, { message: INVALID_LINK, portalStatus: 501 }],
];

for (const kind of ["sync", "async"]) {
  for (const [status, retryAfter, fields] of CASES) {
    test(`${kind}: redemption ${status} (Retry-After ${retryAfter ?? "none"}) keeps v0.3.0 fields and exposes the status`, async (t) => {
      const { state, auth, sessionCount } = await fixture(t, kind);
      state.status = status;
      state.headers = retryAfter === undefined ? {} : { "Retry-After": retryAfter };
      const error = await refusal(auth);
      assert.deepEqual(shape(error), expected(fields));
      assert.equal(state.redeemCalls, 1, "the connector must not retry a failed redemption");
      assert.equal(sessionCount(), 0, "a failed redemption must not create a session");
    });
  }

  test(`${kind}: 429 and 401 are told apart only by portalStatus`, async (t) => {
    const { state, auth } = await fixture(t, kind);
    state.status = 429;
    const throttled = shape(await refusal(auth));
    state.status = 401;
    const refused = shape(await refusal(auth));
    assert.equal(throttled.portalStatus, 429);
    assert.equal(refused.portalStatus, 401);
    const { portalStatus: _a, ...throttledRest } = throttled;
    const { portalStatus: _b, ...refusedRest } = refused;
    assert.deepEqual(throttledRest, refusedRest, "every pre-existing field must match between 429 and 401");
  });

  test(`${kind}: a 401 after credential fall-through still reports the Portal status`, async (t) => {
    const { state, auth } = await fixture(t, kind, {
      credentialProvider: {
        configured: () => true,
        getCredentials: async () => [
          { schemaVersion: 1, appKey: "daily-close", credentialId: "pending", secret: "synthetic-pending", stage: "AWSPENDING" },
          { schemaVersion: 1, appKey: "daily-close", credentialId: "current", secret: "synthetic-current", stage: "AWSCURRENT" },
        ],
      },
    });
    state.status = 401;
    const error = await refusal(auth);
    assert.deepEqual(shape(error), expected({ message: INVALID_LINK, portalStatus: 401 }));
  });

  test(`${kind}: failures with no Portal status response leave portalStatus absent`, async (t) => {
    const { state, auth } = await fixture(t, kind);
    // A 2xx the connector rejects is a validation failure, not a status.
    state.body = "not json";
    let error = await refusal(auth);
    assert.equal(error.message, "The Portal returned an invalid sign-in response.");
    assert.equal(error.portalStatus, undefined);
    assert.equal("portalStatus" in error, false);
    state.body = JSON.stringify({ email: EMAIL, context: { ...context(), roles: ["finance"] }, revalidation_handle: "h" });
    error = await refusal(auth);
    assert.equal(error.portalStatus, undefined);
    // Local refusal before any Portal call.
    await assert.rejects(() => auth.signInWithPortalToken(""), (e) =>
      e instanceof PortalError && e.message === "Missing sign-in token." && !("portalStatus" in e));
    // Other Portal calls are out of scope and do not gain the field.
    state.directoryStatus = 429;
    await assert.rejects(() => auth.readAppDirectory(), (e) =>
      e instanceof PortalError && e.message === "Portal rejected the directory request." &&
      !("portalStatus" in e) && e.retryAfterSeconds === undefined);
  });

  test(`${kind}: an unreachable Portal (closed port) leaves portalStatus absent`, async (t) => {
    const db = new Database(":memory:");
    const options = {
      db, sessionStore: { async init() {}, async sweep() {}, async insert() {}, async get() { return null; }, async delete() {}, async updateContext() {} },
      appName: "daily-close", portalUrl: "http://127.0.0.1:1", sharedKey: "synthetic-key",
      credentialProvider: { configured: () => false },
    };
    const auth = kind === "sync" ? createPortalAuth(options) : createPortalAuthAsync(options);
    t.after(() => { auth.close(); db.close(); });
    const error = await refusal(auth);
    assert.deepEqual(shape(error), expected({
      message: "Couldn't reach the Portal to complete sign-in.", unavailable: true,
    }));
  });

  // The field is named portalStatus, not status, because Express's final
  // handler (and http-errors-style handlers) read err.status as the response
  // code. A consumer that lets a sign-in error reach Express must still get 500.
  test(`${kind}: an unhandled sign-in error still answers 500 through Express`, async (t) => {
    const { state, auth } = await fixture(t, kind);
    state.status = 429;
    const app = express();
    app.post("/sso", async (_req, _res, next) => {
      try { await auth.signInWithPortalToken("synthetic-sso"); } catch (error) { next(error); }
    });
    const appUrl = await listen(t, app);
    const realError = console.error;
    console.error = () => {};
    t.after(() => { console.error = realError; });
    const response = await fetch(`${appUrl}/sso`, { method: "POST" });
    await response.arrayBuffer();
    assert.equal(response.status, 500);
    assert.equal(response.headers.get("retry-after"), null);
  });
}

test("the consumer-side throttled check compiles against the emitted declarations", async () => {
  const { spawnSync } = await import("node:child_process");
  const result = spawnSync(process.execPath, ["node_modules/typescript/bin/tsc", "--noEmit", "--strict", "--skipLibCheck", "--module", "NodeNext", "test/fixtures/redeem-status-types.ts"], { encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
});
