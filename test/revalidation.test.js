import assert from "node:assert/strict";
import { test } from "node:test";
import Database from "better-sqlite3";
import { OAuth2Client } from "google-auth-library";
import { createPortalAuth, PortalError } from "../dist/index.js";

const realFetch = globalThis.fetch;

function context(overrides = {}) {
  return {
    email: "manager@themule.ca",
    name: "Manager",
    role: "manager",
    is_admin: false,
    status: "active",
    locations: [],
    apps: ["example-app"],
    ctx_version: 2,
    active: true,
    ...overrides,
  };
}

function configured(overrides = {}) {
  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    sharedKey: "test-key",
    revalidateMs: 0,
    portalRequestTimeoutMs: 25,
    ...overrides,
  });
  return { db, auth };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function invoke(auth, token) {
  return new Promise((resolve) => {
    const responseHeaders = new Map();
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = {
      statusCode: 200,
      setHeader(name, value) {
        responseHeaders.set(String(name).toLowerCase(), String(value));
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(body) {
        resolve({ next: false, status: this.statusCode, body, headers: responseHeaders, req });
        return this;
      },
    };
    auth.requireAuth(req, res, () => {
      resolve({ next: true, status: res.statusCode, headers: responseHeaders, req });
    });
  });
}

test("Portal revalidation fails closed and recovers without extending stale trust", async (t) => {
  await t.test("a fresh session does not contact the Portal before its recheck is due", async () => {
    const { db, auth } = configured({ revalidateMs: 60_000 });
    const session = auth.devSignIn("manager@themule.ca", "Manager");
    globalThis.fetch = async () => {
      throw new Error("fetch should not run");
    };
    const result = await invoke(auth, session.token);
    assert.equal(result.next, true);
    db.close();
  });

  await t.test("explicit local dev sign-in remains usable when Portal auth is unconfigured", async () => {
    const db = new Database(":memory:");
    const auth = createPortalAuth({ db, appName: "example-app", revalidateMs: 0 });
    const session = auth.devSignIn("dev@localhost", "Dev Admin");
    globalThis.fetch = async () => {
      throw new Error("fetch should not run");
    };
    const result = await invoke(auth, session.token);
    assert.equal(result.next, true);
    db.close();
  });

  await t.test("an unconfigured connector never mistakes a migrated Portal session for dev", async () => {
    const db = new Database(":memory:");
    const auth = createPortalAuth({ db, appName: "example-app", revalidateMs: 0 });
    const session = auth.devSignIn("legacy@themule.ca", "Legacy");
    db.prepare("UPDATE portal_sessions SET source = 'portal' WHERE token = ?").run(session.token);
    const result = await invoke(auth, session.token);
    assert.equal(result.next, false);
    assert.equal(result.status, 503);
    db.close();
  });

  await t.test("the session-origin column marks existing v0.1.2 rows as legacy", () => {
    const db = new Database(":memory:");
    db.exec(`
      CREATE TABLE portal_sessions (
        token TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
        context TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        last_validated INTEGER NOT NULL
      )
    `);
    const now = Date.now();
    db.prepare(
      `INSERT INTO portal_sessions
       (token, email, name, context, created_at, expires_at, last_validated)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(
      "legacy-token",
      "ops@themule.ca",
      "Ops",
      JSON.stringify(
        context({
          email: "ops@themule.ca",
          name: "Ops",
          role: "ops",
          is_admin: true,
          locations: "all",
          apps: [],
        })
      ),
      now,
      now + 60_000,
      now
    );
    createPortalAuth({ db, appName: "example-app" });
    const columns = db.prepare("PRAGMA table_info(portal_sessions)").all();
    assert.equal(columns.some((column) => column.name === "source"), true);
    assert.equal(
      db.prepare("SELECT source FROM portal_sessions WHERE token = 'legacy-token'").get().source,
      "legacy"
    );
    db.close();
  });

  await t.test("a v0.1.2 writer into a new schema still creates a legacy session", async () => {
    const db = new Database(":memory:");
    const auth = createPortalAuth({
      db,
      appName: "example-app",
      portalUrl: "https://portal.example",
      sharedKey: "test-key",
      adminEmails: ["ops@themule.ca"],
      allowOfflineAdmin: true,
      revalidateMs: 60_000,
    });
    const now = Date.now();
    const legacyContext = context({
      email: "ops@themule.ca",
      name: "Ops",
      role: "ops",
      is_admin: true,
      locations: "all",
      apps: [],
    });

    // Simulate a rollback/overlapping v0.1.2 process, whose INSERT predates the
    // source column and therefore relies on the new schema's default.
    db.prepare(
      `INSERT INTO portal_sessions
       (token, email, name, context, created_at, expires_at, last_validated)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run("old-writer-token", "ops@themule.ca", "Ops", JSON.stringify(legacyContext), now, now + 60_000, now);
    assert.equal(
      db.prepare("SELECT source FROM portal_sessions WHERE token = 'old-writer-token'").get().source,
      "legacy"
    );

    globalThis.fetch = async () => {
      throw new Error("offline");
    };
    const denied = await invoke(auth, "old-writer-token");
    assert.equal(denied.next, false);
    assert.equal(denied.status, 503);

    globalThis.fetch = async () => jsonResponse(legacyContext);
    const verified = await invoke(auth, "old-writer-token");
    assert.equal(verified.next, true);
    assert.equal(
      db.prepare("SELECT source FROM portal_sessions WHERE token = 'old-writer-token'").get().source,
      "portal"
    );
    db.close();
  });

  await t.test("a legacy admin must pass one live Portal check before outage access", async () => {
    const db = new Database(":memory:");
    db.exec(`
      CREATE TABLE portal_sessions (
        token TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
        context TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        last_validated INTEGER NOT NULL
      )
    `);
    const now = Date.now();
    const legacyContext = context({
      email: "ops@themule.ca",
      name: "Ops",
      role: "ops",
      is_admin: true,
      locations: "all",
      apps: [],
    });
    db.prepare(
      `INSERT INTO portal_sessions
       (token, email, name, context, created_at, expires_at, last_validated)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run("legacy-token", "ops@themule.ca", "Ops", JSON.stringify(legacyContext), now, now + 60_000, now);
    const auth = createPortalAuth({
      db,
      appName: "example-app",
      portalUrl: "https://portal.example",
      sharedKey: "test-key",
      adminEmails: ["ops@themule.ca"],
      allowOfflineAdmin: true,
      revalidateMs: 60_000,
    });

    globalThis.fetch = async () => {
      throw new Error("offline");
    };
    const denied = await invoke(auth, "legacy-token");
    assert.equal(denied.next, false);
    assert.equal(denied.status, 503);
    assert.equal(
      db.prepare("SELECT source FROM portal_sessions WHERE token = 'legacy-token'").get().source,
      "legacy"
    );

    globalThis.fetch = async () => jsonResponse(legacyContext);
    const verified = await invoke(auth, "legacy-token");
    assert.equal(verified.next, true);
    assert.equal(
      db.prepare("SELECT source FROM portal_sessions WHERE token = 'legacy-token'").get().source,
      "portal"
    );

    db.prepare("UPDATE portal_sessions SET last_validated = 0 WHERE token = 'legacy-token'").run();
    globalThis.fetch = async () => {
      throw new Error("offline again");
    };
    const breakGlass = await invoke(auth, "legacy-token");
    assert.equal(breakGlass.next, true);
    db.close();
  });

  await t.test("Portal SSO refuses a stale token after this app grant is removed", async () => {
    const { db, auth } = configured();
    globalThis.fetch = async () =>
      jsonResponse({
        email: "manager@themule.ca",
        name: "Manager",
        role: "manager",
        context: context({ apps: [] }),
      });
    await assert.rejects(() => auth.signInWithPortalToken("stale-token"), /no longer have access/i);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 0);

    globalThis.fetch = async () =>
      jsonResponse({
        email: "manager@themule.ca",
        name: "Manager",
        role: "manager",
        context: context(),
      });
    const session = await auth.signInWithPortalToken("current-token");
    assert.equal(session.context.apps.includes("example-app"), true);
    db.close();
  });

  await t.test("Portal SSO marks only retryable failures as unavailable", async () => {
    const hardFailures = [
      async () => jsonResponse({ error: "bad key" }, 401),
      async () => jsonResponse({ error: "disabled" }, 403),
      async () => jsonResponse({ error: "rate limited" }, 429),
      async () => new Response("not json", { status: 200 }),
      async () =>
        jsonResponse({
          email: "manager@themule.ca",
          context: context({ role: "manager", is_admin: true, locations: "all" }),
        }),
    ];
    for (const fetchImpl of hardFailures) {
      const { db, auth } = configured();
      globalThis.fetch = fetchImpl;
      await assert.rejects(() => auth.signInWithPortalToken("token"), (error) => {
        assert.ok(error instanceof PortalError);
        assert.equal(error.unavailable, false);
        return true;
      });
      db.close();
    }

    const { db, auth } = configured();
    globalThis.fetch = async () => jsonResponse({ error: "busy" }, 503);
    await assert.rejects(() => auth.signInWithPortalToken("token"), (error) => {
      assert.ok(error instanceof PortalError);
      assert.equal(error.unavailable, true);
      return true;
    });
    db.close();
  });

  await t.test("a successful recheck refreshes context", async () => {
    const { db, auth } = configured();
    const session = auth.devSignIn("manager@themule.ca", "Manager");
    globalThis.fetch = async () => jsonResponse(context({ ctx_version: 9 }));
    const result = await invoke(auth, session.token);
    assert.equal(result.next, true);
    assert.equal(result.req.portal.context.ctx_version, 9);
    db.close();
  });

  await t.test("a disabled person is signed out and the local session is destroyed", async () => {
    const { db, auth } = configured();
    const session = auth.devSignIn("manager@themule.ca", "Manager");
    globalThis.fetch = async () => jsonResponse({ active: false, email: session.email });
    const result = await invoke(auth, session.token);
    assert.equal(result.next, false);
    assert.equal(result.status, 401);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 0);
    db.close();
  });

  await t.test("removing this app from a non-ops context destroys the session", async () => {
    const { db, auth } = configured();
    const session = auth.devSignIn("manager@themule.ca", "Manager");
    globalThis.fetch = async () => jsonResponse(context({ apps: [] }));
    const result = await invoke(auth, session.token);
    assert.equal(result.status, 401);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 0);
    db.close();
  });

  await t.test("ops remains authorized without an explicit app entry", async () => {
    const { db, auth } = configured();
    const session = auth.devSignIn("ops@themule.ca", "Ops");
    globalThis.fetch = async () =>
      jsonResponse(
        context({
          email: "ops@themule.ca",
          name: "Ops",
          role: "ops",
          is_admin: true,
          locations: "all",
          apps: [],
        })
      );
    const result = await invoke(auth, session.token);
    assert.equal(result.next, true);
    db.close();
  });

  await t.test("a network failure returns retryable 503 and recovery needs no new login", async () => {
    const { db, auth } = configured();
    const session = auth.devSignIn("manager@themule.ca", "Manager");
    globalThis.fetch = async () => {
      throw new Error("offline");
    };
    const unavailable = await invoke(auth, session.token);
    assert.equal(unavailable.next, false);
    assert.equal(unavailable.status, 503);
    assert.equal(unavailable.headers.get("cache-control"), "no-store");
    assert.equal(unavailable.headers.get("retry-after"), "5");
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 1);

    globalThis.fetch = async () => jsonResponse(context());
    const recovered = await invoke(auth, session.token);
    assert.equal(recovered.next, true);
    db.close();
  });

  await t.test("a hung Portal request is bounded and denied", async () => {
    const { db, auth } = configured({ portalRequestTimeoutMs: 10 });
    const session = auth.devSignIn("manager@themule.ca", "Manager");
    globalThis.fetch = async (_url, init = {}) =>
      new Promise((_, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
      });
    const result = await invoke(auth, session.token);
    assert.equal(result.status, 503);
    db.close();
  });

  await t.test("Portal errors and malformed JSON are denied, not served from cache", async () => {
    for (const fetchImpl of [
      async () => jsonResponse({ error: "broken" }, 500),
      async () => new Response("not json", { status: 200 }),
    ]) {
      const { db, auth } = configured();
      const session = auth.devSignIn("manager@themule.ca", "Manager");
      globalThis.fetch = fetchImpl;
      const result = await invoke(auth, session.token);
      assert.equal(result.status, 503);
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 1);
      db.close();
    }
  });

  await t.test("authorization-breaking context shapes are rejected", async () => {
    const malformed = [
      context({ role: "manager", is_admin: true, locations: "all", apps: [] }),
      context({ locations: "all" }),
      context({ locations: [{ id: 1, key: "", name: "Broken" }] }),
      context({ apps: ["example-app", 42] }),
    ];
    for (const bad of malformed) {
      const { db, auth } = configured();
      const session = auth.devSignIn("manager@themule.ca", "Manager");
      globalThis.fetch = async () => jsonResponse(bad);
      const result = await invoke(auth, session.token);
      assert.equal(result.status, 503);
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 1);
      db.close();
    }
  });

  await t.test("a malformed inactive response cannot revoke the wrong person's session", async () => {
    const { db, auth } = configured();
    const session = auth.devSignIn("manager@themule.ca", "Manager");
    globalThis.fetch = async () => jsonResponse({ active: false, email: "someone-else@themule.ca" });
    const result = await invoke(auth, session.token);
    assert.equal(result.status, 503);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 1);
    db.close();
  });

  await t.test("hard session expiry still destroys the local session", async () => {
    const { db, auth } = configured({ revalidateMs: 60_000 });
    const session = auth.devSignIn("manager@themule.ca", "Manager");
    db.prepare("UPDATE portal_sessions SET expires_at = 0 WHERE token = ?").run(session.token);
    const result = await invoke(auth, session.token);
    assert.equal(result.status, 401);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 0);
    db.close();
  });

  await t.test("cached offline admin access is disabled by default and explicit when enabled", async () => {
    for (const allowOfflineAdmin of [false, true]) {
      const { db, auth } = configured({
        adminEmails: ["ops@themule.ca"],
        allowOfflineAdmin,
      });
      const session = auth.devSignIn("ops@themule.ca", "Ops");
      globalThis.fetch = async () => {
        throw new Error("offline");
      };
      const result = await invoke(auth, session.token);
      assert.equal(result.next, allowOfflineAdmin);
      assert.equal(result.status, allowOfflineAdmin ? 200 : 503);
      db.close();
    }
  });

  await t.test("cached offline admin accepts only retryable Portal HTTP responses", async () => {
    for (const status of [408, 425, 500, 502, 503, 504]) {
      const { db, auth } = configured({
        adminEmails: ["ops@themule.ca"],
        allowOfflineAdmin: true,
      });
      const session = auth.devSignIn("ops@themule.ca", "Ops");
      globalThis.fetch = async () => jsonResponse({ error: "temporary" }, status);
      const result = await invoke(auth, session.token);
      assert.equal(result.next, true, `status ${status} should qualify as unavailable`);
      db.close();
    }
  });

  await t.test("cached offline admin denies auth, protocol, and malformed Portal responses", async () => {
    const hardFailures = [
      async () => jsonResponse({ error: "bad key" }, 401),
      async () => jsonResponse({ error: "forbidden" }, 403),
      async () => jsonResponse({ error: "rate limited" }, 429),
      async () => jsonResponse({ error: "unsupported protocol" }, 501),
      async () => new Response("not json", { status: 200 }),
      async () => jsonResponse(context({ role: "manager", is_admin: true, locations: "all" })),
    ];
    for (const fetchImpl of hardFailures) {
      const { db, auth } = configured({
        adminEmails: ["ops@themule.ca"],
        allowOfflineAdmin: true,
      });
      const session = auth.devSignIn("ops@themule.ca", "Ops");
      globalThis.fetch = fetchImpl;
      const result = await invoke(auth, session.token);
      assert.equal(result.next, false);
      assert.equal(result.status, 503);
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 1);
      db.close();
    }
  });

  await t.test("cached offline admin denies local URL and timeout configuration errors", async () => {
    for (const overrides of [
      { portalUrl: "not a URL" },
      { portalRequestTimeoutMs: -1 },
    ]) {
      const { db, auth } = configured({
        adminEmails: ["ops@themule.ca"],
        allowOfflineAdmin: true,
        ...overrides,
      });
      const session = auth.devSignIn("ops@themule.ca", "Ops");
      globalThis.fetch = async () => {
        throw new Error("fetch must not run for invalid request configuration");
      };
      const result = await invoke(auth, session.token);
      assert.equal(result.next, false);
      assert.equal(result.status, 503);
      db.close();
    }
  });

  await t.test("cached offline admin accepts a real Portal timeout", async () => {
    const { db, auth } = configured({
      adminEmails: ["ops@themule.ca"],
      allowOfflineAdmin: true,
      portalRequestTimeoutMs: 10,
    });
    const session = auth.devSignIn("ops@themule.ca", "Ops");
    globalThis.fetch = async (_url, init = {}) =>
      new Promise((_, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
      });
    const result = await invoke(auth, session.token);
    assert.equal(result.next, true);
    db.close();
  });

  await t.test("direct Google offline-admin sign-in rejects hard failures but permits retryable outages", async () => {
    const originalVerify = OAuth2Client.prototype.verifyIdToken;
    OAuth2Client.prototype.verifyIdToken = async () => ({
      getPayload: () => ({
        email: "ops@themule.ca",
        email_verified: true,
        name: "Ops",
      }),
    });
    try {
      const hard = configured({
        googleClientId: "test-google-client",
        adminEmails: ["ops@themule.ca"],
        allowOfflineAdmin: true,
      });
      globalThis.fetch = async () => jsonResponse({ error: "bad key" }, 401);
      await assert.rejects(() => hard.auth.signInWithGoogle("google-token"));
      assert.equal(hard.db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 0);
      hard.db.close();

      const retryable = configured({
        googleClientId: "test-google-client",
        adminEmails: ["ops@themule.ca"],
        allowOfflineAdmin: true,
      });
      globalThis.fetch = async () => jsonResponse({ error: "busy" }, 503);
      const session = await retryable.auth.signInWithGoogle("google-token");
      assert.equal(session.context.is_admin, true);
      assert.equal(
        retryable.db.prepare("SELECT source FROM portal_sessions WHERE token = ?").get(session.token).source,
        "offline-admin"
      );
      retryable.db.close();
    } finally {
      OAuth2Client.prototype.verifyIdToken = originalVerify;
    }
  });

  await t.test("offline admin bootstrap is denied when Portal configuration is absent", async () => {
    const db = new Database(":memory:");
    const auth = createPortalAuth({
      db,
      appName: "example-app",
      googleClientId: "test-google-client",
      adminEmails: ["ops@themule.ca"],
      allowOfflineAdmin: true,
    });

    await assert.rejects(() => auth.signInWithGoogle("unused-google-token"), (error) => {
      assert.ok(error instanceof PortalError);
      assert.match(error.message, /Portal access verification isn't configured/i);
      assert.equal(error.unavailable, false);
      return true;
    });
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 0);
    db.close();
  });

  globalThis.fetch = realFetch;
});
