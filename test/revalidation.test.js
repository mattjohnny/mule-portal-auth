import assert from "node:assert/strict";
import { test } from "node:test";
import Database from "better-sqlite3";
import { OAuth2Client } from "google-auth-library";
import {
  createPortalAuth,
  createPortalAuthAsync,
  PortalCredentialError,
  PortalError,
} from "../dist/index.js";

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

function memorySessionStore() {
  const rows = new Map();
  return {
    rows,
    async init() {},
    async insert(row) {
      rows.set(row.token, { ...row });
    },
    async get(token) {
      const row = rows.get(token);
      return row ? { ...row } : null;
    },
    async delete(token) {
      rows.delete(token);
    },
    async updateContext(token, value, validatedAt, source) {
      const row = rows.get(token);
      if (!row) return;
      rows.set(token, {
        ...row,
        context: JSON.stringify(value),
        name: value.name,
        last_validated: validatedAt,
        source: source ?? row.source,
      });
    },
    async sweep(expiredBefore) {
      for (const [token, row] of rows) {
        if (row.expires_at < expiredBefore) rows.delete(token);
      }
    },
  };
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
      "portal-v2"
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
      "portal-v2"
    );

    db.prepare("UPDATE portal_sessions SET last_validated = 0 WHERE token = 'legacy-token'").run();
    globalThis.fetch = async () => {
      throw new Error("offline again");
    };
    const breakGlass = await invoke(auth, "legacy-token");
    assert.equal(breakGlass.next, true);
    db.close();
  });

  await t.test("a v0.2.1 elevated Portal row is re-proven before cache or outage use", async () => {
    const { db, auth } = configured({
      adminEmails: ["ops@themule.ca"],
      allowOfflineAdmin: true,
      revalidateMs: 60_000,
    });
    const session = auth.devSignIn("ops@themule.ca", "Ops");
    const elevated = context({
      email: "ops@themule.ca",
      name: "Ops",
      role: "ops",
      is_admin: true,
      locations: "all",
      apps: [],
    });
    db.prepare(
      `UPDATE portal_sessions
       SET context = ?, source = 'portal', last_validated = ?
       WHERE token = ?`
    ).run(JSON.stringify(elevated), Date.now(), session.token);

    globalThis.fetch = async () => {
      throw new Error("offline");
    };
    const denied = await invoke(auth, session.token);
    assert.equal(denied.status, 503);

    globalThis.fetch = async () =>
      jsonResponse(
        context({
          email: "ops@themule.ca",
          name: "Ops",
          role: "manager",
          is_admin: false,
          apps: ["example-app"],
        })
      );
    const verified = await invoke(auth, session.token);
    assert.equal(verified.next, true);
    assert.equal(verified.req.portal.context.role, "manager");
    assert.equal(verified.req.portal.context.is_admin, false);
    assert.equal(
      db.prepare("SELECT source FROM portal_sessions WHERE token = ?").get(session.token)
        .source,
      "portal-v2"
    );
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
    const { db, auth } = configured({
      adminEmails: ["manager@themule.ca"],
      allowOfflineAdmin: true,
    });
    const session = auth.devSignIn("manager@themule.ca", "Manager");
    globalThis.fetch = async (url, init) => {
      const endpoint = new URL(String(url));
      const headers = new Headers(init?.headers);
      assert.equal(endpoint.searchParams.get("app"), "example-app");
      assert.equal(headers.get("x-portal-app"), "example-app");
      return jsonResponse(
        context({
          role: "manager",
          is_admin: false,
          locations: [{ id: 7, key: "hamilton", name: "Hamilton" }],
          ctx_version: 9,
        })
      );
    };
    const result = await invoke(auth, session.token);
    assert.equal(result.next, true);
    assert.equal(result.req.portal.context.ctx_version, 9);
    assert.equal(result.req.portal.context.role, "manager");
    assert.equal(result.req.portal.context.is_admin, false);
    assert.deepEqual(result.req.portal.context.locations, [
      { id: 7, key: "hamilton", name: "Hamilton" },
    ]);
    assert.equal(
      JSON.parse(
        db.prepare("SELECT context FROM portal_sessions WHERE token = ?").get(session.token).context
      ).is_admin,
      false
    );
    db.close();
  });

  await t.test("an ADMIN_EMAILS entry cannot preserve a removed legacy app grant", async () => {
    const { db, auth } = configured({
      adminEmails: ["ops@themule.ca"],
      allowOfflineAdmin: true,
    });
    const session = auth.devSignIn("ops@themule.ca", "Ops");
    globalThis.fetch = async () =>
      jsonResponse(
        context({
          email: "ops@themule.ca",
          name: "Ops",
          role: "manager",
          is_admin: false,
          apps: [],
        })
      );
    const result = await invoke(auth, session.token);
    assert.equal(result.status, 401);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 0);
    db.close();
  });

  await t.test("an ADMIN_EMAILS entry cannot preserve a removed handle session", async () => {
    const credential = {
      schemaVersion: 1,
      appKey: "example-app",
      credentialId: "current-credential",
      secret: "currentsecretcurrentsecretcurrentsecret123",
      stage: "AWSCURRENT",
    };
    globalThis.fetch = async (url) => {
      const path = new URL(String(url)).pathname;
      if (path === "/api/credential-proof") return jsonResponse({ ok: true });
      if (path === "/api/redeem-sso") {
        return jsonResponse({
          email: "ops@themule.ca",
          name: "Ops",
          role: "manager",
          context: context({
            email: "ops@themule.ca",
            name: "Ops",
            role: "manager",
            is_admin: false,
            apps: ["example-app"],
          }),
          revalidation_handle: "handle-handle-handle-handle-handle-123",
        });
      }
      if (path === "/api/context") {
        return jsonResponse(
          context({
            email: "ops@themule.ca",
            name: "Ops",
            role: "manager",
            is_admin: false,
            apps: [],
          })
        );
      }
      throw new Error(`Unexpected path ${path}`);
    };
    const db = new Database(":memory:");
    const auth = createPortalAuth({
      db,
      appName: "example-app",
      portalUrl: "https://portal.example",
      credentialProvider: {
        configured: () => true,
        async getCredentials() {
          return [{ ...credential }];
        },
      },
      adminEmails: ["ops@themule.ca"],
      allowOfflineAdmin: true,
      revalidateMs: 0,
    });
    const session = await auth.signInWithPortalToken("portal-token");
    assert.equal(session.context.is_admin, false);
    const result = await invoke(auth, session.token);
    assert.equal(result.status, 401);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 0);
    auth.close();
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

test("credential discovery failures never activate cached offline-admin access", async (t) => {
  const failures = [
    {
      name: "IAM access denied",
      create() {
        const error = new Error("not authorized");
        error.name = "AccessDeniedException";
        return Promise.reject(error);
      },
    },
    {
      name: "deleted secret",
      create() {
        const error = new Error("secret deleted");
        error.name = "ResourceNotFoundException";
        return Promise.reject(error);
      },
    },
    {
      name: "malformed secret",
      create() {
        return Promise.reject(
          new Error("Portal credential AWSCURRENT is not valid JSON.")
        );
      },
    },
    {
      name: "provider timeout",
      create() {
        return new Promise(() => {});
      },
    },
  ];

  async function exercise(kind, entry) {
    let enabled = false;
    const provider = {
      configured: () => enabled,
      getCredentials: () => entry.create(),
    };
    const common = {
      appName: "example-app",
      portalUrl: "https://portal.example",
      sharedKey: "migration-only-key",
      credentialProvider: provider,
      adminEmails: ["ops@themule.ca"],
      allowOfflineAdmin: true,
      revalidateMs: 0,
      portalRequestTimeoutMs: 10,
    };
    let auth;
    let session;
    let close;
    if (kind === "sync") {
      const db = new Database(":memory:");
      auth = createPortalAuth({ ...common, db });
      session = auth.devSignIn("ops@themule.ca", "Ops");
      db.prepare(
        `UPDATE portal_sessions
         SET source = 'portal-v2', last_validated = 0,
             revalidation_handle = ?
         WHERE token = ?`
      ).run("handle-handle-handle-handle-handle-123", session.token);
      session.revalidationHandle =
        "handle-handle-handle-handle-handle-123";
      close = () => {
        auth.close();
        db.close();
      };
    } else {
      const sessionStore = memorySessionStore();
      auth = createPortalAuthAsync({ ...common, sessionStore });
      session = await auth.devSignIn("ops@themule.ca", "Ops");
      const row = sessionStore.rows.get(session.token);
      row.source = "portal-v2";
      row.last_validated = 0;
      row.revalidation_handle =
        "handle-handle-handle-handle-handle-123";
      session.revalidationHandle =
        "handle-handle-handle-handle-handle-123";
      close = () => auth.close();
    }
    enabled = true;
    try {
      await assert.rejects(
        () => auth.revalidateIfStale(session),
        (error) => {
          assert.ok(error instanceof PortalCredentialError);
          assert.equal(error.unavailable, false);
          return true;
        }
      );
      const denied = await invoke(auth, session.token);
      assert.equal(denied.next, false);
      assert.equal(denied.status, 503);
    } finally {
      close();
    }
  }

  for (const entry of failures) {
    await t.test(`sync: ${entry.name}`, () => exercise("sync", entry));
    await t.test(`async: ${entry.name}`, () => exercise("async", entry));
  }
  globalThis.fetch = realFetch;
});

test("simultaneous stale revalidations share one Portal call and clean up", async (t) => {
  async function exercise(kind) {
    let auth;
    let session;
    let makeStale;
    let close;
    if (kind === "sync") {
      const db = new Database(":memory:");
      auth = createPortalAuth({
        db,
        appName: "example-app",
        portalUrl: "https://portal.example",
        sharedKey: "test-key",
        revalidateMs: 60_000,
      });
      session = auth.devSignIn("manager@themule.ca", "Manager");
      makeStale = () =>
        db
          .prepare(
            "UPDATE portal_sessions SET last_validated = 0 WHERE token = ?"
          )
          .run(session.token);
      close = () => {
        auth.close();
        db.close();
      };
    } else {
      const sessionStore = memorySessionStore();
      auth = createPortalAuthAsync({
        sessionStore,
        appName: "example-app",
        portalUrl: "https://portal.example",
        sharedKey: "test-key",
        revalidateMs: 60_000,
      });
      session = await auth.devSignIn("manager@themule.ca", "Manager");
      makeStale = () => {
        sessionStore.rows.get(session.token).last_validated = 0;
      };
      close = () => auth.close();
    }

    let calls = 0;
    let release;
    makeStale();
    globalThis.fetch = async () => {
      calls += 1;
      await new Promise((resolve) => {
        release = resolve;
      });
      return jsonResponse(context({ ctx_version: 10 }));
    };
    try {
      const requests = [
        auth.revalidateIfStale(session),
        auth.revalidateIfStale(session),
        auth.revalidateIfStale(session),
      ];
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(calls, 1);
      release();
      const results = await Promise.all(requests);
      assert.ok(results.every((result) => result?.context.ctx_version === 10));

      // A successful operation must leave no stuck in-flight entry.
      makeStale();
      globalThis.fetch = async () => {
        calls += 1;
        throw new Error("Portal offline");
      };
      const failed = await Promise.allSettled([
        auth.revalidateIfStale(session),
        auth.revalidateIfStale(session),
        auth.revalidateIfStale(session),
      ]);
      assert.equal(calls, 2);
      assert.ok(failed.every((result) => result.status === "rejected"));

      // A rejected operation must also be removed so the next request retries.
      globalThis.fetch = async () => {
        calls += 1;
        return jsonResponse(context({ ctx_version: 11 }));
      };
      const recovered = await auth.revalidateIfStale(session);
      assert.equal(calls, 3);
      assert.equal(recovered.context.ctx_version, 11);
    } finally {
      close();
    }
  }

  await t.test("SQLite connector", () => exercise("sync"));
  await t.test("async connector", () => exercise("async"));
  globalThis.fetch = realFetch;
});

test("the optional async store lease coalesces across connector instances", async () => {
  const sessionStore = memorySessionStore();
  const tails = new Map();
  let lockCalls = 0;
  sessionStore.withRevalidationLock = async (token, callback) => {
    lockCalls += 1;
    const prior = tails.get(token) ?? Promise.resolve();
    let release;
    const next = new Promise((resolve) => {
      release = resolve;
    });
    const tail = prior.then(() => next);
    tails.set(token, tail);
    await prior;
    try {
      return await callback();
    } finally {
      release();
      if (tails.get(token) === tail) tails.delete(token);
    }
  };
  const common = {
    sessionStore,
    appName: "example-app",
    portalUrl: "https://portal.example",
    sharedKey: "test-key",
    revalidateMs: 60_000,
  };
  const first = createPortalAuthAsync(common);
  const second = createPortalAuthAsync(common);
  const session = await first.devSignIn(
    "manager@themule.ca",
    "Manager"
  );
  const fresh = await second.revalidateIfStale(session);
  assert.equal(fresh.email, session.email);
  assert.equal(lockCalls, 0, "a fresh session must not acquire the distributed lock");
  sessionStore.rows.get(session.token).last_validated = 0;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    await new Promise((resolve) => setImmediate(resolve));
    return jsonResponse(context({ ctx_version: 12 }));
  };
  try {
    const [left, right] = await Promise.all([
      first.revalidateIfStale(session),
      second.revalidateIfStale(session),
    ]);
    assert.equal(calls, 1);
    assert.equal(lockCalls, 2, "each process reaches the shared lease for the stale row");
    assert.equal(left.context.ctx_version, 12);
    assert.equal(right.context.ctx_version, 12);
    await first.revalidateIfStale(left);
    await second.revalidateIfStale(right);
    assert.equal(
      lockCalls,
      2,
      "the refreshed row returns through the fast path without another lock"
    );
  } finally {
    first.close();
    second.close();
    globalThis.fetch = realFetch;
  }
});

test("async session stores preserve revoke-now and hard-expiry behavior", async () => {
  const sessionStore = memorySessionStore();
  const auth = createPortalAuthAsync({
    sessionStore,
    appName: "example-app",
    portalUrl: "https://portal.example",
    sharedKey: "test-key",
    adminEmails: ["manager@themule.ca"],
    allowOfflineAdmin: true,
    revalidateMs: 0,
  });
  globalThis.fetch = async () =>
    jsonResponse({
      email: "manager@themule.ca",
      name: "Manager",
      role: "manager",
      context: context(),
    });
  const portalSession = await auth.signInWithPortalToken("portal-token");
  assert.equal(portalSession.context.role, "manager");
  assert.equal(portalSession.context.is_admin, false);
  await auth.logout(portalSession.token);

  const session = await auth.devSignIn("manager@themule.ca", "Manager");

  globalThis.fetch = async () => jsonResponse(context({ ctx_version: 7 }));
  const refreshed = await invoke(auth, session.token);
  assert.equal(refreshed.next, true);
  assert.equal(refreshed.req.portal.context.ctx_version, 7);
  assert.equal(refreshed.req.portal.context.role, "manager");
  assert.equal(refreshed.req.portal.context.is_admin, false);

  globalThis.fetch = async () => jsonResponse(context({ apps: [] }));
  const revoked = await invoke(auth, session.token);
  assert.equal(revoked.status, 401);
  assert.equal(sessionStore.rows.size, 0);

  const expiring = await auth.devSignIn("manager@themule.ca", "Manager");
  sessionStore.rows.get(expiring.token).expires_at = 0;
  const expired = await invoke(auth, expiring.token);
  assert.equal(expired.status, 401);
  assert.equal(sessionStore.rows.size, 0);

  globalThis.fetch = realFetch;
});

test("async v0.2.1 elevated rows require one live authority recheck", async () => {
  const sessionStore = memorySessionStore();
  const auth = createPortalAuthAsync({
    sessionStore,
    appName: "example-app",
    portalUrl: "https://portal.example",
    sharedKey: "test-key",
    adminEmails: ["ops@themule.ca"],
    allowOfflineAdmin: true,
    revalidateMs: 60_000,
  });
  const session = await auth.devSignIn("ops@themule.ca", "Ops");
  const row = sessionStore.rows.get(session.token);
  row.source = "portal";
  row.last_validated = Date.now();
  row.context = JSON.stringify(
    context({
      email: "ops@themule.ca",
      name: "Ops",
      role: "ops",
      is_admin: true,
      locations: "all",
      apps: [],
    })
  );

  globalThis.fetch = async () => {
    throw new Error("offline");
  };
  const denied = await invoke(auth, session.token);
  assert.equal(denied.status, 503);

  globalThis.fetch = async () =>
    jsonResponse(
      context({
        email: "ops@themule.ca",
        name: "Ops",
        role: "manager",
        is_admin: false,
        apps: ["example-app"],
      })
    );
  const verified = await invoke(auth, session.token);
  assert.equal(verified.next, true);
  assert.equal(verified.req.portal.context.is_admin, false);
  assert.equal(sessionStore.rows.get(session.token).source, "portal-v2");
  auth.close();
  globalThis.fetch = realFetch;
});

test("direct Google sign-in respects the credential-migration boundary", async (t) => {
  t.after(() => {
    globalThis.fetch = realFetch;
  });
  const credentialProvider = {
    configured: () => true,
    async getCredentials() {
      return [];
    },
  };

  await t.test("a provider-absent legacy deployment keeps its fixed-lifetime flow", async () => {
    const originalVerify = OAuth2Client.prototype.verifyIdToken;
    OAuth2Client.prototype.verifyIdToken = async () => ({
      getPayload: () => ({
        email: "manager@themule.ca",
        email_verified: true,
        name: "Manager",
      }),
    });
    const db = new Database(":memory:");
    const auth = createPortalAuth({
      db,
      appName: "example-app",
      portalUrl: "https://portal.example",
      sharedKey: "migration-only-key",
      googleClientId: "test-google-client",
      adminEmails: ["manager@themule.ca"],
    });
    globalThis.fetch = async (_url, init) => {
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("x-portal-key"), "migration-only-key");
      assert.equal(headers.get("authorization"), null);
      return jsonResponse(context());
    };
    try {
      const session = await auth.signInWithGoogle("google-token");
      assert.equal(session.context.role, "manager");
      assert.equal(session.context.is_admin, false);
      const row = db
        .prepare(
          `SELECT source, revalidation_handle, created_at, expires_at
           FROM portal_sessions WHERE token = ?`
        )
        .get(session.token);
      assert.equal(row.source, "google-v2");
      assert.equal(row.revalidation_handle, "");
      assert.equal(row.expires_at - row.created_at, 8 * 60 * 60 * 1000);
    } finally {
      auth.close();
      db.close();
      OAuth2Client.prototype.verifyIdToken = originalVerify;
    }
  });

  await t.test("SQLite sessions fail before legacy Portal authentication", async () => {
    const db = new Database(":memory:");
    const auth = createPortalAuth({
      db,
      appName: "example-app",
      portalUrl: "https://portal.example",
      sharedKey: "migration-only-key",
      credentialProvider,
      googleClientId: "test-google-client",
    });
    let fetchCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls += 1;
      throw new Error("legacy Portal authentication must not run");
    };
    try {
      await assert.rejects(() => auth.signInWithGoogle("google-token"), (error) => {
        assert.ok(error instanceof PortalError);
        assert.match(error.message, /Sign in through the Mule Portal/i);
        assert.equal(error.unavailable, false);
        return true;
      });
      assert.equal(fetchCalls, 0);
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM portal_sessions").get().n, 0);
    } finally {
      auth.close();
      db.close();
    }
  });

  await t.test("async sessions fail before legacy Portal authentication", async () => {
    const sessionStore = memorySessionStore();
    const auth = createPortalAuthAsync({
      sessionStore,
      appName: "example-app",
      portalUrl: "https://portal.example",
      sharedKey: "migration-only-key",
      credentialProvider,
      googleClientId: "test-google-client",
    });
    let fetchCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls += 1;
      throw new Error("legacy Portal authentication must not run");
    };
    try {
      await assert.rejects(() => auth.signInWithGoogle("google-token"), (error) => {
        assert.ok(error instanceof PortalError);
        assert.match(error.message, /Sign in through the Mule Portal/i);
        assert.equal(error.unavailable, false);
        return true;
      });
      assert.equal(fetchCalls, 0);
      assert.equal(sessionStore.rows.size, 0);
    } finally {
      auth.close();
    }
  });

});

test("a 503 records whether the Portal was actually unavailable", async () => {
  const common = {
    appName: "example-app",
    portalUrl: "https://portal.example",
    sharedKey: "test-key",
    revalidateMs: 0,
    portalRequestTimeoutMs: 25,
  };

  async function denialEvents(storeOverrides, fetchImpl) {
    const sessionStore = { ...memorySessionStore(), ...storeOverrides };
    const auth = createPortalAuthAsync({ ...common, sessionStore });
    const session = await auth.devSignIn("ops@themule.ca", "Ops");
    const row = sessionStore.rows.get(session.token);
    row.source = "portal-v2";
    row.last_validated = 0;

    const events = [];
    const realWarn = console.warn;
    console.warn = (line) => {
      try {
        const parsed = JSON.parse(line);
        if (parsed.event === "portal_revalidation_denied") events.push(parsed);
      } catch {
        // not our structured line
      }
    };
    globalThis.fetch = fetchImpl;
    try {
      const denied = await invoke(auth, session.token);
      assert.equal(denied.status, 503, "both causes must still fail closed");
      return events;
    } finally {
      console.warn = realWarn;
      globalThis.fetch = realFetch;
      auth.close();
    }
  }

  // A shared store failing its own bounded lock wait is not a Portal outage.
  // This is the expected outcome under contention, so it must be tellable apart
  // from one.
  const lockTimeout = new Error("canceling statement due to lock timeout");
  const storeFailure = await denialEvents(
    {
      async withRevalidationLock() {
        throw lockTimeout;
      },
    },
    async () => {
      throw new Error("the Portal must not be reached once the lock fails");
    }
  );
  assert.equal(storeFailure.length, 1);
  assert.equal(
    storeFailure[0].portal_unavailable,
    false,
    "a local store failure must not be reported as a Portal outage"
  );

  // A genuine Portal outage is marked as one.
  const outage = await denialEvents({}, async () => jsonResponse({}, 503));
  assert.equal(outage.length, 1);
  assert.equal(outage[0].portal_unavailable, true);

  // Neither line may carry an error message, which can hold a session token or
  // a Secrets Manager ARN.
  for (const event of [...storeFailure, ...outage]) {
    assert.equal(typeof event.error_name, "string");
    assert.ok(
      !JSON.stringify(event).includes("canceling statement"),
      "only an allow-listed error name may be logged"
    );
  }
});
