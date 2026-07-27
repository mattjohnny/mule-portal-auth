import assert from "node:assert/strict";
import { test } from "node:test";
import Database from "better-sqlite3";
import {
  createPortalAuth,
  PortalCredentialError,
} from "../dist/index.js";

const current = {
  schemaVersion: 1,
  appKey: "example-app",
  credentialId: "current-credential",
  secret: "currentsecretcurrentsecretcurrentsecret123",
  stage: "AWSCURRENT",
};
const pending = {
  schemaVersion: 1,
  appKey: "example-app",
  credentialId: "pending-credential",
  secret: "pendingsecretpendingsecretpendingsecret123",
  stage: "AWSPENDING",
};

const activeContext = {
  email: "manager@themule.ca",
  name: "Manager",
  role: "manager",
  is_admin: false,
  status: "active",
  locations: [],
  apps: ["example-app"],
  ctx_version: 3,
  active: true,
};

function provider() {
  return {
    configured: () => true,
    async getCredentials() {
      return [{ ...pending }, { ...current }];
    },
  };
}

function credentialId(init) {
  const header = new Headers(init?.headers).get("authorization") || "";
  return header.match(/^PortalCredential ([^.]+)\./)?.[1] || "";
}

function ssoResponse() {
  return new Response(
    JSON.stringify({
      email: activeContext.email,
      name: activeContext.name,
      role: activeContext.role,
      context: activeContext,
      revalidation_handle: "handle-handle-handle-handle-handle-123",
    }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("a low-traffic connector synthetically proves pending credentials", async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, init) => {
    seen.push({ url: String(url), credentialId: credentialId(init) });
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    credentialProvider: provider(),
    credentialRefreshMs: 20,
  });
  try {
    await delay(35);
    assert.ok(
      seen.some(
        (entry) =>
          entry.url.endsWith("/api/credential-proof") &&
          entry.credentialId === pending.credentialId
      )
    );
  } finally {
    auth.close();
    db.close();
    globalThis.fetch = originalFetch;
  }
});

test("unregistered or rejected pending credentials fall back to current", async () => {
  const originalFetch = globalThis.fetch;
  let pendingRegistered = false;
  let rejectPendingRedeem = false;
  const redeemAttempts = [];
  globalThis.fetch = async (url, init) => {
    const path = new URL(String(url)).pathname;
    const id = credentialId(init);
    if (path === "/api/credential-proof") {
      return new Response("", { status: pendingRegistered ? 200 : 401 });
    }
    if (path === "/api/redeem-sso") {
      redeemAttempts.push(id);
      if (id === pending.credentialId && rejectPendingRedeem) {
        return new Response("", { status: 401 });
      }
      return ssoResponse();
    }
    throw new Error(`Unexpected request: ${path}`);
  };

  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    credentialProvider: provider(),
    credentialRefreshMs: 20,
  });
  try {
    await delay(10);
    await auth.signInWithPortalToken("first-token");
    assert.deepEqual(redeemAttempts, [current.credentialId]);

    pendingRegistered = true;
    await delay(35);
    rejectPendingRedeem = true;
    redeemAttempts.length = 0;
    await auth.signInWithPortalToken("second-token");
    assert.deepEqual(redeemAttempts, [
      pending.credentialId,
      current.credentialId,
    ]);
  } finally {
    auth.close();
    db.close();
    globalThis.fetch = originalFetch;
  }
});

test("a cold-cache credential-provider outage fails closed despite a legacy key", async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (_url, init) => {
    const headers = new Headers(init?.headers);
    seen.push({
      credential: headers.get("authorization"),
      legacy: headers.get("x-portal-key"),
    });
    return ssoResponse();
  };

  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    sharedKey: "migration-only-key",
    credentialProvider: {
      configured: () => true,
      async getCredentials() {
        throw new Error("Secrets Manager is unavailable");
      },
    },
  });
  try {
    await assert.rejects(
      () => auth.signInWithPortalToken("provider-outage-token"),
      (error) =>
        error instanceof PortalCredentialError &&
        error.unavailable === false
    );
    assert.deepEqual(seen, []);
  } finally {
    auth.close();
    db.close();
    globalThis.fetch = originalFetch;
  }
});

test("an empty configured provider fails closed instead of using the legacy key", async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (_url, init) => {
    const headers = new Headers(init?.headers);
    seen.push({
      credential: headers.get("authorization"),
      legacy: headers.get("x-portal-key"),
    });
    return ssoResponse();
  };

  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    sharedKey: "migration-only-key",
    credentialProvider: {
      configured: () => true,
      async getCredentials() {
        return [];
      },
    },
  });
  try {
    await assert.rejects(
      () => auth.signInWithPortalToken("empty-provider-token"),
      (error) =>
        error instanceof PortalCredentialError &&
        error.unavailable === false
    );
    assert.deepEqual(seen, []);
  } finally {
    auth.close();
    db.close();
    globalThis.fetch = originalFetch;
  }
});

test("a legacy-only configuration still authenticates with the shared key", async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, init) => {
    const headers = new Headers(init?.headers);
    seen.push({
      credential: headers.get("authorization"),
      legacy: headers.get("x-portal-key"),
      app: headers.get("x-portal-app"),
      path: new URL(String(url)).pathname,
    });
    return ssoResponse();
  };

  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    sharedKey: "migration-only-key",
  });
  try {
    await auth.signInWithPortalToken("legacy-only-token");
    assert.deepEqual(seen, [
      {
        credential: null,
        legacy: "migration-only-key",
        app: "example-app",
        path: "/api/redeem-sso",
      },
    ]);
  } finally {
    auth.close();
    db.close();
    globalThis.fetch = originalFetch;
  }
});

test("a hung cold-cache credential lookup is bounded by the Portal request deadline", async () => {
  const originalFetch = globalThis.fetch;
  const providerSignals = [];
  let providerCalls = 0;
  globalThis.fetch = async (url) => {
    if (new URL(String(url)).pathname === "/api/credential-proof") {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    throw new Error("Portal fetch must not start before credential lookup completes");
  };
  const credentialProvider = {
    configured: () => true,
    async getCredentials(_forceRefresh, signal) {
      providerCalls += 1;
      providerSignals.push(signal);
      // The constructor's background proof gets a usable current credential.
      if (providerCalls === 1) return [{ ...current }];
      return new Promise((_, reject) => {
        signal.addEventListener(
          "abort",
          () => reject(signal.reason),
          { once: true }
        );
      });
    },
  };
  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    credentialProvider,
    portalRequestTimeoutMs: 15,
    credentialRefreshMs: 60_000,
  });

  try {
    const startedAt = Date.now();
    await assert.rejects(
      () => auth.signInWithPortalToken("cold-cache-token"),
      (error) =>
        error instanceof PortalCredentialError &&
        error.unavailable === false
    );
    assert.ok(Date.now() - startedAt < 500, "credential lookup exceeded its request deadline");
    assert.ok(providerSignals[0] instanceof AbortSignal, "proof lookup did not receive a deadline");
    assert.equal(providerSignals.at(-1).aborted, true);
  } finally {
    auth.close();
    db.close();
    globalThis.fetch = originalFetch;
  }
});

test("the request deadline bounds a legacy provider that ignores abort signals", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("Portal fetch must not start before credential lookup completes");
  };
  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    credentialProvider: {
      configured: () => true,
      async getCredentials() {
        return new Promise(() => {});
      },
    },
    portalRequestTimeoutMs: 15,
    credentialRefreshMs: 60_000,
  });

  try {
    const startedAt = Date.now();
    await assert.rejects(
      () => auth.signInWithPortalToken("ignoring-provider-token"),
      (error) =>
        error instanceof PortalCredentialError &&
        error.unavailable === false
    );
    assert.ok(Date.now() - startedAt < 500, "legacy provider escaped the request deadline");
  } finally {
    auth.close();
    db.close();
    globalThis.fetch = originalFetch;
  }
});

test("explicit credential rejection never falls back to the legacy key", async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, init) => {
    const path = new URL(String(url)).pathname;
    const headers = new Headers(init?.headers);
    if (path === "/api/credential-proof") {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    seen.push({
      credentialId: credentialId(init),
      legacy: headers.get("x-portal-key"),
    });
    return new Response("", { status: 401 });
  };

  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    sharedKey: "migration-only-key",
    credentialProvider: provider(),
    credentialRefreshMs: 20,
  });
  try {
    await delay(10);
    await assert.rejects(() => auth.signInWithPortalToken("revoked-token"));
    assert.deepEqual(seen, [
      { credentialId: pending.credentialId, legacy: null },
      { credentialId: current.credentialId, legacy: null },
    ]);
  } finally {
    auth.close();
    db.close();
    globalThis.fetch = originalFetch;
  }
});

test("a refresh outage after a 401 still fails closed", async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  let providerCalls = 0;
  globalThis.fetch = async (url, init) => {
    const path = new URL(String(url)).pathname;
    const headers = new Headers(init?.headers);
    if (path === "/api/credential-proof") {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    seen.push({
      credentialId: credentialId(init),
      legacy: headers.get("x-portal-key"),
    });
    return new Response("", { status: 401 });
  };

  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    sharedKey: "migration-only-key",
    credentialProvider: {
      configured: () => true,
      async getCredentials() {
        providerCalls += 1;
        if (providerCalls >= 3) {
          throw new Error("Secrets Manager refresh is unavailable");
        }
        return [{ ...current }];
      },
    },
    credentialRefreshMs: 60_000,
  });
  try {
    await delay(10);
    await assert.rejects(() => auth.signInWithPortalToken("revoked-token"));
    assert.deepEqual(seen, [
      { credentialId: current.credentialId, legacy: null },
    ]);
  } finally {
    auth.close();
    db.close();
    globalThis.fetch = originalFetch;
  }
});

test("app directory reads use the app-bound credential", async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, init) => {
    const path = new URL(String(url)).pathname;
    seen.push({ path, credentialId: credentialId(init) });
    if (path === "/api/credential-proof") {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (path === "/api/app-directory") {
      return new Response(
        JSON.stringify({ syncedAt: new Date().toISOString(), locations: [], people: [] }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }
    throw new Error(`Unexpected request: ${path}`);
  };

  const db = new Database(":memory:");
  const auth = createPortalAuth({
    db,
    appName: "example-app",
    portalUrl: "https://portal.example",
    credentialProvider: {
      configured: () => true,
      async getCredentials() {
        return [{ ...current }];
      },
    },
  });
  try {
    const directory = await auth.readAppDirectory();
    assert.deepEqual(directory.people, []);
    assert.ok(
      seen.some(
        (request) =>
          request.path === "/api/app-directory" &&
          request.credentialId === current.credentialId
      )
    );
  } finally {
    auth.close();
    db.close();
    globalThis.fetch = originalFetch;
  }
});
