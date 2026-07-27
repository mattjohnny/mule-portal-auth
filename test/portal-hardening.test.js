import assert from "node:assert/strict";
import { test } from "node:test";
import {
  PortalCredentialError,
  PortalServiceAuth,
  fetchAppDirectory,
  fetchContext,
  redeemSso,
} from "../dist/portal.js";

const realFetch = globalThis.fetch;

function portalOpts(serviceAuth) {
  return {
    portalUrl: "https://portal.example",
    appName: "example-app",
    requestTimeoutMs: 100,
    serviceAuth,
  };
}

function cancellableResponse(status) {
  let cancellations = 0;
  const response = new Response(
    new ReadableStream({
      cancel() {
        cancellations += 1;
      },
    }),
    { status }
  );
  return { response, cancellations: () => cancellations };
}

test("every non-success Portal response body is cancelled before rejection", async (t) => {
  const serviceAuth = new PortalServiceAuth(
    undefined,
    "legacy-key",
    "https://portal.example",
    60_000,
    "example-app"
  );
  t.after(() => {
    serviceAuth.close();
    globalThis.fetch = realFetch;
  });

  await t.test("redeem", async () => {
    const tracked = cancellableResponse(403);
    globalThis.fetch = async () => tracked.response;
    await assert.rejects(
      () => redeemSso(portalOpts(serviceAuth), "one-time-token"),
      /disabled/
    );
    assert.equal(tracked.cancellations(), 1);
  });

  await t.test("redeem generic rejection", async () => {
    const tracked = cancellableResponse(429);
    globalThis.fetch = async () => tracked.response;
    await assert.rejects(
      () => redeemSso(portalOpts(serviceAuth), "one-time-token"),
      /invalid or has expired/
    );
    assert.equal(tracked.cancellations(), 1);
  });

  await t.test("context", async () => {
    const tracked = cancellableResponse(403);
    globalThis.fetch = async () => tracked.response;
    await assert.rejects(
      () =>
        fetchContext(
          portalOpts(serviceAuth),
          undefined,
          "manager@themule.ca"
        ),
      /rejected/
    );
    assert.equal(tracked.cancellations(), 1);
  });

  await t.test("directory", async () => {
    const tracked = cancellableResponse(403);
    globalThis.fetch = async () => tracked.response;
    await assert.rejects(
      () => fetchAppDirectory(portalOpts(serviceAuth)),
      /rejected/
    );
    assert.equal(tracked.cancellations(), 1);
  });
});

test("background proof logs safe discovery failures and keeps the 401 race quiet", async (t) => {
  const originalWarn = console.warn;
  t.after(() => {
    console.warn = originalWarn;
    globalThis.fetch = realFetch;
  });

  await t.test("discovery failure", async () => {
    const warnings = [];
    console.warn = (value) => warnings.push(String(value));
    globalThis.fetch = async () => {
      throw new Error("proof fetch must not run");
    };
    const serviceAuth = new PortalServiceAuth(
      {
        configured: () => true,
        async getCredentials() {
          const error = new Error(
            "sensitive secret and employee@example.com"
          );
          error.name = "AccessDeniedException";
          throw error;
        },
      },
      "",
      "https://portal.example",
      60_000,
      "example-app"
    );
    try {
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(warnings.length, 1);
      const event = JSON.parse(warnings[0]);
      assert.equal(event.event, "portal_credential_proof_discovery_failed");
      assert.equal(event.error_name, "AccessDeniedException");
      assert.equal("message" in event, false);
      assert.doesNotMatch(warnings[0], /sensitive|employee@/i);
    } finally {
      serviceAuth.close();
    }
  });

  await t.test("secret-shaped custom error names are not logged", async () => {
    const warnings = [];
    console.warn = (value) => warnings.push(String(value));
    const serviceAuth = new PortalServiceAuth(
      {
        configured: () => true,
        async getCredentials() {
          const error = new Error("provider failed");
          error.name = "credential_secret_abcdefghijklmnopqrstuvwxyz123456";
          throw error;
        },
      },
      "",
      "https://portal.example",
      60_000,
      "example-app"
    );
    try {
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(warnings.length, 1);
      const event = JSON.parse(warnings[0]);
      assert.equal(event.event, "portal_credential_proof_discovery_failed");
      assert.equal(event.error_name, "Error");
      assert.doesNotMatch(warnings[0], /credential_secret/i);
    } finally {
      serviceAuth.close();
    }
  });

  await t.test("expected registration race", async () => {
    const warnings = [];
    console.warn = (value) => warnings.push(String(value));
    globalThis.fetch = async () => new Response("", { status: 401 });
    const serviceAuth = new PortalServiceAuth(
      {
        configured: () => true,
        async getCredentials() {
          return [
            {
              schemaVersion: 1,
              appKey: "example-app",
              credentialId: "current-credential",
              secret: "currentsecretcurrentsecretcurrentsecret123",
              stage: "AWSCURRENT",
            },
          ];
        },
      },
      "",
      "https://portal.example",
      60_000,
      "example-app"
    );
    try {
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepEqual(warnings, []);
    } finally {
      serviceAuth.close();
    }
  });
});

test("an abort after credential discovery remains a hard credential failure", async (t) => {
  const controller = new AbortController();
  let enabled = false;
  const credentials = [
    {
      schemaVersion: 1,
      appKey: "example-app",
      credentialId: "current-credential",
      secret: "currentsecretcurrentsecretcurrentsecret123",
      stage: "AWSCURRENT",
    },
  ];
  const provider = {
    configured: () => enabled,
    getCredentials() {
      const result = Promise.resolve(credentials);
      result.then(() =>
        queueMicrotask(() =>
          controller.abort(new DOMException("deadline", "TimeoutError"))
        )
      );
      return result;
    },
  };
  const serviceAuth = new PortalServiceAuth(
    provider,
    "",
    "https://portal.example",
    60_000,
    "example-app"
  );
  let fetchCalls = 0;
  enabled = true;
  globalThis.fetch = async (_url, init) => {
    fetchCalls += 1;
    if (init?.signal?.aborted) throw init.signal.reason;
    return new Response("{}");
  };
  t.after(() => {
    serviceAuth.close();
    globalThis.fetch = realFetch;
  });

  await assert.rejects(
    () =>
      serviceAuth.request("https://portal.example/api/context", {
        signal: controller.signal,
      }),
    (error) => {
      assert.ok(error instanceof PortalCredentialError);
      assert.equal(error.unavailable, false);
      return true;
    }
  );
  assert.equal(fetchCalls, 0);
});
