import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { once } from "node:events";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { createPortalAuth, createPortalAuthAsync, PortalError } from "../dist/index.js";
import { PortalServiceAuth, fetchContext, fetchAppDirectory, redeemSso } from "../dist/portal.js";
import { childReceipt, validateTap, tlsTitle } from "../scripts/c2-evidence.mjs";

const credential = { schemaVersion: 1, appKey: "transport-test", credentialId: "synthetic-id", secret: "synthetic-secret-for-local-tests-only", stage: "AWSCURRENT" };
const context = { email: "test@example.invalid", name: "Test", role: "manager", is_admin: false, status: "active", active: true, locations: [], apps: ["transport-test"], ctx_version: 1 };
const provider = () => ({ configured: () => true, getCredentials: async () => [credential] });
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function environment(t, nodeEnv, render) {
  const saved = { NODE_ENV: process.env.NODE_ENV, RENDER: process.env.RENDER };
  for (const [key, value] of Object.entries({ NODE_ENV: nodeEnv, RENDER: render })) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  t.after(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
}

async function portal(t) {
  const received = [];
  const server = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    received.push({ path: req.url, headers: req.headers, body });
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(req.url.startsWith("/api/context") ? context : {
      email: context.email, context, revalidation_handle: "synthetic-handle", ok: true,
    }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  return { url: `http://127.0.0.1:${server.address().port}`, received };
}

function authFor(t, kind, url, credentials = true) {
  const db = new Database(":memory:");
  const config = { db, appName: "transport-test", portalUrl: url, sharedKey: "synthetic-legacy", credentialProvider: credentials ? provider() : { configured: () => false }, portalRequestTimeoutMs: 2000 };
  // The async directory and SSO rejection tests need no stored session. Any
  // accidental successful sign-in must fail explicitly at the store boundary.
  const store = { init: async () => {}, sweep: async () => {}, insert: async () => { throw new Error("unexpected session insertion"); } };
  const auth = kind === "sync" ? createPortalAuth(config) : createPortalAuthAsync({ ...config, sessionStore: store });
  t.after(() => { auth.close(); db.close(); });
  return auth;
}

for (const [label, nodeEnv, render] of [["production", "production", undefined], ["Render without NODE_ENV", undefined, "true"], ["Render with development NODE_ENV", "development", "1"]]) {
  test(`${label}: all HTTP transport paths reject without sending credentials`, async (t) => {
    environment(t, nodeEnv, render);
    const { url, received } = await portal(t);
    const results = [];
    for (const kind of ["sync", "async"]) {
      const auth = authFor(t, kind, url);
      results.push(...await Promise.allSettled([auth.signInWithPortalToken("synthetic-sso"), auth.readAppDirectory()]));
    }
    for (const credentials of [true, false]) {
      const serviceAuth = new PortalServiceAuth(credentials ? provider() : undefined, "synthetic-legacy", url, 60_000, "transport-test");
      t.after(() => serviceAuth.close());
      const opts = { portalUrl: url, appName: "transport-test", requestTimeoutMs: 2000, serviceAuth };
      results.push(...await Promise.allSettled([
        redeemSso(opts, "synthetic-sso"),
        fetchContext(opts, credentials ? "synthetic-handle" : undefined, context.email),
        fetchAppDirectory(opts),
        serviceAuth.request(`${url}/api/context`, {}, credentials ? "normal" : "legacy-only"),
      ]));
    }
    // Include the automatically launched proof cycles in the wire observation.
    await delay(100);
    assert.equal(received.length, 0, `unexpected cleartext requests: ${received.map((r) => r.path).join(", ")}`);
    for (const result of results) {
      assert.equal(result.status, "rejected");
      assert.ok(result.reason instanceof PortalError);
      assert.match(result.reason.message, /HTTPS/);
      assert.equal(result.reason.unavailable, false);
      assert.equal(result.reason.signedOut, false);
      assert.doesNotMatch(result.reason.message, /synthetic|127\.0\.0\.1|example\.invalid/);
    }
  });
}

for (const nodeEnv of [undefined, "development", "test"]) {
  test(`local HTTP remains usable with NODE_ENV=${nodeEnv}`, async (t) => {
    environment(t, nodeEnv, undefined);
    const { url, received } = await portal(t);
    const serviceAuth = new PortalServiceAuth(provider(), "", url, 60_000, "transport-test");
    t.after(() => serviceAuth.close());
    const opts = { portalUrl: url, appName: "transport-test", requestTimeoutMs: 2000, serviceAuth };
    try {
      assert.equal((await redeemSso(opts, "synthetic-sso")).email, context.email);
      assert.equal((await fetchContext(opts, "synthetic-handle", context.email)).email, context.email);
      await fetchAppDirectory(opts);
    } catch (error) {
      // Only the intended policy regression becomes mutation evidence. Preserve
      // unrelated runtime/transport errors instead of wrapping them as assertions.
      if (error instanceof PortalError && !error.unavailable &&
          error.message === "Portal URL must use HTTPS in production or on Render.") {
        assert.fail("Local HTTP development was incorrectly rejected by HTTPS policy");
      }
      throw error;
    }
    await delay(50);
    for (const path of ["/api/credential-proof", "/api/redeem-sso", "/api/context", "/api/app-directory?app=transport-test"]) {
      assert.ok(received.some((r) => r.path === path && r.headers.authorization === `PortalCredential ${credential.credentialId}.${credential.secret}`), path);
    }
    assert.ok(received.some((r) => r.body.includes("synthetic-sso")));
    assert.ok(received.some((r) => r.body.includes("synthetic-handle")));
  });
}

test("real trusted HTTPS transport and downgrade redirects", (t) => {
  const env = { ...process.env, NODE_EXTRA_CA_CERTS: fileURLToPath(new URL("./fixtures/localhost-cert.pem", import.meta.url)), NODE_ENV: "production", RENDER: "true" };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["--test", fileURLToPath(new URL("./fixtures/transport-tls.mjs", import.meta.url))], {
    env,
    encoding: "utf8", timeout: 30_000,
  });
  t.diagnostic(childReceipt(result).slice(2).trimEnd());
  // A child crash/load failure/cancellation is invalid evidence, never a
  // behavioral AssertionError. Retain the complete child receipt for the runner.
  const child = validateTap(result, [tlsTitle]);
  assert.equal(child.failed.length, 0, result.stdout);
});
