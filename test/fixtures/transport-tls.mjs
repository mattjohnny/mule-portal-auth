// Real TLS and HTTP listeners. The checked-in key is a disposable localhost
// fixture, not a credential; trust is limited to the spawned test process.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer as httpsServer } from "node:https";
import { createServer as httpServer } from "node:http";
import { readFileSync } from "node:fs";
import { once } from "node:events";
import { PortalServiceAuth, PortalError, redeemSso, fetchContext, fetchAppDirectory } from "../../dist/portal.js";

const current = { schemaVersion: 1, appKey: "transport-test", credentialId: "synthetic-current", secret: "synthetic-secret-only", stage: "AWSCURRENT" };
const pending = { ...current, credentialId: "synthetic-pending", stage: "AWSPENDING" };
const context = { email: "test@example.invalid", name: "Test", role: "manager", is_admin: false, status: "active", active: true, locations: [], apps: ["transport-test"], ctx_version: 1 };
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function listen(t, server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  return server.address().port;
}

test("HTTPS succeeds; redirects cannot move credentials, bodies or proof trust", async (t) => {
  const leaked = [];
  const sinkPort = await listen(t, httpServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    leaked.push({ path: req.url, body, headers: req.headers });
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ ...context, email: context.email, context, revalidation_handle: "synthetic-handle" }));
  }));
  let redirectStatus = 0;
  let redirectTarget = "";
  const received = [];
  const server = httpsServer({
    cert: readFileSync(new URL("localhost-cert.pem", import.meta.url)),
    key: readFileSync(new URL("localhost-key.pem", import.meta.url)),
  }, async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    received.push({ path: req.url, body, headers: req.headers });
    if (redirectStatus && !req.url.startsWith("/redirect-target")) {
      res.writeHead(redirectStatus, { location: redirectTarget });
      res.end("redirect");
      return;
    }
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(req.url.startsWith("/api/context") ? context : { email: context.email, context, revalidation_handle: "synthetic-handle", ok: true }));
  });
  const port = await listen(t, server);
  const portalUrl = `https://127.0.0.1:${port}`;
  function auth(credentials = true) {
    const serviceAuth = new PortalServiceAuth(credentials ? { configured: () => true, getCredentials: async () => [pending, current] } : undefined, "synthetic-legacy", portalUrl, 60_000, "transport-test");
    t.after(() => serviceAuth.close());
    return { portalUrl, appName: "transport-test", requestTimeoutMs: 2000, serviceAuth };
  }
  const success = auth();
  assert.equal((await redeemSso(success, "synthetic-sso")).email, context.email);
  assert.equal((await fetchContext(success, "synthetic-handle", context.email)).email, context.email);
  await fetchAppDirectory(success);
  await delay(100);
  assert.ok(received.some((r) => r.path === "/api/credential-proof" && r.headers.authorization?.includes("synthetic-pending")));
  assert.equal(leaked.length, 0);
  success.serviceAuth.close();

  for (const target of [`http://127.0.0.1:${sinkPort}/redirect-target`, `${portalUrl}/redirect-target`]) {
    for (const status of [301, 302, 303, 307, 308]) {
      redirectStatus = status;
      redirectTarget = target;
      const before = received.length;
      for (const credentials of [true, false]) {
        const opts = auth(credentials);
        const outcomes = await Promise.allSettled([
          redeemSso(opts, "synthetic-sso"),
          fetchContext(opts, credentials ? "synthetic-handle" : undefined, context.email),
          fetchAppDirectory(opts),
        ]);
        await delay(50);
        // Calling request with follow explicitly cannot override the invariant.
        const raw = await opts.serviceAuth.request(`${portalUrl}/api/app-directory`, { redirect: "follow" });
        await raw.body?.cancel();
        assert.equal(raw.status, status);
        for (const outcome of outcomes) {
          assert.equal(outcome.status, "rejected", `${status} ${target}`);
          assert.ok(outcome.reason instanceof PortalError);
          assert.equal(outcome.reason.unavailable, false);
        }
        // A redirect from credential-proof must not promote AWSPENDING.
        const normal = received.slice(before).filter((r) => !r.path.startsWith("/api/credential-proof"));
        assert.ok(normal.every((r) => !r.headers.authorization?.includes("synthetic-pending")));
        opts.serviceAuth.close();
      }
      assert.equal(leaked.length, 0, "HTTP sink received a redirected request");
      assert.equal(received.slice(before).filter((r) => r.path.startsWith("/redirect-target")).length, 0, "same-origin redirect was followed");
    }
  }
});
