// Run after build, without concurrent builds or integrations. Each mutation
// must load successfully and fail a named public-behavior assertion.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { validateTap } from "./c2-evidence.mjs";

const output = process.argv[2] ?? `docs/evidence/authority-mutations-${Date.now()}`;
mkdirSync(output, { recursive: false });
const originals = new Map(["dist/index.js", "dist/portal.js", "dist/types.d.ts"].map((path) => [path, readFileSync(path)]));
const titles = [
  "unknown authority modes fail configuration instead of falling back to cached trust",
  "legacy scalar consumers and typed directory declarations compile",
  ...["sync", "async"].flatMap((kind) => [
    "additive roles preserve the primary role and malformed grants fail closed",
    "malformed SSO email and handle never become sessions",
    "legacy scalar payloads retain cached access but malformed additive claims are rejected",
    "even ops needs a current app grant and malformed live authority never falls back",
    "request authority refreshes views downloads and mutations and refuses offline fallback",
    "later requests never share authority fetched before a confirmed revocation",
    "typed directory is fresh and non-Mule locations are opt-in",
    "missing stale and contradictory directory evidence is refused",
  ].map((title) => `${kind}: ${title}`)),
  "async: request authority does not require writing a cached context snapshot",
  "async: post-fetch session-store failure denies without leaking error content",
];

const mutation = (file, from, to, count = 1) => ({ file, from, to, count });
const index = (from, to, count) => mutation("dist/index.js", from, to, count);
const portal = (from, to, count) => mutation("dist/portal.js", from, to, count);
const cases = [
  ["invalid-mode-fallback", [index('mode !== undefined && mode !== "cached" && mode !== "request"', 'false')], ["unknown authority modes"]],
  ["required-claims", [portal('opts.authorityMode === "request");', 'false);', 2)], ["additive roles", "even ops"]],
  ["role-contradiction", [portal('!validRoles(roles, ctx.role)', 'false')], ["additive roles", "legacy scalar payloads", "even ops"]],
  ["additional-role-allowlist", [portal('ADDITIONAL_PORTAL_ROLES.has(role)', 'true')], ["additive roles", "missing stale"]],
  ["hr-role-dropped", [portal('new Set(["finance", "hr"])', 'new Set(["finance"])')], ["additive roles", "typed directory is fresh"]],
  ["permission-validation", [portal('!permissionsInvariant ||', 'false ||')], ["additive roles"]],
  ["canonical-context", [portal('validLocations(ctx.locations, strict)', 'validLocations(ctx.locations, false)')], ["additive roles"]],
  ["sso-email-validation", [portal('!validEmail(body?.email)', '!body?.email'), portal('!validEmail(email) ||', '!email ||')], ["malformed SSO"]],
  ["sso-handle-validation", [portal('body.revalidation_handle !== undefined && typeof body.revalidation_handle !== "string"', 'false'), portal('!body.revalidation_handle?.trim() && opts.serviceAuth.hasCredentialProvider()', 'false')], ["malformed SSO"]],
  ["request-cache-reuse", [index('!requestAuthority &&\n            hasCurrentAuthorityProvenance(row.source)', 'hasCurrentAuthorityProvenance(row.source)', 3)], ["even ops", "request authority refreshes", "request authority does not require", "post-fetch session-store"]],
  ["earlier-inflight-reuse", [index('if (requestAuthority)\n            return revalidateOnce(session);', '// fresh bypass removed', 2)], ["later requests never share"]],
  ["offline-fallback", [index('!requestAuthority &&\n                allowOfflineAdmin', 'allowOfflineAdmin', 4)], ["request authority refreshes"]],
  ["ops-app-bypass", [index('(requestAuthority || !context.is_admin)', '!context.is_admin', 2), index('(requestAuthority || !ctx.is_admin)', '!ctx.is_admin', 4)], ["even ops"]],
  ["deleted-session-admission", [index('if (!getRow(session.token))\n                return null;', 'if (false) return null;'), index('if (!await getRow(session.token))\n                return null;', 'if (false) return null;')], ["later requests never share", "post-fetch session-store"]],
  ["request-snapshot-write", [index('else\n            await saveContext(session.token, ctx);', 'await saveContext(session.token, ctx);')], ["request authority does not require"]],
  ["non-mule-option", [portal('endpoint.searchParams.set("include_non_mule", "true");', 'endpoint.searchParams.set("include_non_mule", "false");')], ["typed directory is fresh"]],
  ["directory-shape-validation", [portal('return validateDirectory(await response.json(), options, startedAt);', 'return await response.json();')], ["missing stale"]],
  ["directory-location-contradiction", [portal('return !canonical || canonical.key !== location.key || canonical.name !== location.name || canonical.is_mule !== location.is_mule;', 'return false;')], ["missing stale"]],
  ["directory-past-timestamp", [portal('syncedAt < startedAt - 30_000 || Math.abs(receivedAt - syncedAt) > 30_000', 'syncedAt > receivedAt + 30_000')], ["missing stale"]],
  ["directory-future-timestamp", [portal('Math.abs(receivedAt - syncedAt) > 30_000', 'receivedAt - syncedAt > 30_000')], ["missing stale"]],
  ["legacy-type-compatibility", [mutation("dist/types.d.ts", 'roles?: string[];', 'roles: string[];')], ["legacy scalar consumers"]],
];

function restore() {
  for (const [path, bytes] of originals) writeFileSync(path, bytes);
}
function run(name) {
  const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", "test/authority-contract.test.js"], { encoding: "utf8", timeout: 30_000 });
  writeFileSync(`${output}/${name}.tap`, `${result.stdout ?? ""}${result.stderr ?? ""}`);
  return validateTap(result, titles);
}
function preflight() {
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", "await import('./dist/index.js'); await import('./dist/portal.js');"], { encoding: "utf8", timeout: 10_000 });
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
}

const results = [];
try {
  preflight();
  assert.deepEqual(run("baseline").failed, []);
  for (const [name, patches, expectedParts] of cases) {
    restore();
    for (const { file, from, to, count } of patches) {
      const text = readFileSync(file, "utf8");
      assert.equal(text.split(from).length - 1, count, `${name}: mutation anchor`);
      writeFileSync(file, text.replaceAll(from, to));
    }
    preflight();
    const expected = titles.filter((title) => expectedParts.some((part) => title.includes(part)));
    assert.ok(expected.length > 0);
    const { failed } = run(name);
    assert.deepEqual(failed, expected, `${name}: unexpected failure census`);
    results.push({ name, result: "assertion-killed", failed });
    console.log(`${name}: assertion-killed`);
  }
} finally {
  restore();
  for (const [path, bytes] of originals) assert.deepEqual(readFileSync(path), bytes);
  writeFileSync(`${output}/mutations.json`, JSON.stringify({ runtime: process.version, results }, null, 2) + "\n");
}
assert.deepEqual(run("restored").failed, []);
writeFileSync(`${output}/completion.json`, JSON.stringify({
  status: "complete", declaredMutants: cases.length, assertionKilled: results.length,
  exactByteRestoration: true, restoredBaseline: "passed",
  artifacts: Object.fromEntries([...originals].map(([path, bytes]) => [path, createHash("sha256").update(bytes).digest("hex")])),
}, null, 2) + "\n");
console.log(`${results.length}/${cases.length} killed; exact bytes restored; restored suite passed`);
