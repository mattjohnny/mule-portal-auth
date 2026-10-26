// Run after build, without concurrent builds or integrations. Each mutation
// must load successfully and fail a named public-behavior assertion.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { basename } from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { validateTap } from "./c2-evidence.mjs";

const output = process.argv[2] ?? `docs/evidence/authority-mutations-${Date.now()}`;
mkdirSync(output, { recursive: false });
const originals = new Map(["dist/index.js", "dist/portal.js", "dist/safe-error.js", "dist/types.d.ts"].map((path) => [path, readFileSync(path)]));
const contractTitles = [
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
  ...["sync", "async"].flatMap((kind) => [
    "request mode refuses a dev session when the Portal is unconfigured",
    "request mode deletes the session when the app grant is revoked",
    "directory allows 30 seconds of clock skew and refuses more",
    "request mode revalidates every request through the handle and never rewrites the stored row",
    "cached mode rejects present malformed permissions and location flags",
    "directory rejects shared location keys, non-boolean options and undated logins",
  ].map((title) => `${kind}: ${title}`)),
];
const releaseGateTitles = [
  ...["sync", "async"].flatMap((kind) => [
    "the Portal's delta-seconds Retry-After reaches the 503, clamped to 1..300",
    "a 429 Retry-After never turns rate limiting into offline-admin access",
    "devSignIn is refused in request authority mode and unchanged in cached mode",
    "a session created with a revalidation handle never outlives the Portal's 8 h handle",
    "revalidation denials log the allow-listed PortalError name and no message",
    "a request's own authority wins over a req.context set by other middleware",
    "revalidateIfStale looks up the stored row's email and handle, not the caller's",
    "offline-admin break glass is decided by the stored row's email",
    "the connector exposes its validated authority mode read-only",
    "a refused directory names the failed check and position, never a value",
    "locations sharing an id are refused in contexts and directories",
    "only a plain delta-seconds Retry-After on a 429 or 503 is passed through",
    "a fresh cached revalidation returns the stored row, not the caller's Session",
    "a request requireAuth has not admitted has no context, whatever req.context says",
    "an SSO session is measured from before the Portal issued its handle",
  ].map((title) => `${kind}: ${title}`)),
  "async: request mode re-checks Portal configuration in revalidateUnderLock and refuses a dev row",
  "async: a session store's PortalError cannot set an out-of-range Retry-After",
  "async: a row a peer validated under the lock is returned from the store, not the caller's Session",
  "Portal error classes have allow-listed log names",
];
// Each suite runs as its own TAP process and must match its own exact plan;
// the census below is over both, in this order.
const suites = [["test/authority-contract.test.js", contractTitles], ["test/release-gate.test.js", releaseGateTitles]];
const titles = suites.flatMap(([, list]) => list);
assert.equal(new Set(titles).size, titles.length, "test titles must be unique across suites");
// A part naming one kind ("sync: …" / "async: …") selects only that kind's
// test: as a plain substring "sync: x" would also match "async: x".
const selects = (title, part) => /^a?sync: /.test(part) ? title.startsWith(part) : title.includes(part);

// `count` is the exact number of emitted occurrences of `from`. Without `at`
// every occurrence is replaced; with `at` only that one (0-based) is, which is
// how one of the sync/async factories' identical emitted twins is mutated
// alone. The sync factory is emitted first: at 0 = sync, at 1 = async.
const mutation = (file, from, to, count = 1, at) => ({ file, from, to, count, at });
const index = (from, to, count, at) => mutation("dist/index.js", from, to, count, at);
const portal = (from, to, count, at) => mutation("dist/portal.js", from, to, count, at);
const safeError = (from, to) => mutation("dist/safe-error.js", from, to);
const cases = [
  ["invalid-mode-fallback", [index('mode !== undefined && mode !== "cached" && mode !== "request"', 'false')], ["unknown authority modes"]],
  ["required-claims", [portal('opts.authorityMode === "request");', 'false);', 2)], ["additive roles", "even ops", "log the allow-listed PortalError name"]],
  ["role-contradiction", [portal('!validRoles(roles, ctx.role)', 'false')], ["additive roles", "legacy scalar payloads", "even ops", "log the allow-listed PortalError name"]],
  ["permission-validation", [portal('!permissionsInvariant ||', 'false ||')], ["additive roles", "cached mode rejects present malformed"]],
  ["canonical-context", [portal('validLocations(ctx.locations, strict)', 'validLocations(ctx.locations, false)')], ["additive roles"]],
  ["sso-email-validation", [portal('!validEmail(body?.email)', '!body?.email'), portal('!validEmail(email) ||', '!email ||')], ["malformed SSO"]],
  ["sso-handle-validation", [portal('body.revalidation_handle !== undefined && typeof body.revalidation_handle !== "string"', 'false'), portal('!body.revalidation_handle?.trim() && opts.serviceAuth.hasCredentialProvider()', 'false')], ["malformed SSO"]],
  ["request-cache-reuse", [index('!requestAuthority &&\n            hasCurrentAuthorityProvenance(row.source)', 'hasCurrentAuthorityProvenance(row.source)', 3)], ["even ops", "request authority refreshes", "request authority does not require", "post-fetch session-store", "request mode refuses a dev session", "request mode deletes the session", "request mode revalidates every request", "log the allow-listed PortalError name", "only a plain delta-seconds Retry-After", "async: request mode re-checks Portal configuration in revalidateUnderLock"]],
  ["earlier-inflight-reuse", [index('if (requestAuthority)\n            return revalidateOnce(session);', '// fresh bypass removed', 2)], ["later requests never share", "request mode revalidates every request"]],
  ["offline-fallback", [index('!requestAuthority &&\n                allowOfflineAdmin', 'allowOfflineAdmin', 4)], ["request authority refreshes"]],
  ["ops-app-bypass", [index('(requestAuthority || !context.is_admin)', '!context.is_admin', 2), index('(requestAuthority || !ctx.is_admin)', '!ctx.is_admin', 4)], ["even ops"]],
  ["deleted-session-admission", [index('if (!getRow(session.token))\n                return null;', 'if (false) return null;'), index('if (!await getRow(session.token))\n                return null;', 'if (false) return null;')], ["later requests never share", "post-fetch session-store"]],
  ["request-snapshot-write", [index('else\n            await saveContext(session.token, ctx);', 'await saveContext(session.token, ctx);')], ["request authority does not require", "async: request mode revalidates every request"]],
  ["non-mule-option", [portal('endpoint.searchParams.set("include_non_mule", "true");', 'endpoint.searchParams.set("include_non_mule", "false");')], ["typed directory is fresh"]],
  ["directory-shape-validation", [portal('return validateDirectory(await response.json(), options, startedAt);', 'return await response.json();')], ["missing stale", "directory allows 30 seconds", "directory rejects shared location keys", "a refused directory names the failed check", "locations sharing an id are refused"]],
  ["directory-location-contradiction", [portal('return !canonical || canonical.key !== location.key || canonical.name !== location.name || canonical.is_mule !== location.is_mule;', 'return false;')], ["missing stale", "a refused directory names the failed check"]],
  ["directory-past-timestamp", [portal('syncedAt < startedAt - 30_000 || Math.abs(receivedAt - syncedAt) > 30_000', 'syncedAt > receivedAt + 30_000')], ["missing stale", "directory allows 30 seconds", "a refused directory names the failed check"]],
  ["directory-future-timestamp", [portal('Math.abs(receivedAt - syncedAt) > 30_000', 'receivedAt - syncedAt > 30_000')], ["missing stale", "directory allows 30 seconds"]],
  ["legacy-type-compatibility", [mutation("dist/types.d.ts", 'roles?: string[];', 'roles: string[];')], ["legacy scalar consumers"]],
  // Release-gate additions. Each edits one emitted site. The async dev guard in
  // revalidateUnderLock is its own mutant below (async-dev-guard-under-lock):
  // revalidateUnderLock re-checks Portal configuration after revalidateOnce did
  // (request mode calls it directly, without a lock), and it can change between.
  ["sync-dev-request-guard", [index(`deny.\n            if (!requestAuthority && row.source === "dev")`, `deny.\n            if (row.source === "dev")`)], ["sync: request mode refuses a dev session"]],
  ["async-dev-request-guard", [index('if (!requestAuthority && row.source === "dev")\n                return rowToSession(row);\n            throw new PortalError("Portal access verification isn\'t configured.");\n        }\n        if (!requestAuthority && store.withRevalidationLock)', 'if (row.source === "dev")\n                return rowToSession(row);\n            throw new PortalError("Portal access verification isn\'t configured.");\n        }\n        if (!requestAuthority && store.withRevalidationLock)')], ["async: request mode refuses a dev session"]],
  ["sync-revoked-grant-kept", [index('!ctx.apps.includes(appName)) {\n            destroy(session.token);', '!ctx.apps.includes(appName)) {')], ["sync: request mode deletes the session"]],
  ["async-revoked-grant-kept", [index('!ctx.apps.includes(appName)) {\n            await destroy(session.token);', '!ctx.apps.includes(appName)) {')], ["async: request mode deletes the session"]],
  ["directory-skew-narrowed", [portal('Math.abs(receivedAt - syncedAt) > 30_000', 'Math.abs(receivedAt - syncedAt) > 10_000')], ["directory allows 30 seconds"]],
  ["directory-skew-widened", [portal('Math.abs(receivedAt - syncedAt) > 30_000', 'Math.abs(receivedAt - syncedAt) > 60_000')], ["directory allows 30 seconds"]],
  ["directory-start-skew-narrowed", [portal('syncedAt < startedAt - 30_000', 'syncedAt < startedAt - 10_000')], ["directory allows 30 seconds"]],
  ["handle-transport", [portal('const useHandle = !!revalidationHandle && opts.serviceAuth.hasCredentialProvider();', 'const useHandle = false;')], ["request mode deletes the session", "request mode revalidates every request", "revalidateIfStale looks up the stored row"]],
  ["sync-request-snapshot-write", [index('else\n            saveContext(session.token, ctx);', 'saveContext(session.token, ctx);')], ["sync: request mode revalidates every request"]],
  ["cached-permission-keys", [portal('appsInvariant && ctx.apps.includes(app) && stringSet(values)', 'appsInvariant && (!strict || ctx.apps.includes(app)) && stringSet(values)')], ["cached mode rejects present malformed"]],
  ["cached-location-flag", [portal('(!requireCanonical && location.is_mule === undefined)', '!requireCanonical')], ["cached mode rejects present malformed"]],
  ["directory-shared-location-key", [portal('if (keys.has(location.key))', 'if (false)')], ["directory rejects shared location keys", "a refused directory names the failed check"]],
  ["directory-option-type", [portal('options.include_non_mule !== undefined && typeof options.include_non_mule !== "boolean"', 'false')], ["directory rejects shared location keys"]],
  ["directory-last-login-date", [portal('Number.isFinite(Date.parse(person.last_login))', 'true')], ["directory rejects shared location keys"]],
  // test/release-gate.test.js guards (issue #11 review fixes). index.js
  // retryAfterSeconds' own guard is reachable (a session store can throw a
  // PortalError carrying any value) and is mutated below (index-retry-after-*).
  ["sync-retry-after-fixed", [index('res.setHeader("Retry-After", String(retryAfterSeconds(error)));', 'res.setHeader("Retry-After", "5");', 2, 0)], ["sync: the Portal's delta-seconds Retry-After", "sync: a 429 Retry-After", "sync: only a plain delta-seconds Retry-After"]],
  ["async-retry-after-fixed", [index('res.setHeader("Retry-After", String(retryAfterSeconds(error)));', 'res.setHeader("Retry-After", "5");', 2, 1)], ["async: the Portal's delta-seconds Retry-After", "async: a 429 Retry-After", "async: only a plain delta-seconds Retry-After", "async: a session store's PortalError cannot set"]],
  ["context-retry-after-dropped", [portal('false, unavailable, { retryAfterSeconds });', 'false, unavailable, {});')], ["the Portal's delta-seconds Retry-After", "a 429 Retry-After", "only a plain delta-seconds Retry-After"]],
  ["sync-request-dev-sign-in", [index('if (requestAuthority)\n            throw new PortalError("Development sign-in', 'if (false)\n            throw new PortalError("Development sign-in', 2, 0)], ["sync: devSignIn is refused"]],
  ["async-request-dev-sign-in", [index('if (requestAuthority)\n            throw new PortalError("Development sign-in', 'if (false)\n            throw new PortalError("Development sign-in', 2, 1)], ["async: devSignIn is refused"]],
  ["handle-session-ttl", [index('return now + (revalidationHandle ? Math.min(sessionTtlMs, PORTAL_HANDLE_TTL_MS) : sessionTtlMs);', 'return now + sessionTtlMs;')], ["never outlives the Portal's 8 h handle", "an SSO session is measured from before"]],
  ["portal-error-log-name", [safeError('    "PortalError",\n', '')], ["log the allow-listed PortalError name", "Portal error classes have allow-listed log names"]],
  ["credential-error-log-name", [safeError('    "PortalCredentialError",\n', '')], ["Portal error classes have allow-listed log names"]],
  ["to-context-precedence", [index('if ("portal" in src && src.portal)', 'if ("context" in src && src.context)\n        return src.context;\n    if ("portal" in src && src.portal)')], ["a request's own authority wins", "a request requireAuth has not admitted"]],
  ["sync-lookup-session-handle", [index('ctx = await fetchContext(portal, row.revalidation_handle || undefined, row.email);', 'ctx = await fetchContext(portal, session.revalidationHandle, row.email);', 2, 0)], ["sync: revalidateIfStale looks up the stored row"]],
  ["async-lookup-session-handle", [index('ctx = await fetchContext(portal, row.revalidation_handle || undefined, row.email);', 'ctx = await fetchContext(portal, session.revalidationHandle, row.email);', 2, 1)], ["async: revalidateIfStale looks up the stored row"]],
  ["sync-lookup-session-email", [index('ctx = await fetchContext(portal, row.revalidation_handle || undefined, row.email);', 'ctx = await fetchContext(portal, row.revalidation_handle || undefined, session.email);', 2, 0)], ["sync: revalidateIfStale looks up the stored row"]],
  ["async-lookup-session-email", [index('ctx = await fetchContext(portal, row.revalidation_handle || undefined, row.email);', 'ctx = await fetchContext(portal, row.revalidation_handle || undefined, session.email);', 2, 1)], ["async: revalidateIfStale looks up the stored row"]],
  ["sync-returned-session-handle", [index('revalidationHandle: row.revalidation_handle || undefined,\n        };\n    }\n    function revalidateIfStale', 'revalidationHandle: session.revalidationHandle,\n        };\n    }\n    function revalidateIfStale')], ["sync: revalidateIfStale looks up the stored row"]],
  ["async-returned-session-handle", [index('revalidationHandle: row.revalidation_handle || undefined,\n        };\n    }\n    async function revalidateOnce', 'revalidationHandle: session.revalidationHandle,\n        };\n    }\n    async function revalidateOnce')], ["async: revalidateIfStale looks up the stored row"]],
  ["sync-offline-admin-session-email", [index('adminEmails.has(row.email) &&', 'adminEmails.has(session.email) &&', 2, 0)], ["sync: offline-admin break glass is decided"]],
  ["async-offline-admin-session-email", [index('adminEmails.has(row.email) &&', 'adminEmails.has(session.email) &&', 2, 1)], ["async: offline-admin break glass is decided"]],
  ["sync-writable-authority-mode", [index('get authorityMode() {\n            return authorityMode;\n        },', 'authorityMode,', 2, 0)], ["sync: the connector exposes its validated authority mode"]],
  ["async-writable-authority-mode", [index('get authorityMode() {\n            return authorityMode;\n        },', 'authorityMode,', 2, 1)], ["async: the connector exposes its validated authority mode"]],
  ["authority-mode-default", [index('return mode ?? "cached";', 'return mode;')], ["the connector exposes its validated authority mode"]],
  ["directory-detail-dropped", [portal('detail: error instanceof PortalError ? error.detail : undefined,', 'detail: undefined,')], ["a refused directory names the failed check", "locations sharing an id are refused"]],
  // PR #12 review fixes. Not declared: removing `syncedAt < startedAt - 30_000`
  // is equivalent, because receivedAt >= startedAt means any syncedAt it rejects
  // is already more than 30 s before receivedAt and the absolute check rejects
  // it too (barring a backwards wall-clock step between the two readings).
  ["async-dev-guard-under-lock", [index('if (!portalUrl || !serviceAuth.configured()) {\n            if (!requestAuthority && row.source === "dev")\n                return rowToSession(row);\n            throw new PortalError("Portal access verification isn\'t configured.");\n        }\n        // The stored row', 'if (!portalUrl || !serviceAuth.configured()) {\n            if (row.source === "dev")\n                return rowToSession(row);\n            throw new PortalError("Portal access verification isn\'t configured.");\n        }\n        // The stored row')], ["async: request mode re-checks Portal configuration in revalidateUnderLock"]],
  ["location-shared-id", [portal('if (ids.has(location.id))', 'if (false)')], ["locations sharing an id are refused"]],
  ["index-retry-after-range", [index('value >= MIN_RETRY_AFTER_SECONDS && value <= MAX_RETRY_AFTER_SECONDS', 'true')], ["async: a session store's PortalError cannot set"]],
  ["index-retry-after-integer", [index('Number.isSafeInteger(value) &&', '')], ["async: a session store's PortalError cannot set"]],
  ["index-retry-after-typeof-only", [index('typeof value === "number" && Number.isSafeInteger(value) &&\n        value >= MIN_RETRY_AFTER_SECONDS && value <= MAX_RETRY_AFTER_SECONDS', 'typeof value === "number"')], ["async: a session store's PortalError cannot set"]],
  ["portal-retry-after-format", [portal('!value || !/^\\d+$/.test(value)', '!value')], ["only a plain delta-seconds Retry-After"]],
  ["portal-retry-after-end-anchor", [portal('/^\\d+$/', '/^\\d+/')], ["only a plain delta-seconds Retry-After"]],
  ["portal-retry-after-502", [portal('response.status !== 429 && response.status !== 503', 'response.status !== 429 && response.status !== 503 && response.status !== 502')], ["only a plain delta-seconds Retry-After"]],
  ["directory-skew-25s", [portal('Math.abs(receivedAt - syncedAt) > 30_000', 'Math.abs(receivedAt - syncedAt) > 25_000')], ["directory allows 30 seconds"]],
  ["directory-skew-40s", [portal('Math.abs(receivedAt - syncedAt) > 30_000', 'Math.abs(receivedAt - syncedAt) > 40_000')], ["directory allows 30 seconds"]],
  // The fresh path is emitted three times: sync revalidateOnce (at 0), async
  // revalidateUnderLock (at 1, defined first) and async revalidateOnce (at 2).
  ["sync-fresh-caller-session", [index('Date.now() - row.last_validated < revalidateMs)\n            return rowToSession(row);', 'Date.now() - row.last_validated < revalidateMs)\n            return session;', 3, 0)], ["sync: a fresh cached revalidation returns the stored row"]],
  ["async-locked-fresh-caller-session", [index('Date.now() - row.last_validated < revalidateMs)\n            return rowToSession(row);', 'Date.now() - row.last_validated < revalidateMs)\n            return session;', 3, 1)], ["async: a row a peer validated under the lock"]],
  ["async-fresh-caller-session", [index('Date.now() - row.last_validated < revalidateMs)\n            return rowToSession(row);', 'Date.now() - row.last_validated < revalidateMs)\n            return session;', 3, 2)], ["async: a fresh cached revalidation returns the stored row"]],
  ["to-context-unadmitted-request", [index('if ("headers" in src)\n        return null;\n', '')], ["a request requireAuth has not admitted"]],
  ["sync-sso-start-after-redeem", [index('return startLocalSession(context, PORTAL_AUTHORITY_SOURCE, revalidationHandle, startedAt);', 'return startLocalSession(context, PORTAL_AUTHORITY_SOURCE, revalidationHandle);', 2, 0)], ["sync: an SSO session is measured from before"]],
  ["async-sso-start-after-redeem", [index('return startLocalSession(context, PORTAL_AUTHORITY_SOURCE, revalidationHandle, startedAt);', 'return startLocalSession(context, PORTAL_AUTHORITY_SOURCE, revalidationHandle);', 2, 1)], ["async: an SSO session is measured from before"]],
];

function restore() {
  for (const [path, bytes] of originals) writeFileSync(path, bytes);
}
function run(name) {
  const failed = [];
  for (const [file, list] of suites) {
    const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", file], { encoding: "utf8", timeout: 30_000 });
    writeFileSync(`${output}/${name}.${basename(file, ".test.js")}.tap`, `${result.stdout ?? ""}${result.stderr ?? ""}`);
    failed.push(...validateTap(result, list).failed);
  }
  return { failed };
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
    for (const { file, from, to, count, at } of patches) {
      const text = readFileSync(file, "utf8");
      const pieces = text.split(from);
      assert.equal(pieces.length - 1, count, `${name}: mutation anchor`);
      if (at === undefined) writeFileSync(file, text.replaceAll(from, to));
      else {
        assert.ok(Number.isInteger(at) && at >= 0 && at < count, `${name}: mutation occurrence`);
        writeFileSync(file, pieces.slice(0, at + 1).join(from) + to + pieces.slice(at + 1).join(from));
      }
    }
    preflight();
    const expected = titles.filter((title) => expectedParts.some((part) => selects(title, part)));
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
