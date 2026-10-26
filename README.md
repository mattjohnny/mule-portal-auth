# @mule/portal-auth

The shared identity client every Mule app uses to talk to **The Mule Portal**.
It replaces the copied-and-drifting `auth.ts` that each app used to hand-roll.

One module does three things (see `mule-portal/docs/identity-and-access.md` §8):

1. **Sign in** — trade the Portal's one-click SSO token for a local session.
   Legacy deployments without an app-bound credential may also verify a direct
   Google sign-in and pull the person's context from the Portal.
2. **Read identity facts** — role, `is_admin`, the location set (or `"all"`), and
   the apps a person may open — sourced from the Portal, never re-derived.
3. **Revoke-now (§7 R1)** — re-check each live session against the Portal at most
   every 5 minutes; if the person was disabled/removed, their session is
   destroyed and the next request is rejected. The Portal is the single kill
   switch for every app.

## Install

Pin it by git URL + tag/commit in the app's `package.json`:

```jsonc
"dependencies": {
  "@mule/portal-auth": "github:mattjohnny/mule-portal-auth#v0.2.2"
}
```

`better-sqlite3`, `express`, and (optionally) `google-auth-library` are peer
dependencies — the app already has them.

### v0.2.2 release gates

Complete this release in order:

1. Merge Portal Auth PR #4 into `main`.
2. Create and publish the `v0.2.2` tag from that merged `main` commit.
3. Update both the package and lockfile pin in Labour Live PR #47 to `v0.2.2`,
   rerun its checks, and only then merge that PR.

Do not begin the remaining fleet bump until all three steps are complete.

## Use

Portal requests require HTTPS when `NODE_ENV=production` or `RENDER` is nonempty.
An HTTP URL fails locally with `PortalError.unavailable === false`; it cannot
activate outage-only access. HTTP remains available for local development and
tests outside those environments. This check occurs when a Portal request is
made, including background credential proof; construction alone is not a URL
validation check.

Portal responses must be direct: redirects are never followed for app credentials
or legacy keys, including SSO bodies, revalidation handles and credential proof.
Configure the final Portal HTTPS URL instead of a redirecting alias.

```ts
import Database from "better-sqlite3";
import { createPortalAuth } from "@mule/portal-auth";

const db = new Database("app.db");
const auth = createPortalAuth({
  db,                       // the app's own database; one `portal_sessions` table is added
  appName: "training-days", // this app's key in the Portal
  // portalUrl / sharedKey / googleClientId / allowedDomains / adminEmails all
  // default to the matching env vars (PORTAL_URL, PORTAL_SHARED_KEY, …).
});

// Sign-in routes
app.post("/auth/portal", async (req, res) => {
  const s = await auth.signInWithPortalToken(String(req.body.token || ""));
  res.json({ token: s.token, name: s.name, role: s.context.role });
});

// Protect routes
app.get("/api/me", auth.requireAuth, (req, res) => res.json(req.portal!.context));
app.post("/api/admin/thing", auth.requireAdmin, (req, res) => { /* ops only */ });

// Scope every query, server-side (§6)
app.get("/api/data", auth.requireAuth, (req, res) => {
  const scope = auth.locationIds(req);        // number[] | "all"
  res.json(readData(scope));                  // filter to the person's locations
});
```

## Surface

| Function | What it does |
|---|---|
| `signInWithPortalToken(ssoToken)` | Redeem the Portal handoff → local `Session` with full context |
| `signInWithGoogle(idToken)` | Legacy direct-door sign-in; unavailable once an app-bound credential provider is configured |
| `requireAuth` / `requireAdmin` | Express middleware; attaches `req.portal`; re-validates on the §7 cadence |
| `getContext(req \| session)` | The resolved `Context` |
| `locationIds(req \| session)` | `number[]` the person may see, or `"all"` for ops |
| `revalidateIfStale(session)` | Force the §7 re-check; returns the session, or `null` if signed out |
| `logout(token)` | Destroy a local session |

## Config knobs

| Option | Default | Meaning |
|---|---|---|
| `sessionTtlMs` | `8h` | Fallback session lifetime (§7 belt-and-braces) |
| `revalidateMs` | `5min` | Max time between Portal re-checks (§7 R1 SLA) |
| `portalRequestTimeoutMs` | `5s` | Maximum wait for a Portal sign-in or context request |
| `credentialSecretArn` | `PORTAL_CREDENTIAL_SECRET_ARN` | App-bound AWS Secrets Manager credential |
| `awsRegion` | `AWS_REGION` | Region containing the app credential |
| `credentialRefreshMs` | `60s` | Refresh stages and synthetically prove pending credentials |
| `googleClientId` | `GOOGLE_CLIENT_ID` | Enables legacy direct Google sign-in only before app-bound credential migration |
| `adminEmails` | `ADMIN_EMAILS` env | Emails eligible for explicit outage-only break glass; never overrides a successful Portal role or app decision |
| `allowOfflineAdmin` | `false` | Outage-only break glass for `ADMIN_EMAILS`; the Portal must still be configured |

## Rotating app credentials

Production services authenticate to Portal with one app-bound secret from AWS
Secrets Manager. Render assumes the app's exact-service IAM role through OIDC;
do not set long-lived AWS access keys. Configure `AWS_ROLE_ARN`, `AWS_REGION`,
and `PORTAL_CREDENTIAL_SECRET_ARN`.

The connector refreshes `AWSCURRENT` and `AWSPENDING` in the background. It
synthetically proves new credentials even when the app has no user traffic,
uses a proven pending credential first, and falls back to `AWSCURRENT` on 401.
The configured Portal request timeout covers Secrets Manager credential loading,
the Portal request, and its response body; a cold or refreshing AWS lookup cannot
extend that deadline. The caller enforces the bound even for an older injected
provider that ignores `AbortSignal`. Coalesced AWS loads use a group-owned abort
signal, so one request timing out cannot cancel another live waiter. Legacy
shared-key requests include the app claim for
migration telemetry, but the Portal never treats that claim as authorization.
During migration, `PORTAL_SHARED_KEY` still supports legacy-only deployments
that have no credential provider. Once `credentialSecretArn` or an injected
provider is configured, normal service requests never fall back to the shared
key. Configuring a provider also disables new direct Google sign-ins because the
legacy context-by-email exchange cannot issue an app/user-bound revalidation
handle; new production sessions must enter through Portal SSO. Explicit
legacy-only revalidation remains available for sessions created before migration
until their original expiry. No new legacy-only sessions are created after the
migration deploy, so with the default session TTL the drain is at most 8 hours
(use the configured `sessionTtlMs` instead if it was overridden). A provider with
a cold cache therefore fails closed if Secrets Manager is unavailable. The AWS
provider can continue using a previously loaded credential during a temporary
network/service outage because Portal still validates its state. IAM denial, a
deleted secret, malformed `AWSCURRENT`, local configuration errors, and a
caller credential-discovery deadline are hard failures and never activate
`allowOfflineAdmin`, even when a stale value was previously loaded. Once
`AWSCURRENT` has parsed successfully, a separate `AWSPENDING` read or parse
failure is logged without secret material and current remains usable.
Background synthetic-proof discovery failures are also emitted as structured,
sanitized warnings; the expected pre-registration `401` race remains quiet.
Remove the shared key only after that session drain and Portal telemetry's clean
48-hour window.

## Revalidation concurrency

In the default cached mode, simultaneous stale requests for the same session share one Portal context call
inside each connector process. The in-flight entry is removed after success or
failure, so a later request can retry normally.

### Request authority (unreleased, issue #8)

HR must use `authorityMode: "request"` with either `createPortalAuth` or
`createPortalAuthAsync`. Mount `requireAuth` on every protected view, download,
and mutation. Each invocation, including `requireAdmin` and `revalidateIfStale`,
performs a new Portal lookup. `revalidateMs: 0` alone does not provide this
guarantee: cached mode still shares in-flight lookups.

Request mode requires the complete current `roles`, `app_permissions`, and
canonical location fields. It requires an explicit app grant even for ops,
refuses offline/dev fallback, and never persists refreshed context snapshots.
This prevents a late response from overwriting newer access state. An inactive
or revoked reply deletes the local session; an older active response cannot
admit a session that has since disappeared. The context attached to the request
is that request's authority result. `getContext(req)`, `locationIds(req)`, and
`locationKeys(req)` read that result (`req.portal`) even when other middleware
has set `req.context`. Calls that began before a Portal change are
not a substitute for a new authorization check after that change.

Request mode draws on a Portal rate limit that other apps may share. The Portal's
app-to-app routes (`POST /api/redeem-sso`, `POST /api/context`,
`POST /api/credential-proof`, and `GET /api/app-directory`) share one limit of 60
requests per one-minute window. The limit is counted per source address, before
authentication, in a PostgreSQL store that every Portal instance shares. Request
mode makes one `POST /api/context` for every protected request, so the 61st
protected request in a minute gets a Portal `429`, which the connector returns
as a `503`. Cached mode makes at most one call per session per `revalidateMs`,
and simultaneous requests in one process share that call. Render services in the same region
share outbound address ranges, so sign-ins, re-checks, credential proofs, and
directory reads from other apps may count against the same 60. Confirm this
capacity before any request-mode pilot. The Portal-side finding is STAB-17 in
mattjohnny/mule-fleet-docs `audits/stability/portal-2026-10-25-608b090.md`.

`Context.role`, `Session.role`, and `is_admin` retain their primary-role meaning.
`roles` includes that primary role first and validated additional roles;
`app_permissions` is a sparse map of app keys to permission lists. A missing app
key or empty list grants no permission. Apps apply their domain policy using
these facts and exact canonical locations. The connector adds no HR policy.

`finance` is the only additional role the connector accepts. Any other
additional role makes a context or directory entry malformed, in cached mode as
well as request mode. That person's sign-in fails. Once their session is due for
a re-check, every protected request they make is refused. Any directory read
that includes them fails as a whole. Before the Portal starts emitting a new
additional role, release a connector that accepts it and have every consuming
app adopt that release.

The new fields are optional in the TypeScript interface so older scalar
consumers still compile. In cached mode only, a live Portal response that lacks
them is normalized to `roles: [role]` and `app_permissions: {}`. Present
malformed claims always fail validation. That normalization applies only to a
response the connector has just validated. A context read back from the session
store is not normalized. Sessions from `devSignIn` and offline-admin sign-in
start without these fields. A session stored by v0.2.4 or earlier may also lack
them. Each of these sessions gets the fields at its next successful re-check. A
dev session with no Portal configured is never re-checked, so it never gets
them. In cached mode, read an absent `roles` as `[role]` and an absent
`app_permissions` as granting nothing. Default cached-mode timing,
coalescing, and explicit outage behavior remain unchanged.

#### Boot checks, dev sign-in, expiry, back-off and directory errors

Both factories expose the validated mode as read-only `auth.authorityMode`
(`"cached"` or `"request"`, type `PortalAuthorityMode`). An app that depends on
request authority, such as HR, should check at boot that it reads `"request"`
and refuse to start if it does not. In request mode, `devSignIn` throws a
`PortalError` and creates no session. A session created with a revalidation
handle expires after `min(sessionTtlMs, 8 h)`, the Portal's handle lifetime. An
expired handle's `401` looks the same as a bad app credential, so the session
must not outlive its handle. Sessions without a handle keep `sessionTtlMs`
(default 8 h). When a context lookup gets a `429` or `503` with a whole-seconds
`Retry-After`, `requireAuth` and `requireAdmin` send it on their `503`, clamped
to 1–300 seconds. Any other value, or none, gives 5. A `429` is still not an
outage, and the connector never retries. A refused `readAppDirectory()` still
fails as a whole. Its `PortalError.detail` names only the failed check and its
position, such as `people[3].email` or `syncedAt skew`, so it is safe to log.

`readAppDirectory({ include_non_mule: true })` returns `PortalAppDirectory`:
`syncedAt`, canonical `locations` (including required boolean `is_mule`), and
`people` with `role`, `roles`, `permissions`, `status`, `locations`,
`ctx_version`, and `last_login`. Non-Mule catalogue and person locations require
the explicit option. Disabled people may remain in the directory: callers must
check `status` before selecting an eligible processor or recipient.

Every directory call fetches afresh with `cache: "no-store"`; transport failure,
missing fields, duplicate/contradictory identities or locations, and timestamps
outside a 30-second clock-skew window are rejected. No saved directory is used
as a fallback. The timestamp is a sanity check, not a permission lease: fetch
again before a later eligibility decision. `getContext` reads an already
resolved snapshot and does not itself revalidate.

This change requires the matching Portal roles/permissions and directory
contract for Portal issues #92 and #93. That Portal change is
mattjohnny/mule-portal#112: head `856fd566b8f2d9e8fd7645849b39169752d5f1f0`,
merged as `638bfeffb251831b2a5efad2be87e64880d27bf7`, and in production since
2026-10-25. The
[local verification summary](docs/evidence/authority-2026-10-25/README.md)
names two Portal commits that were never published and a `dist/index.js`
fingerprint that does not match the merged file. Its
[erratum](docs/evidence/authority-2026-10-25/ERRATUM-2026-10-26.md) gives the
corrections and the re-verification on the merged bytes.
Release tagging and consumer pins remain separate gates; the package version
is still `0.2.4`. Follow
[`docs/release/v0.3.0-preflight.md`](docs/release/v0.3.0-preflight.md) before
tagging.

An async store shared by multiple service instances can additionally implement:

```ts
withRevalidationLock<T>(
  token: string,
  callback: () => Promise<T>
): Promise<T>
```

The store must hold a per-token distributed lease while `callback` runs and
release it whether the callback resolves or rejects. Bound lock acquisition so
a stuck peer fails closed rather than waiting forever. The callback calls the
same store's `get`, `updateContext`, or `delete` methods; those operations must
remain safe while the lease is held by reusing its database connection or by
not monopolizing a connection they need. The connector reads the session again
inside that lease, so a second instance observes the first instance's successful
validation instead of repeating it. Fresh sessions do not acquire the
distributed lease. Without this optional hook, coalescing is process-local:
overlapping instances can each make one Portal call for the same stale session.

## Portal outages fail closed

By default, if the Portal cannot be reached during a due re-check, the protected
request is rejected with a retryable `503`. The local session is kept, its
validation time is not advanced, and the next request tries again. This prevents
stale access from surviving an outage while allowing service to resume without
another login once the Portal can confirm the person. `allowOfflineAdmin` is the
explicit exception for matching `ADMIN_EMAILS` users during a configured Portal
outage; missing Portal configuration still denies access. Sessions created by a
pre-provenance release, including `portal`/`google` rows from v0.2.1 and sessions
written by an older binary after a rollback, are forced through one successful
Portal re-check before they can use that exception. The successful check marks
the row `portal-v2`. Async stores that persist the optional source marker pay
that forced re-check once; a store that ignores it remains safe by rechecking
until expiry. Labour Live's companion `agent/portal-credential-rotation` branch
persists the marker; follow the v0.2.2 release gates above before the fleet bump.
A Portal response that
marks the person inactive, or removes this app from their grants, destroys the
session. A successful Portal response always controls role, admin status,
locations, and app grants; `ADMIN_EMAILS` never elevates it. Only Portal
network/timeouts, retryable `408`/`425`, and selected `5xx` responses qualify as
an outage. Credential-provider, AWS IAM, secret configuration/content, and
caller credential-discovery deadline failures are local hard failures. `429`
throttling, authentication failures, and malformed Portal responses also remain
fail-closed even when `allowOfflineAdmin` is enabled.
