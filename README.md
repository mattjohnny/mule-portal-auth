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

## Use

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
outage because Portal still validates its state. Remove the shared key only
after that session drain and Portal telemetry's clean 48-hour window.

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
the row `portal-v2`; known async stores persist the same marker, while an older
store that ignores the optional marker remains safe by rechecking until expiry.
A Portal response that
marks the person inactive, or removes this app from their grants, destroys the
session. A successful Portal response always controls role, admin status,
locations, and app grants; `ADMIN_EMAILS` never elevates it. Only
network/timeouts, retryable `408`/`425`, and selected `5xx`
responses qualify as an outage. `429` throttling, authentication failures, and
malformed Portal responses remain fail-closed even when `allowOfflineAdmin` is enabled.
