# @mule/portal-auth

The shared identity client every Mule app uses to talk to **The Mule Portal**.
It replaces the copied-and-drifting `auth.ts` that each app used to hand-roll.

One module does three things (see `mule-portal/docs/identity-and-access.md` §8):

1. **Sign in** — trade the Portal's one-click SSO token for a local session, or
   verify a direct Google sign-in and pull the person's context from the Portal.
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
  "@mule/portal-auth": "github:mattjohnny/mule-portal-auth#v0.1.0"
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
| `signInWithGoogle(idToken)` | Verify Google, pull context from the Portal, start a session (direct-door apps) |
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
| `adminEmails` | `ADMIN_EMAILS` env | Bootstrap admins that work even if the Portal is unreachable (§10) |

## Fail-open on Portal blips

If the Portal is briefly unreachable during a re-check, the connector keeps
serving the cached context and retries next request — the short session TTL is
the backstop. A person is only signed out when the Portal *explicitly* says they
are inactive.
