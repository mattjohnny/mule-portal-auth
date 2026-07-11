import type { Request } from "express";

// A canonical location as the Portal hands it to us (identity-and-access.md §5).
export interface PortalLocation {
  id: number;
  key: string;
  name: string;
}

// The identity "profile card" the Portal is the source of truth for. Every app
// receives this instead of re-deriving role / location itself. `locations` is a
// SET (or the string "all" for ops), because a franchisee owns several and ops
// sees every location (§3, §4).
export interface Context {
  email: string;
  name: string;
  role: string; // ops | franchisee | gm | manager | chef
  is_admin: boolean; // role === 'ops'
  status: string; // active | disabled
  locations: PortalLocation[] | "all";
  apps: string[]; // effective app keys this person may open
  ctx_version: number; // bumped by the Portal on any change (§7)
  active: boolean; // false = disabled / removed / off-domain → sign out
}

// A live local session in the consuming app. The app keeps its own sessions
// (login stickiness); only the identity facts inside `context` come from the
// Portal. `token` is the bearer the browser sends back on every request.
export interface Session {
  token: string;
  email: string;
  name: string;
  role: string;
  context: Context;
}

// requireAuth attaches the resolved session (and its context) to the request.
export interface PortalAuthedRequest extends Request {
  portal?: Session;
}

// Config for one app's connector. Everything but `db` + `appName` has a sane
// default or comes from the environment.
export interface PortalAuthConfig {
  // The app's own better-sqlite3 database (the connector adds one small table).
  db: import("better-sqlite3").Database;
  // This app's key in the Portal, e.g. "training-days" — used when redeeming
  // SSO tokens and asking the Portal about a person.
  appName: string;
  // Base URL of the Portal, e.g. https://mule-portal.onrender.com (no trailing /).
  portalUrl?: string;
  // The shared service key both sides hold (PORTAL_SHARED_KEY).
  sharedKey?: string;
  // For apps that also allow a direct Google sign-in (not just Portal handoff).
  googleClientId?: string;
  // Approved company domains for direct Google sign-in (e.g. ["themule.ca"]).
  allowedDomains?: string[];
  // Local emails that are always admins even if the Portal is unreachable — the
  // bootstrap admin (§10). Keep at least one.
  adminEmails?: string[];
  // How long a local session lives before it must be re-established (the §7
  // fallback TTL). Default 8h.
  sessionTtlMs?: number;
  // How often, at most, to re-check a live session against the Portal (§7 R1).
  // Default 5 minutes.
  revalidateMs?: number;
}
