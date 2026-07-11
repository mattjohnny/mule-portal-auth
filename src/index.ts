import crypto from "node:crypto";
import type { Response, NextFunction } from "express";
import type {
  Context,
  PortalAuthConfig,
  PortalAuthedRequest,
  PortalLocation,
  Session,
} from "./types.js";
import { PortalError, fetchContext, redeemSso, type PortalClientOpts } from "./portal.js";

export type {
  Context,
  PortalLocation,
  Session,
  PortalAuthConfig,
  PortalAuthedRequest,
} from "./types.js";
export { PortalError } from "./portal.js";

const DEFAULT_TTL_MS = 8 * 60 * 60 * 1000; // 8h fallback session TTL (§7)
const DEFAULT_REVALIDATE_MS = 5 * 60 * 1000; // re-check the Portal at most every 5 min (§7 R1)

// Build one app's Portal connector. Adds a single `portal_sessions` table to the
// app's own database and returns the sign-in helpers + Express middleware every
// Mule app shares (identity-and-access.md §8). Retire the app's copied auth.ts
// role/location logic and read from the context this exposes instead.
export function createPortalAuth(config: PortalAuthConfig) {
  const db = config.db;
  const appName = config.appName;
  const portalUrl = (config.portalUrl ?? process.env.PORTAL_URL ?? "").trim().replace(/\/$/, "");
  const sharedKey = (config.sharedKey ?? process.env.PORTAL_SHARED_KEY ?? "").trim();
  const googleClientId = (config.googleClientId ?? process.env.GOOGLE_CLIENT_ID ?? "").trim();
  const allowedDomains = (config.allowedDomains ?? envList("ALLOWED_DOMAINS")).map((d) =>
    d.toLowerCase()
  );
  const adminEmails = new Set(
    (config.adminEmails ?? envList("ADMIN_EMAILS")).map((e) => e.toLowerCase())
  );
  const sessionTtlMs = config.sessionTtlMs ?? DEFAULT_TTL_MS;
  const revalidateMs = config.revalidateMs ?? DEFAULT_REVALIDATE_MS;
  const portal: PortalClientOpts = { portalUrl, sharedKey, appName };

  db.exec(`
    CREATE TABLE IF NOT EXISTS portal_sessions (
      token          TEXT PRIMARY KEY,
      email          TEXT NOT NULL,
      name           TEXT NOT NULL DEFAULT '',
      context        TEXT NOT NULL,          -- JSON snapshot of the Portal context
      created_at     INTEGER NOT NULL,
      expires_at     INTEGER NOT NULL,       -- epoch ms; the 8h fallback TTL
      last_validated INTEGER NOT NULL        -- epoch ms of the last Portal re-check
    );
  `);

  // --- Local session store --------------------------------------------------
  function startLocalSession(ctx: Context): Session {
    const token = crypto.randomBytes(32).toString("hex");
    const now = Date.now();
    db.prepare(
      `INSERT INTO portal_sessions (token, email, name, context, created_at, expires_at, last_validated)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(token, ctx.email, ctx.name, JSON.stringify(ctx), now, now + sessionTtlMs, now);
    return { token, email: ctx.email, name: ctx.name, role: ctx.role, context: ctx };
  }

  function rowToSession(row: {
    token: string;
    email: string;
    name: string;
    context: string;
  }): Session {
    const ctx = JSON.parse(row.context) as Context;
    return { token: row.token, email: row.email, name: row.name, role: ctx.role, context: ctx };
  }

  function getRow(token: string) {
    const row = db
      .prepare(
        "SELECT token, email, name, context, expires_at, last_validated FROM portal_sessions WHERE token = ?"
      )
      .get(token) as
      | {
          token: string;
          email: string;
          name: string;
          context: string;
          expires_at: number;
          last_validated: number;
        }
      | undefined;
    if (!row) return null;
    if (Date.now() > row.expires_at) {
      db.prepare("DELETE FROM portal_sessions WHERE token = ?").run(token);
      return null;
    }
    return row;
  }

  function destroy(token: string): void {
    db.prepare("DELETE FROM portal_sessions WHERE token = ?").run(token);
  }

  function saveContext(token: string, ctx: Context): void {
    db.prepare(
      "UPDATE portal_sessions SET context = ?, name = ?, last_validated = ? WHERE token = ?"
    ).run(JSON.stringify(ctx), ctx.name, Date.now(), token);
  }

  // Housekeeping: drop expired sessions so the table stays small.
  function sweep(): void {
    try {
      db.prepare("DELETE FROM portal_sessions WHERE expires_at < ?").run(Date.now());
    } catch {
      /* ignore */
    }
  }
  sweep();
  const sweepTimer = setInterval(sweep, 6 * 60 * 60 * 1000);
  sweepTimer.unref?.();

  // --- Sign in --------------------------------------------------------------
  // The Portal one-click handoff: trade the single-use SSO token for a local
  // session carrying the full context.
  async function signInWithPortalToken(ssoToken: string): Promise<Session> {
    if (!portalUrl || !sharedKey)
      throw new PortalError("Portal sign-in isn't configured (missing PORTAL_URL / shared key).");
    if (!ssoToken) throw new PortalError("Missing sign-in token.");
    const { context } = await redeemSso(portal, ssoToken);
    return startLocalSession(applyBootstrapAdmin(context));
  }

  // Direct Google sign-in for apps that keep their own door. Verifies the Google
  // token locally, then pulls the person's context from the Portal so role /
  // locations are always Portal-sourced (§10). Refuses anyone the Portal doesn't
  // grant this app (bootstrap admins always pass).
  async function signInWithGoogle(idToken: string): Promise<Session> {
    if (!googleClientId) throw new PortalError("Google sign-in isn't configured.");
    if (!idToken) throw new PortalError("No sign-in token was received.");

    const { OAuth2Client } = await import("google-auth-library");
    const client = new OAuth2Client(googleClientId);
    let email = "";
    let name = "";
    try {
      const ticket = await client.verifyIdToken({ idToken, audience: googleClientId });
      const payload = ticket.getPayload();
      if (!payload?.email) throw new Error("no email");
      if (!payload.email_verified) throw new PortalError("That Google account's email isn't verified.");
      email = payload.email.toLowerCase();
      name = payload.name || payload.given_name || email;
    } catch (e) {
      if (e instanceof PortalError) throw e;
      throw new PortalError("We couldn't verify that Google sign-in. Please try again.");
    }

    if (allowedDomains.length && !allowedDomains.includes(domainOf(email)))
      throw new PortalError("That account isn't on an approved company domain.");

    // Bootstrap admin: works even if the Portal is unreachable (§10).
    if (adminEmails.has(email)) return startLocalSession(bootstrapAdminContext(email, name));

    let ctx: Context | null;
    try {
      ctx = await fetchContext(portal, email);
    } catch {
      throw new PortalError("Couldn't reach the Portal to confirm your access. Please try again.");
    }
    if (!ctx) throw new PortalError("You don't have access to this app yet. Ask an admin in the Mule Portal.");
    if (!ctx.is_admin && !ctx.apps.includes(appName))
      throw new PortalError("You haven't been given access to this app yet. Ask an admin in the Mule Portal.");
    return startLocalSession(ctx);
  }

  function logout(token: string): void {
    if (token) destroy(token);
  }

  // Dev-only sign-in for running an app locally without Google / the Portal.
  // Starts a local admin (ops) session. Callers MUST gate this on !isConfigured()
  // so it is dead in production (where GOOGLE_CLIENT_ID is always set).
  function devSignIn(email: string, name = "Dev Admin"): Session {
    return startLocalSession(bootstrapAdminContext(email.toLowerCase(), name));
  }

  // --- Revalidation (§7 R1) -------------------------------------------------
  // Re-check a live session against the Portal, but at most once per revalidateMs.
  // Returns the (possibly refreshed) session, or null if the person is now signed
  // out. A Portal network blip fails OPEN — we keep serving the cached context and
  // retry next request, with the short session TTL as the backstop.
  async function revalidateIfStale(session: Session): Promise<Session | null> {
    const row = getRow(session.token);
    if (!row) return null; // expired / gone
    if (Date.now() - row.last_validated < revalidateMs) return rowToSession(row);

    // Bootstrap admins are never signed out by revalidation (§10) — but do refresh
    // their context if the Portal answers.
    let ctx: Context | null;
    try {
      ctx = await fetchContext(portal, session.email);
    } catch {
      return rowToSession(row); // fail open; try again next request
    }
    if (!ctx) {
      if (adminEmails.has(session.email)) return rowToSession(row);
      destroy(session.token);
      return null;
    }
    saveContext(session.token, ctx);
    return { token: session.token, email: ctx.email, name: ctx.name, role: ctx.role, context: ctx };
  }

  // --- Express middleware ---------------------------------------------------
  function requireAuth(req: PortalAuthedRequest, res: Response, next: NextFunction): void {
    const token = bearer(req);
    const row = token ? getRow(token) : null;
    if (!row) {
      res.status(401).json({ error: "Not signed in." });
      return;
    }
    // Re-check with the Portal if this session is due (revoke-now, §7).
    revalidateIfStale(rowToSession(row))
      .then((session) => {
        if (!session) {
          res.status(401).json({ error: "Your access has been updated. Please sign in again." });
          return;
        }
        req.portal = session;
        next();
      })
      .catch(() => {
        // Should not happen (revalidate fails open), but never wedge a request.
        req.portal = rowToSession(row);
        next();
      });
  }

  function requireAdmin(req: PortalAuthedRequest, res: Response, next: NextFunction): void {
    requireAuth(req, res, () => {
      if (!req.portal?.context.is_admin) {
        res.status(403).json({ error: "Admins only." });
        return;
      }
      next();
    });
  }

  // --- Reads for the app ----------------------------------------------------
  // The location ids this person may see, or "all" for ops. Apps scope every
  // read/write to this set, server-side (§6).
  function locationIds(src: Session | Context | PortalAuthedRequest): number[] | "all" {
    const ctx = toContext(src);
    if (!ctx) return [];
    if (ctx.locations === "all") return "all";
    return ctx.locations.map((l) => l.id);
  }

  // The location KEYS this person may see, or "all" for ops. Prefer this over
  // locationIds when the app's own locations table is keyed by name (burlington,
  // cambridge, …) — the Portal's numeric ids won't match the app's.
  function locationKeys(src: Session | Context | PortalAuthedRequest): string[] | "all" {
    const ctx = toContext(src);
    if (!ctx) return [];
    if (ctx.locations === "all") return "all";
    return ctx.locations.map((l) => l.key);
  }

  function getContext(src: Session | PortalAuthedRequest): Context | null {
    return toContext(src);
  }

  return {
    signInWithPortalToken,
    signInWithGoogle,
    devSignIn,
    logout,
    requireAuth,
    requireAdmin,
    revalidateIfStale,
    getContext,
    locationIds,
    locationKeys,
    isConfigured: () => !!portalUrl && !!sharedKey,
    isAdminEmail: (email: string) => adminEmails.has((email || "").toLowerCase()),
  };

  // --- helpers --------------------------------------------------------------
  // If a person comes back as ops from the Portal, keep is_admin true; if the app
  // has them as a bootstrap admin, honour that regardless of the Portal answer.
  function applyBootstrapAdmin(ctx: Context): Context {
    if (adminEmails.has(ctx.email) && !ctx.is_admin) {
      return { ...ctx, role: "ops", is_admin: true, locations: "all" };
    }
    return ctx;
  }
}

// --- module-level helpers ---------------------------------------------------
function bearer(req: PortalAuthedRequest): string | null {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}

function domainOf(email: string): string {
  return (email.split("@")[1] || "").toLowerCase();
}

function envList(name: string): string[] {
  return (process.env[name] || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function bootstrapAdminContext(email: string, name: string): Context {
  return {
    email,
    name: name || email,
    role: "ops",
    is_admin: true,
    status: "active",
    locations: "all",
    apps: [],
    ctx_version: 0,
    active: true,
  };
}

function toContext(src: Session | Context | PortalAuthedRequest | null | undefined): Context | null {
  if (!src) return null;
  if ("context" in src && src.context) return src.context as Context; // Session
  if ("portal" in src && (src as PortalAuthedRequest).portal)
    return (src as PortalAuthedRequest).portal!.context; // request
  if ("role" in src && "is_admin" in src) return src as Context; // already a Context
  return null;
}
