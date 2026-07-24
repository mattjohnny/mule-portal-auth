import crypto from "node:crypto";
import { PortalError, fetchContext, redeemSso } from "./portal.js";
export { PortalError } from "./portal.js";
const DEFAULT_TTL_MS = 8 * 60 * 60 * 1000; // 8h fallback session TTL (§7)
const DEFAULT_REVALIDATE_MS = 5 * 60 * 1000; // re-check the Portal at most every 5 min (§7 R1)
const DEFAULT_PORTAL_TIMEOUT_MS = 5_000;
// Build one app's Portal connector. Adds a single `portal_sessions` table to the
// app's own database and returns the sign-in helpers + Express middleware every
// Mule app shares (identity-and-access.md §8). Retire the app's copied auth.ts
// role/location logic and read from the context this exposes instead.
export function createPortalAuth(config) {
    const db = config.db;
    const appName = config.appName;
    const portalUrl = (config.portalUrl ?? process.env.PORTAL_URL ?? "").trim().replace(/\/$/, "");
    const sharedKey = (config.sharedKey ?? process.env.PORTAL_SHARED_KEY ?? "").trim();
    const googleClientId = (config.googleClientId ?? process.env.GOOGLE_CLIENT_ID ?? "").trim();
    const allowedDomains = (config.allowedDomains ?? envList("ALLOWED_DOMAINS")).map((d) => d.toLowerCase());
    const adminEmails = new Set((config.adminEmails ?? envList("ADMIN_EMAILS")).map((e) => e.toLowerCase()));
    const sessionTtlMs = config.sessionTtlMs ?? DEFAULT_TTL_MS;
    const revalidateMs = config.revalidateMs ?? DEFAULT_REVALIDATE_MS;
    const requestTimeoutMs = config.portalRequestTimeoutMs ?? DEFAULT_PORTAL_TIMEOUT_MS;
    const allowOfflineAdmin = config.allowOfflineAdmin ?? false;
    const portal = { portalUrl, sharedKey, appName, requestTimeoutMs };
    db.exec(`
    CREATE TABLE IF NOT EXISTS portal_sessions (
      token          TEXT PRIMARY KEY,
      email          TEXT NOT NULL,
      name           TEXT NOT NULL DEFAULT '',
      context        TEXT NOT NULL,          -- JSON snapshot of the Portal context
      created_at     INTEGER NOT NULL,
      expires_at     INTEGER NOT NULL,       -- epoch ms; the 8h fallback TTL
      last_validated INTEGER NOT NULL,       -- epoch ms of the last Portal re-check
      source         TEXT NOT NULL DEFAULT 'legacy' -- explicit writers use portal | google | offline-admin | dev
    );
  `);
    const sessionColumns = db.prepare("PRAGMA table_info(portal_sessions)").all();
    if (!sessionColumns.some((column) => column.name === "source"))
        // Old releases could create Portal, Google, offline bootstrap-admin, or dev
        // sessions, so their provenance is unknowable. Mark them legacy and force a
        // real Portal recheck before they can use cached/offline-admin trust.
        db.exec("ALTER TABLE portal_sessions ADD COLUMN source TEXT NOT NULL DEFAULT 'legacy'");
    // --- Local session store --------------------------------------------------
    function startLocalSession(ctx, source = "portal") {
        const token = crypto.randomBytes(32).toString("hex");
        const now = Date.now();
        db.prepare(`INSERT INTO portal_sessions (token, email, name, context, created_at, expires_at, last_validated, source)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(token, ctx.email, ctx.name, JSON.stringify(ctx), now, now + sessionTtlMs, now, source);
        return { token, email: ctx.email, name: ctx.name, role: ctx.role, context: ctx };
    }
    function rowToSession(row) {
        const ctx = JSON.parse(row.context);
        return { token: row.token, email: row.email, name: row.name, role: ctx.role, context: ctx };
    }
    function getRow(token) {
        const row = db
            .prepare("SELECT token, email, name, context, expires_at, last_validated, source FROM portal_sessions WHERE token = ?")
            .get(token);
        if (!row)
            return null;
        if (Date.now() > row.expires_at) {
            db.prepare("DELETE FROM portal_sessions WHERE token = ?").run(token);
            return null;
        }
        return row;
    }
    function destroy(token) {
        db.prepare("DELETE FROM portal_sessions WHERE token = ?").run(token);
    }
    function saveContext(token, ctx) {
        db.prepare(`UPDATE portal_sessions
       SET context = ?, name = ?, last_validated = ?,
           source = CASE WHEN source = 'legacy' THEN 'portal' ELSE source END
       WHERE token = ?`).run(JSON.stringify(ctx), ctx.name, Date.now(), token);
    }
    // Housekeeping: drop expired sessions so the table stays small.
    function sweep() {
        try {
            db.prepare("DELETE FROM portal_sessions WHERE expires_at < ?").run(Date.now());
        }
        catch {
            /* ignore */
        }
    }
    sweep();
    const sweepTimer = setInterval(sweep, 6 * 60 * 60 * 1000);
    sweepTimer.unref?.();
    // --- Sign in --------------------------------------------------------------
    // The Portal one-click handoff: trade the single-use SSO token for a local
    // session carrying the full context.
    async function signInWithPortalToken(ssoToken) {
        if (!portalUrl || !sharedKey)
            throw new PortalError("Portal sign-in isn't configured (missing PORTAL_URL / shared key).");
        if (!ssoToken)
            throw new PortalError("Missing sign-in token.");
        const { context } = await redeemSso(portal, ssoToken);
        const effective = applyBootstrapAdmin(context);
        if (!effective.active || (!effective.is_admin && !effective.apps.includes(appName)))
            throw new PortalError("You no longer have access to this app.", true);
        return startLocalSession(effective, "portal");
    }
    // Direct Google sign-in for apps that keep their own door. Verifies the Google
    // token locally, then pulls the person's context from the Portal so role /
    // locations are always Portal-sourced (§10). Refuses anyone the Portal doesn't
    // grant this app (bootstrap admins always pass).
    async function signInWithGoogle(idToken) {
        if (!googleClientId)
            throw new PortalError("Google sign-in isn't configured.");
        if (!idToken)
            throw new PortalError("No sign-in token was received.");
        // Offline-admin is outage-only break glass, not a substitute for deploying
        // the connector's Portal URL and key correctly.
        if (!portalUrl || !sharedKey)
            throw new PortalError("Portal access verification isn't configured.");
        const { OAuth2Client } = await import("google-auth-library");
        const client = new OAuth2Client(googleClientId);
        let email = "";
        let name = "";
        try {
            const ticket = await client.verifyIdToken({ idToken, audience: googleClientId });
            const payload = ticket.getPayload();
            if (!payload?.email)
                throw new Error("no email");
            if (!payload.email_verified)
                throw new PortalError("That Google account's email isn't verified.");
            email = payload.email.toLowerCase();
            name = payload.name || payload.given_name || email;
        }
        catch (e) {
            if (e instanceof PortalError)
                throw e;
            throw new PortalError("We couldn't verify that Google sign-in. Please try again.");
        }
        if (allowedDomains.length && !allowedDomains.includes(domainOf(email)))
            throw new PortalError("That account isn't on an approved company domain.");
        let ctx;
        try {
            ctx = await fetchContext(portal, email);
        }
        catch (error) {
            if (allowOfflineAdmin &&
                adminEmails.has(email) &&
                error instanceof PortalError &&
                error.unavailable) {
                return startLocalSession(bootstrapAdminContext(email, name), "offline-admin");
            }
            throw new PortalError("Couldn't reach the Portal to confirm your access. Please try again.");
        }
        if (!ctx)
            throw new PortalError("You don't have access to this app yet. Ask an admin in the Mule Portal.");
        const effective = applyBootstrapAdmin(ctx);
        if (!effective.is_admin && !effective.apps.includes(appName))
            throw new PortalError("You haven't been given access to this app yet. Ask an admin in the Mule Portal.");
        return startLocalSession(effective, "google");
    }
    function logout(token) {
        if (token)
            destroy(token);
    }
    // Dev-only sign-in for running an app locally without Google / the Portal.
    // Starts a local admin (ops) session. Callers MUST gate this on an explicit
    // non-production check as well as !isConfigured() so it is dead in production.
    function devSignIn(email, name = "Dev Admin") {
        return startLocalSession(bootstrapAdminContext(email.toLowerCase(), name), "dev");
    }
    // --- Revalidation (§7 R1) -------------------------------------------------
    // Re-check a live session against the Portal, but at most once per revalidateMs.
    // Returns the (possibly refreshed) session, or null if the person is now signed
    // out. An unavailable Portal throws: requireAuth denies that request with 503,
    // keeps the local row, and retries on the next request without extending trust.
    async function revalidateIfStale(session) {
        const row = getRow(session.token);
        if (!row)
            return null; // expired / gone
        // Legacy rows have no trustworthy validation provenance. Even if their old
        // timestamp is recent, make the first request after upgrade prove access.
        if (row.source !== "legacy" && Date.now() - row.last_validated < revalidateMs)
            return rowToSession(row);
        if (!portalUrl || !sharedKey) {
            // Only an explicitly created dev session may run without Portal config.
            // Existing production rows migrate with source='legacy' and deny.
            if (row.source === "dev")
                return rowToSession(row);
            throw new PortalError("Portal access verification isn't configured.");
        }
        let ctx;
        try {
            ctx = await fetchContext(portal, session.email);
        }
        catch (error) {
            if (allowOfflineAdmin &&
                adminEmails.has(session.email) &&
                row.source !== "legacy" &&
                error instanceof PortalError &&
                error.unavailable)
                return rowToSession(row);
            throw error;
        }
        if (!ctx) {
            destroy(session.token);
            return null;
        }
        const effective = applyBootstrapAdmin(ctx);
        if (!effective.is_admin && !effective.apps.includes(appName)) {
            destroy(session.token);
            return null;
        }
        saveContext(session.token, effective);
        return {
            token: session.token,
            email: effective.email,
            name: effective.name,
            role: effective.role,
            context: effective,
        };
    }
    // --- Express middleware ---------------------------------------------------
    function requireAuth(req, res, next) {
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
            res.setHeader("Cache-Control", "no-store");
            res.setHeader("Retry-After", "5");
            res.status(503).json({
                error: "We can't confirm your access with the Mule Portal right now. Please try again.",
            });
        });
    }
    function requireAdmin(req, res, next) {
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
    function locationIds(src) {
        const ctx = toContext(src);
        if (!ctx)
            return [];
        if (ctx.locations === "all")
            return "all";
        return ctx.locations.map((l) => l.id);
    }
    // The location KEYS this person may see, or "all" for ops. Prefer this over
    // locationIds when the app's own locations table is keyed by name (burlington,
    // cambridge, …) — the Portal's numeric ids won't match the app's.
    function locationKeys(src) {
        const ctx = toContext(src);
        if (!ctx)
            return [];
        if (ctx.locations === "all")
            return "all";
        return ctx.locations.map((l) => l.key);
    }
    function getContext(src) {
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
        isAdminEmail: (email) => adminEmails.has((email || "").toLowerCase()),
    };
    // --- helpers --------------------------------------------------------------
    // If a person comes back as ops from the Portal, keep is_admin true; if the app
    // has them as a bootstrap admin, honour that regardless of the Portal answer.
    function applyBootstrapAdmin(ctx) {
        if (adminEmails.has(ctx.email) && !ctx.is_admin) {
            return { ...ctx, role: "ops", is_admin: true, locations: "all" };
        }
        return ctx;
    }
}
// Async variant for stateless services whose sessions live in a shared
// database. The synchronous SQLite connector above remains unchanged so
// existing Mule apps do not need to migrate until they are ready.
export function createPortalAuthAsync(config) {
    const store = config.sessionStore;
    const appName = config.appName;
    const portalUrl = (config.portalUrl ?? process.env.PORTAL_URL ?? "").trim().replace(/\/$/, "");
    const sharedKey = (config.sharedKey ?? process.env.PORTAL_SHARED_KEY ?? "").trim();
    const googleClientId = (config.googleClientId ?? process.env.GOOGLE_CLIENT_ID ?? "").trim();
    const allowedDomains = (config.allowedDomains ?? envList("ALLOWED_DOMAINS")).map((d) => d.toLowerCase());
    const adminEmails = new Set((config.adminEmails ?? envList("ADMIN_EMAILS")).map((e) => e.toLowerCase()));
    const sessionTtlMs = config.sessionTtlMs ?? DEFAULT_TTL_MS;
    const revalidateMs = config.revalidateMs ?? DEFAULT_REVALIDATE_MS;
    const requestTimeoutMs = config.portalRequestTimeoutMs ?? DEFAULT_PORTAL_TIMEOUT_MS;
    const allowOfflineAdmin = config.allowOfflineAdmin ?? false;
    const portal = { portalUrl, sharedKey, appName, requestTimeoutMs };
    const ready = store.init();
    async function startLocalSession(ctx, source = "portal") {
        await ready;
        const token = crypto.randomBytes(32).toString("hex");
        const now = Date.now();
        await store.insert({
            token,
            email: ctx.email,
            name: ctx.name,
            context: JSON.stringify(ctx),
            created_at: now,
            expires_at: now + sessionTtlMs,
            last_validated: now,
            source,
        });
        return { token, email: ctx.email, name: ctx.name, role: ctx.role, context: ctx };
    }
    function rowToSession(row) {
        const ctx = JSON.parse(row.context);
        return { token: row.token, email: row.email, name: row.name, role: ctx.role, context: ctx };
    }
    async function getRow(token) {
        await ready;
        const row = await store.get(token);
        if (!row)
            return null;
        if (Date.now() > row.expires_at) {
            await store.delete(token);
            return null;
        }
        return row;
    }
    async function destroy(token) {
        await ready;
        await store.delete(token);
    }
    async function saveContext(token, ctx) {
        await ready;
        await store.updateContext(token, ctx, Date.now());
    }
    async function sweep() {
        try {
            await ready;
            await store.sweep(Date.now());
        }
        catch {
            /* ignore */
        }
    }
    void sweep();
    const sweepTimer = setInterval(() => void sweep(), 6 * 60 * 60 * 1000);
    sweepTimer.unref?.();
    async function signInWithPortalToken(ssoToken) {
        if (!portalUrl || !sharedKey)
            throw new PortalError("Portal sign-in isn't configured (missing PORTAL_URL / shared key).");
        if (!ssoToken)
            throw new PortalError("Missing sign-in token.");
        const { context } = await redeemSso(portal, ssoToken);
        const effective = applyBootstrapAdmin(context);
        if (!effective.active || (!effective.is_admin && !effective.apps.includes(appName)))
            throw new PortalError("You no longer have access to this app.", true);
        return startLocalSession(effective, "portal");
    }
    async function signInWithGoogle(idToken) {
        if (!googleClientId)
            throw new PortalError("Google sign-in isn't configured.");
        if (!idToken)
            throw new PortalError("No sign-in token was received.");
        if (!portalUrl || !sharedKey)
            throw new PortalError("Portal access verification isn't configured.");
        const { OAuth2Client } = await import("google-auth-library");
        const client = new OAuth2Client(googleClientId);
        let email = "";
        let name = "";
        try {
            const ticket = await client.verifyIdToken({ idToken, audience: googleClientId });
            const payload = ticket.getPayload();
            if (!payload?.email)
                throw new Error("no email");
            if (!payload.email_verified)
                throw new PortalError("That Google account's email isn't verified.");
            email = payload.email.toLowerCase();
            name = payload.name || payload.given_name || email;
        }
        catch (e) {
            if (e instanceof PortalError)
                throw e;
            throw new PortalError("We couldn't verify that Google sign-in. Please try again.");
        }
        if (allowedDomains.length && !allowedDomains.includes(domainOf(email)))
            throw new PortalError("That account isn't on an approved company domain.");
        let ctx;
        try {
            ctx = await fetchContext(portal, email);
        }
        catch (error) {
            if (allowOfflineAdmin &&
                adminEmails.has(email) &&
                error instanceof PortalError &&
                error.unavailable) {
                return startLocalSession(bootstrapAdminContext(email, name), "offline-admin");
            }
            throw new PortalError("Couldn't reach the Portal to confirm your access. Please try again.");
        }
        if (!ctx)
            throw new PortalError("You don't have access to this app yet. Ask an admin in the Mule Portal.");
        const effective = applyBootstrapAdmin(ctx);
        if (!effective.is_admin && !effective.apps.includes(appName))
            throw new PortalError("You haven't been given access to this app yet. Ask an admin in the Mule Portal.");
        return startLocalSession(effective, "google");
    }
    async function logout(token) {
        if (token)
            await destroy(token);
    }
    async function devSignIn(email, name = "Dev Admin") {
        return startLocalSession(bootstrapAdminContext(email.toLowerCase(), name), "dev");
    }
    async function revalidateIfStale(session) {
        const row = await getRow(session.token);
        if (!row)
            return null;
        if (row.source !== "legacy" && Date.now() - row.last_validated < revalidateMs)
            return rowToSession(row);
        if (!portalUrl || !sharedKey) {
            if (row.source === "dev")
                return rowToSession(row);
            throw new PortalError("Portal access verification isn't configured.");
        }
        let ctx;
        try {
            ctx = await fetchContext(portal, session.email);
        }
        catch (error) {
            if (allowOfflineAdmin &&
                adminEmails.has(session.email) &&
                row.source !== "legacy" &&
                error instanceof PortalError &&
                error.unavailable)
                return rowToSession(row);
            throw error;
        }
        if (!ctx) {
            await destroy(session.token);
            return null;
        }
        const effective = applyBootstrapAdmin(ctx);
        if (!effective.is_admin && !effective.apps.includes(appName)) {
            await destroy(session.token);
            return null;
        }
        await saveContext(session.token, effective);
        return {
            token: session.token,
            email: effective.email,
            name: effective.name,
            role: effective.role,
            context: effective,
        };
    }
    function requireAuth(req, res, next) {
        void (async () => {
            try {
                const token = bearer(req);
                const row = token ? await getRow(token) : null;
                if (!row) {
                    res.status(401).json({ error: "Not signed in." });
                    return;
                }
                const session = await revalidateIfStale(rowToSession(row));
                if (!session) {
                    res.status(401).json({ error: "Your access has been updated. Please sign in again." });
                    return;
                }
                req.portal = session;
                next();
            }
            catch {
                res.setHeader("Cache-Control", "no-store");
                res.setHeader("Retry-After", "5");
                res.status(503).json({
                    error: "We can't confirm your access with the Mule Portal right now. Please try again.",
                });
            }
        })();
    }
    function requireAdmin(req, res, next) {
        requireAuth(req, res, () => {
            if (!req.portal?.context.is_admin) {
                res.status(403).json({ error: "Admins only." });
                return;
            }
            next();
        });
    }
    function locationIds(src) {
        const ctx = toContext(src);
        if (!ctx)
            return [];
        if (ctx.locations === "all")
            return "all";
        return ctx.locations.map((l) => l.id);
    }
    function locationKeys(src) {
        const ctx = toContext(src);
        if (!ctx)
            return [];
        if (ctx.locations === "all")
            return "all";
        return ctx.locations.map((l) => l.key);
    }
    function getContext(src) {
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
        isAdminEmail: (email) => adminEmails.has((email || "").toLowerCase()),
    };
    function applyBootstrapAdmin(ctx) {
        if (adminEmails.has(ctx.email) && !ctx.is_admin) {
            return { ...ctx, role: "ops", is_admin: true, locations: "all" };
        }
        return ctx;
    }
}
// --- module-level helpers ---------------------------------------------------
function bearer(req) {
    const h = req.headers.authorization || "";
    return h.startsWith("Bearer ") ? h.slice(7) : null;
}
function domainOf(email) {
    return (email.split("@")[1] || "").toLowerCase();
}
function envList(name) {
    return (process.env[name] || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
}
function bootstrapAdminContext(email, name) {
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
function toContext(src) {
    if (!src)
        return null;
    if ("context" in src && src.context)
        return src.context; // Session
    if ("portal" in src && src.portal)
        return src.portal.context; // request
    if ("role" in src && "is_admin" in src)
        return src; // already a Context
    return null;
}
