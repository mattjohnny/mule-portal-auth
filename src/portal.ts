import type { Context } from "./types.js";

// Thin HTTP client for the two Portal service endpoints this connector uses.
// Both are authenticated with the shared service key (x-portal-key), not a user
// session — see the Portal's /api/redeem-sso and /api/context.

export class PortalError extends Error {
  // `signedOut` marks the specific case the Portal told us the person is no
  // longer valid (disabled / removed / off-domain), so callers can sign them
  // out rather than showing a generic error.
  signedOut: boolean;
  constructor(message: string, signedOut = false) {
    super(message);
    this.name = "PortalError";
    this.signedOut = signedOut;
  }
}

export interface PortalClientOpts {
  portalUrl: string;
  sharedKey: string;
  appName: string;
}

// Redeem a one-time SSO token the Portal minted. Returns the legacy fields plus
// the full context (the Portal attaches it under `context`). Throws PortalError
// on an invalid/expired token, an unreachable Portal, or a disabled person.
export async function redeemSso(
  opts: PortalClientOpts,
  ssoToken: string
): Promise<{ email: string; name: string; role: string; context: Context }> {
  let resp: Response;
  try {
    resp = await fetch(`${opts.portalUrl}/api/redeem-sso`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-portal-key": opts.sharedKey },
      body: JSON.stringify({ token: ssoToken, app: opts.appName }),
    });
  } catch {
    throw new PortalError("Couldn't reach the Portal to complete sign-in.");
  }
  if (resp.status === 403) throw new PortalError("That account has been disabled.", true);
  if (!resp.ok) throw new PortalError("That sign-in link is invalid or has expired.");

  const body = (await resp.json()) as {
    email?: string;
    name?: string;
    role?: string;
    context?: Context;
  };
  if (!body?.email) throw new PortalError("The Portal didn't return a valid account.");
  const context = body.context ?? fallbackContext(body.email, body.name || "", body.role || "user");
  return { email: body.email, name: body.name || body.email, role: body.role || "user", context };
}

// Fetch the current context for a person by email (the re-fetchable read used at
// direct sign-in and for periodic re-validation, §7). Returns null when the
// person is signed out (inactive / unknown) so the caller can end the session.
export async function fetchContext(
  opts: PortalClientOpts,
  email: string
): Promise<Context | null> {
  let resp: Response;
  try {
    resp = await fetch(
      `${opts.portalUrl}/api/context?email=${encodeURIComponent(email)}`,
      { headers: { "x-portal-key": opts.sharedKey } }
    );
  } catch {
    // Network blip: let the caller decide (we fail OPEN and retry next time,
    // backed by the short session TTL — §7 phased propagation).
    throw new PortalError("Couldn't reach the Portal.");
  }
  if (!resp.ok) throw new PortalError("Portal rejected the context request.");
  const ctx = (await resp.json()) as Context;
  if (!ctx || ctx.active === false) return null;
  return ctx;
}

// When the Portal is old/absent and returns no context block, synthesize a
// minimal one from the legacy fields so a not-yet-upgraded Portal still works.
function fallbackContext(email: string, name: string, role: string): Context {
  const is_admin = role === "admin" || role === "ops";
  return {
    email,
    name: name || email,
    role: is_admin ? "ops" : role,
    is_admin,
    status: "active",
    locations: is_admin ? "all" : [],
    apps: [],
    ctx_version: 0,
    active: true,
  };
}
