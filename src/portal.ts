import type { Context } from "./types.js";

// Thin HTTP client for the two Portal service endpoints this connector uses.
// Both are authenticated with the shared service key (x-portal-key), not a user
// session — see the Portal's /api/redeem-sso and /api/context.

export class PortalError extends Error {
  // `signedOut` marks the specific case the Portal told us the person is no
  // longer valid (disabled / removed / off-domain), so callers can sign them
  // out rather than showing a generic error.
  signedOut: boolean;
  unavailable: boolean;
  constructor(message: string, signedOut = false, unavailable = false) {
    super(message);
    this.name = "PortalError";
    this.signedOut = signedOut;
    this.unavailable = unavailable;
  }
}

export interface PortalClientOpts {
  portalUrl: string;
  sharedKey: string;
  appName: string;
  requestTimeoutMs: number;
}

/**
 * A bounded-request signal whose timer keeps the event loop alive.
 *
 * `AbortSignal.timeout()` is unref'd by design — Node documents that its timer does
 * not hold the loop open. So if a Portal request is the only outstanding work, the
 * loop drains, the timeout never fires, and the request becomes unbounded. That is
 * the exact opposite of the fail-closed guarantee this module exists to provide.
 *
 * Inside a running server the listening socket masks it, which is why this went
 * unnoticed. Under `node --test` nothing else holds the loop, and the
 * "a hung Portal request is bounded and denied" test hung forever on CI while
 * passing locally.
 *
 * Callers MUST invoke `done()` when the request finishes, or the ref'd timer keeps
 * the process alive for up to `timeoutMs`.
 */
function requestSignal(timeoutMs: number): { signal: AbortSignal; done: () => void } {
  // AbortSignal.timeout() was doing double duty: bounding the request AND rejecting a
  // nonsensical timeout. setTimeout() does not — it clamps a negative delay to 1ms and
  // carries on. Without this guard an invalid `portalRequestTimeoutMs` would stop being
  // a local configuration error and start looking like a retryable Portal outage, which
  // is precisely what can activate outage-only admin access. Validate explicitly, and
  // throw the same TypeError the platform did so callers classify it unchanged.
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
    throw new TypeError(
      `Portal request timeout must be a non-negative number of milliseconds; received ${timeoutMs}.`
    );
  }
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(
      new DOMException("The operation was aborted due to timeout", "TimeoutError")
    );
  }, timeoutMs);
  return { signal: controller.signal, done: () => clearTimeout(timer) };
}

function portalEndpoint(portalUrl: string, path: string): URL {
  let endpoint: URL;
  try {
    endpoint = new URL(`${portalUrl}${path}`);
  } catch {
    throw new PortalError("Portal URL configuration is invalid.");
  }
  if (endpoint.protocol !== "http:" && endpoint.protocol !== "https:")
    throw new PortalError("Portal URL must use HTTP or HTTPS.");
  return endpoint;
}

// Keep outage-only break glass narrow. Authentication/protocol failures must
// never become "Portal unavailable" merely because they arrived over HTTP.
// Do not include 429 here. The Portal's app-to-app endpoint is itself
// rate-limited, so callers can induce a 429 while the Portal is healthy. Treating
// that response as an outage would turn throttling into offline-admin access.
const RETRYABLE_PORTAL_STATUSES = new Set([408, 425, 500, 502, 503, 504]);

function unavailableForStatus(status: number): boolean {
  return RETRYABLE_PORTAL_STATUSES.has(status);
}

const PORTAL_ROLES = new Set(["ops", "franchisee", "gm", "manager", "chef"]);

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function validateActiveContext(value: unknown, expectedEmail: string): Context {
  if (!isObject(value))
    throw new PortalError("The Portal returned an invalid context response.");
  const ctx = value as unknown as Context;
  const email = typeof ctx.email === "string" ? ctx.email.toLowerCase() : "";
  const roleIsValid = typeof ctx.role === "string" && PORTAL_ROLES.has(ctx.role);
  const adminInvariant = roleIsValid && ctx.is_admin === (ctx.role === "ops");
  const locationsInvariant = ctx.is_admin
    ? ctx.locations === "all"
    : Array.isArray(ctx.locations) &&
      ctx.locations.every(
        (location) =>
          isObject(location) &&
          Number.isInteger(location.id) &&
          location.id > 0 &&
          typeof location.key === "string" &&
          !!location.key &&
          typeof location.name === "string" &&
          !!location.name
      );
  const appsInvariant =
    Array.isArray(ctx.apps) && ctx.apps.every((app) => typeof app === "string" && !!app);
  if (
    ctx.active !== true ||
    ctx.status !== "active" ||
    !email ||
    email !== expectedEmail.toLowerCase() ||
    typeof ctx.name !== "string" ||
    !adminInvariant ||
    !locationsInvariant ||
    !appsInvariant ||
    !Number.isInteger(ctx.ctx_version) ||
    ctx.ctx_version < 1
  ) {
    throw new PortalError("The Portal returned an invalid context response.");
  }
  return { ...ctx, email };
}

// Redeem a one-time SSO token the Portal minted. Returns the legacy fields plus
// the full context (the Portal attaches it under `context`). Throws PortalError
// on an invalid/expired token, an unreachable Portal, or a disabled person.
export async function redeemSso(
  opts: PortalClientOpts,
  ssoToken: string
): Promise<{ email: string; name: string; role: string; context: Context }> {
  // Constructing the URL, headers, or timeout signal can fail because of bad
  // local configuration. Keep those failures outside the network-error catch so
  // they can never activate outage-only admin access.
  const endpoint = portalEndpoint(opts.portalUrl, "/api/redeem-sso").toString();
  const headers = new Headers({ "Content-Type": "application/json", "x-portal-key": opts.sharedKey });
  const { signal, done } = requestSignal(opts.requestTimeoutMs);
  // The timeout stays armed until this function returns, so a slow body read is
  // bounded too — same scope as the previous AbortSignal.timeout().
  try {
    let resp: Response;
    try {
      resp = await fetch(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify({ token: ssoToken, app: opts.appName }),
        signal,
      });
    } catch {
      throw new PortalError("Couldn't reach the Portal to complete sign-in.", false, true);
    }
    if (resp.status === 403) throw new PortalError("That account has been disabled.", true);
    if (!resp.ok) {
      const unavailable = unavailableForStatus(resp.status);
      throw new PortalError(
        unavailable
          ? "The Portal is temporarily unavailable. Please try again."
          : "That sign-in link is invalid or has expired.",
        false,
        unavailable
      );
    }

    let body: { email?: string; name?: string; role?: string; context?: Context };
    try {
      body = (await resp.json()) as typeof body;
    } catch {
      throw new PortalError("The Portal returned an invalid sign-in response.");
    }
    if (!body?.email) throw new PortalError("The Portal didn't return a valid account.");
    if (!body.context)
      throw new PortalError("The Portal didn't return current access details.");
    const context = validateActiveContext(body.context, body.email);
    return { email: body.email, name: body.name || body.email, role: body.role || "user", context };
  } finally {
    done();
  }
}

// Fetch the current context for a person by email (the re-fetchable read used at
// direct sign-in and for periodic re-validation, §7). Returns null when the
// person is signed out (inactive / unknown) so the caller can end the session.
export async function fetchContext(
  opts: PortalClientOpts,
  email: string
): Promise<Context | null> {
  const endpoint = portalEndpoint(opts.portalUrl, "/api/context");
  endpoint.searchParams.set("email", email);
  const headers = new Headers({ "x-portal-key": opts.sharedKey });
  const { signal, done } = requestSignal(opts.requestTimeoutMs);
  // Armed until return, so the body read is bounded too.
  try {
    let resp: Response;
    try {
      resp = await fetch(endpoint, { headers, signal });
    } catch {
      throw new PortalError("Couldn't reach the Portal.", false, true);
    }
    if (!resp.ok) {
      const unavailable = unavailableForStatus(resp.status);
      throw new PortalError(
        unavailable
          ? "The Portal is temporarily unavailable."
          : "Portal rejected the context request.",
        false,
        unavailable
      );
    }
    let body: unknown;
    try {
      body = await resp.json();
    } catch {
      throw new PortalError("The Portal returned an invalid context response.");
    }
    if (isObject(body) && body.active === false) {
      if (typeof body.email === "string" && body.email.toLowerCase() === email.toLowerCase())
        return null;
      throw new PortalError("The Portal returned an invalid context response.");
    }
    return validateActiveContext(body, email);
  } finally {
    done();
  }
}
