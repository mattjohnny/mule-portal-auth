import type {
  Context,
  PortalAuthorityMode,
  PortalAppDirectory,
  PortalDirectoryOptions,
  PortalCredentialProvider,
  PortalServiceCredential,
} from "./types.js";
import { safeErrorName } from "./safe-error.js";

// Thin HTTP client for the Portal service endpoints this connector uses.
// Production uses an app-bound rotating credential. x-portal-key remains only
// session — see the Portal's /api/redeem-sso and /api/context.

export class PortalError extends Error {
  // `signedOut` marks the specific case the Portal told us the person is no
  // longer valid (disabled / removed / off-domain), so callers can sign them
  // out rather than showing a generic error.
  signedOut: boolean;
  unavailable: boolean;
  // Whole seconds the Portal asked callers to wait: its delta-seconds
  // `Retry-After` on a 429/503 context lookup, clamped to 1..300. Absent when
  // the Portal sent none (or an HTTP-date / malformed value).
  declare retryAfterSeconds?: number;
  // Which check rejected a Portal response, by field and position only (for
  // example "people[3].email"). Never carries a value from the response.
  declare detail?: string;
  constructor(
    message: string,
    signedOut = false,
    unavailable = false,
    extra: { retryAfterSeconds?: number; detail?: string } = {}
  ) {
    super(message);
    this.name = "PortalError";
    this.signedOut = signedOut;
    this.unavailable = unavailable;
    if (extra.retryAfterSeconds !== undefined) this.retryAfterSeconds = extra.retryAfterSeconds;
    if (extra.detail !== undefined) this.detail = extra.detail;
  }
}

// Credential discovery is local service configuration/IAM, not Portal
// availability. Keep it distinguishable so outage-only ADMIN_EMAILS access can
// never be activated by a broken, deleted, malformed, or timed-out secret.
export class PortalCredentialError extends PortalError {
  constructor(message = "Portal service credential discovery failed.") {
    super(message, false, false);
    this.name = "PortalCredentialError";
  }
}

export interface PortalClientOpts {
  portalUrl: string;
  appName: string;
  requestTimeoutMs: number;
  serviceAuth: PortalServiceAuth;
  authorityMode?: PortalAuthorityMode;
}

export class PortalServiceAuth {
  private readonly provenCredentials = new Set<string>();
  private readonly proofTimer?: ReturnType<typeof setInterval>;
  private static readonly PROOF_TIMEOUT_MS = 5_000;

  constructor(
    private readonly provider: PortalCredentialProvider | undefined,
    private readonly legacyKey: string,
    private readonly portalUrl: string,
    private readonly refreshMs: number,
    private readonly appName = ""
  ) {
    if (provider?.configured()) {
      void this.proveCredentials().catch(() => undefined);
      this.proofTimer = setInterval(
        () => void this.proveCredentials().catch(() => undefined),
        refreshMs
      );
      this.proofTimer.unref?.();
    }
  }

  configured(): boolean {
    return !!this.legacyKey || !!this.provider?.configured();
  }

  hasCredentialProvider(): boolean {
    return !!this.provider?.configured();
  }

  hasLegacyFallback(): boolean {
    return !!this.legacyKey;
  }

  close(): void {
    if (this.proofTimer) clearInterval(this.proofTimer);
    this.provider?.close?.();
  }

  async request(
    endpoint: string,
    init: RequestInit,
    mode: "normal" | "legacy-only" = "normal"
  ): Promise<Response> {
    // Validate before credential discovery or attachment, including direct
    // transport callers. Configuration errors must not become Portal outages.
    portalEndpoint(endpoint, "");
    if (mode === "legacy-only") {
      if (!this.legacyKey) throw new PortalError("Legacy Portal authentication is unavailable.");
      return fetch(endpoint, this.withLegacy(init));
    }
    if (!this.provider?.configured()) {
      if (this.legacyKey) return fetch(endpoint, this.withLegacy(init));
      throw new PortalError("Portal service authentication isn't configured.");
    }

    let lastUnauthorized: Response | undefined;
    const attempted = new Set<string>();
    for (const forceRefresh of [false, true]) {
      let credentials: PortalServiceCredential[];
      try {
        credentials = await this.candidates(
          forceRefresh,
          init.signal ?? undefined
        );
      } catch (error) {
        // A configured credential provider owns normal service authentication.
        // Never turn a cold-cache provider failure into shared-key access: doing
        // so would let a restart bypass per-app credential revocation. The AWS
        // provider itself may return a previously loaded credential during an
        // outage, and Portal still validates that credential.
        if (lastUnauthorized) return lastUnauthorized;
        if (error instanceof PortalCredentialError) throw error;
        throw new PortalCredentialError();
      }
      for (const credential of credentials) {
        if (attempted.has(credential.credentialId)) continue;
        attempted.add(credential.credentialId);
        // Credential discovery and Portal transport share one caller deadline.
        // If discovery (or work between candidates) consumed that deadline,
        // fail locally before fetch can turn an already-aborted signal into an
        // apparent Portal outage and activate offline-admin access.
        if (init.signal?.aborted) {
          throw new PortalCredentialError(
            "Portal credential discovery exceeded the request deadline."
          );
        }
        const response = await fetch(endpoint, this.withCredential(init, credential));
        if (response.status !== 401) return response;
        // A pending credential can be visible in Secrets Manager before the
        // controller's setSecret step registers it with Portal. A 401 therefore
        // falls through to AWSCURRENT instead of interrupting authentication.
        await discardResponse(response);
        lastUnauthorized = response;
      }
    }
    if (lastUnauthorized) return lastUnauthorized;
    throw new PortalCredentialError(
      "The Portal credential provider returned no usable credentials."
    );
  }

  private async candidates(
    forceRefresh: boolean,
    signal?: AbortSignal
  ): Promise<PortalServiceCredential[]> {
    if (!this.provider?.configured()) return [];
    const all = await awaitWithSignal(
      this.provider.getCredentials(forceRefresh, signal),
      signal
    );
    const pending = all.find(
      (credential) =>
        credential.stage === "AWSPENDING" &&
        this.provenCredentials.has(credential.credentialId)
    );
    const current = all.find((credential) => credential.stage === "AWSCURRENT");
    return [pending, current].filter(
      (credential): credential is PortalServiceCredential => !!credential
    );
  }

  private withCredential(
    init: RequestInit,
    credential: PortalServiceCredential
  ): RequestInit {
    const headers = new Headers(init.headers);
    headers.delete("x-portal-key");
    headers.set(
      "Authorization",
      `PortalCredential ${credential.credentialId}.${credential.secret}`
    );
    // Never forward credentials or replay SSO/handle bodies through a redirect.
    // Manual mode leaves 3xx available to the existing non-outage denial path.
    return { ...init, headers, redirect: "manual" };
  }

  private withLegacy(init: RequestInit): RequestInit {
    const headers = new Headers(init.headers);
    headers.delete("Authorization");
    headers.set("x-portal-key", this.legacyKey);
    if (this.appName) headers.set("x-portal-app", this.appName);
    return { ...init, headers, redirect: "manual" };
  }

  private async proveCredentials(): Promise<void> {
    if (!this.provider?.configured()) return;
    // One deadline covers Secrets Manager discovery and every proof request in
    // this cycle. A cold-cache AWS hang therefore cannot stall the background
    // proof loop indefinitely.
    const { signal, done } = requestSignal(
      PortalServiceAuth.PROOF_TIMEOUT_MS
    );
    try {
      let credentials: PortalServiceCredential[];
      try {
        credentials = await awaitWithSignal(
          this.provider.getCredentials(false, signal),
          signal
        );
      } catch (error) {
        console.warn(
          JSON.stringify({
            timestamp: new Date().toISOString(),
            level: "warn",
            event: "portal_credential_proof_discovery_failed",
            error_name: safeErrorName(error),
          })
        );
        return;
      }
      const endpoint = portalEndpoint(this.portalUrl, "/api/credential-proof").toString();
      for (const credential of credentials) {
        if (this.provenCredentials.has(credential.credentialId)) continue;
        let response: Response;
        try {
          response = await fetch(
            endpoint,
            this.withCredential({ method: "POST", signal }, credential)
          );
        } catch {
          if (signal.aborted) return;
          continue;
        }
        if (response.ok) {
          this.provenCredentials.add(credential.credentialId);
          await discardResponse(response);
          continue;
        }
        // 401 is the expected createSecret -> setSecret race. Keep current active
        // and try again on the next refresh tick.
        if (response.status !== 401) {
          console.warn(
            JSON.stringify({
              timestamp: new Date().toISOString(),
              level: "warn",
              event: "portal_credential_proof_failed",
              stage: credential.stage,
              status: response.status,
            })
          );
        }
        await discardResponse(response);
      }
    } finally {
      done();
    }
  }
}

async function discardResponse(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // The response is already closed; there is nothing left to release.
  }
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

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ??
    new DOMException("The operation was aborted.", "AbortError");
}

async function awaitWithSignal<T>(
  promise: Promise<T>,
  signal?: AbortSignal
): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) throw abortReason(signal);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortReason(signal));
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        cleanup();
        if (signal.aborted) reject(abortReason(signal));
        else resolve(value);
      },
      (error) => {
        cleanup();
        reject(error);
      }
    );
  });
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
  if (
    endpoint.protocol !== "https:" &&
    (process.env.NODE_ENV === "production" || process.env.RENDER)
  ) {
    throw new PortalError("Portal URL must use HTTPS in production or on Render.");
  }
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

// Pass the Portal's own back-off through to the person's browser instead of the
// connector's fixed answer. Only delta-seconds is honoured, and it is clamped so
// a misbehaving reply can neither demand an instant retry storm nor park clients
// for hours. This never changes which statuses count as an outage (429 still
// does not) and never causes the connector itself to retry.
export const MIN_RETRY_AFTER_SECONDS = 1;
export const MAX_RETRY_AFTER_SECONDS = 300;

function portalRetryAfterSeconds(response: Response): number | undefined {
  if (response.status !== 429 && response.status !== 503) return undefined;
  const value = response.headers.get("retry-after")?.trim();
  if (!value || !/^\d+$/.test(value)) return undefined;
  return Math.min(MAX_RETRY_AFTER_SECONDS, Math.max(MIN_RETRY_AFTER_SECONDS, Number(value)));
}

const PORTAL_ROLES = new Set(["ops", "franchisee", "gm", "manager", "chef"]);
const ADDITIONAL_PORTAL_ROLES = new Set(["finance", "hr"]);

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+$/.test(value);
}

function stringSet(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string" && item.trim() === item && !!item) &&
    new Set(value).size === value.length;
}

function validRoles(value: unknown, primary: unknown): boolean {
  return typeof primary === "string" && PORTAL_ROLES.has(primary) && stringSet(value) &&
    value[0] === primary && value.slice(1).every((role) => ADDITIONAL_PORTAL_ROLES.has(role));
}

function validLocations(value: unknown, requireCanonical: boolean): boolean {
  return locationsProblem(value, requireCanonical) === null;
}

// null when the location set is valid; otherwise the failed check as a
// position suffix ("" for a non-array, "[2].key duplicate", ...). Names fields
// and indexes only, never a value, so it is safe to surface as error detail.
function locationsProblem(value: unknown, requireCanonical: boolean): string | null {
  if (value === "all") return null;
  if (!Array.isArray(value)) return "";
  const ids = new Set<unknown>();
  const keys = new Set<unknown>();
  for (const [index, location] of value.entries()) {
    if (!isObject(location)) return `[${index}]`;
    if (!Number.isSafeInteger(location.id) || Number(location.id) <= 0) return `[${index}].id`;
    if (typeof location.key !== "string" || !location.key || location.key.trim() !== location.key)
      return `[${index}].key`;
    if (typeof location.name !== "string" || !location.name) return `[${index}].name`;
    if (!(typeof location.is_mule === "boolean" || (!requireCanonical && location.is_mule === undefined)))
      return `[${index}].is_mule`;
    if (ids.has(location.id)) return `[${index}].id duplicate`;
    if (keys.has(location.key)) return `[${index}].key duplicate`;
    ids.add(location.id);
    keys.add(location.key);
  }
  return null;
}

function validateActiveContext(value: unknown, expectedEmail: string, strict = false): Context {
  if (!isObject(value))
    throw new PortalError("The Portal returned an invalid context response.");
  const ctx = value as unknown as Context;
  const email = typeof ctx.email === "string" ? ctx.email.toLowerCase() : "";
  const roleIsValid = typeof ctx.role === "string" && PORTAL_ROLES.has(ctx.role);
  const adminInvariant = roleIsValid && ctx.is_admin === (ctx.role === "ops");
  const locationsInvariant = validLocations(ctx.locations, strict) &&
    (ctx.is_admin ? ctx.locations === "all" : ctx.locations !== "all");
  const appsInvariant =
    stringSet(ctx.apps);
  const roles = !strict && ctx.roles === undefined ? [ctx.role] : ctx.roles;
  const permissions = !strict && ctx.app_permissions === undefined ? {} : ctx.app_permissions;
  const permissionsInvariant = isObject(permissions) && Object.entries(permissions).every(
    ([app, values]) => appsInvariant && ctx.apps.includes(app) && stringSet(values)
  );
  if (
    ctx.active !== true ||
    ctx.status !== "active" ||
    !validEmail(email) ||
    email !== expectedEmail.toLowerCase() ||
    typeof ctx.name !== "string" ||
    !adminInvariant ||
    !locationsInvariant ||
    !appsInvariant ||
    !validRoles(roles, ctx.role) ||
    !permissionsInvariant ||
    !Number.isSafeInteger(ctx.ctx_version) ||
    ctx.ctx_version < 1
  ) {
    throw new PortalError("The Portal returned an invalid context response.");
  }
  return { ...ctx, email, roles: roles as string[], app_permissions: permissions as Record<string, string[]> };
}

// Redeem a one-time SSO token the Portal minted. Returns the legacy fields plus
// the full context (the Portal attaches it under `context`). Throws PortalError
// on an invalid/expired token, an unreachable Portal, or a disabled person.
export async function redeemSso(
  opts: PortalClientOpts,
  ssoToken: string
): Promise<{
  email: string;
  name: string;
  role: string;
  context: Context;
  revalidationHandle: string;
}> {
  // Constructing the URL, headers, or timeout signal can fail because of bad
  // local configuration. Keep those failures outside the network-error catch so
  // they can never activate outage-only admin access.
  const endpoint = portalEndpoint(opts.portalUrl, "/api/redeem-sso").toString();
  const headers = new Headers({ "Content-Type": "application/json" });
  const { signal, done } = requestSignal(opts.requestTimeoutMs);
  // The timeout stays armed until this function returns, so a slow body read is
  // bounded too — same scope as the previous AbortSignal.timeout().
  try {
    let resp: Response;
    try {
      resp = await opts.serviceAuth.request(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify({ token: ssoToken, app: opts.appName }),
        signal,
      });
    } catch (error) {
      if (error instanceof PortalError) throw error;
      throw new PortalError("Couldn't reach the Portal to complete sign-in.", false, true);
    }
    if (resp.status === 403) {
      await discardResponse(resp);
      throw new PortalError("That account has been disabled.", true);
    }
    if (!resp.ok) {
      const unavailable = unavailableForStatus(resp.status);
      await discardResponse(resp);
      throw new PortalError(
        unavailable
          ? "The Portal is temporarily unavailable. Please try again."
          : "That sign-in link is invalid or has expired.",
        false,
        unavailable
      );
    }

    let body: {
      email?: string;
      name?: string;
      role?: string;
      context?: Context;
      revalidation_handle?: string;
    };
    try {
      body = (await resp.json()) as typeof body;
    } catch {
      throw new PortalError("The Portal returned an invalid sign-in response.");
    }
    if (!validEmail(body?.email)) throw new PortalError("The Portal didn't return a valid account.");
    if (!body.context)
      throw new PortalError("The Portal didn't return current access details.");
    if (body.revalidation_handle !== undefined && typeof body.revalidation_handle !== "string")
      throw new PortalError("The Portal returned an invalid sign-in response.");
    if (!body.revalidation_handle?.trim() && opts.serviceAuth.hasCredentialProvider())
      throw new PortalError("The Portal didn't return a revalidation handle.");
    const context = validateActiveContext(body.context, body.email, opts.authorityMode === "request");
    return {
      email: body.email,
      name: body.name || body.email,
      role: body.role || "user",
      context,
      revalidationHandle: body.revalidation_handle || "",
    };
  } finally {
    done();
  }
}

// Fetch the current context for a person by email (the re-fetchable read used at
// direct sign-in and for periodic re-validation, §7). Returns null when the
// person is signed out (inactive / unknown) so the caller can end the session.
export async function fetchContext(
  opts: PortalClientOpts,
  revalidationHandle: string | undefined,
  email: string
): Promise<Context | null> {
  const endpoint = portalEndpoint(opts.portalUrl, "/api/context");
  const useHandle = !!revalidationHandle && opts.serviceAuth.hasCredentialProvider();
  if (!useHandle) {
    endpoint.searchParams.set("email", email);
    // Legacy auth has no credential binding, so include the claimed app for
    // migration telemetry. Portal still treats this only as attribution.
    endpoint.searchParams.set("app", opts.appName);
  }
  const headers = new Headers(
    useHandle ? { "Content-Type": "application/json" } : undefined
  );
  const { signal, done } = requestSignal(opts.requestTimeoutMs);
  // Armed until return, so the body read is bounded too.
  try {
    let resp: Response;
    try {
      resp = await opts.serviceAuth.request(
        endpoint.toString(),
        useHandle
          ? {
              method: "POST",
              headers,
              body: JSON.stringify({ handle: revalidationHandle }),
              signal,
            }
          : { headers, signal, cache: opts.authorityMode === "request" ? "no-store" : "default" },
        useHandle ? "normal" : "legacy-only"
      );
    } catch (error) {
      if (error instanceof PortalError) throw error;
      throw new PortalError("Couldn't reach the Portal.", false, true);
    }
    if (!resp.ok) {
      const unavailable = unavailableForStatus(resp.status);
      // Read the header before the body is released.
      const retryAfterSeconds = portalRetryAfterSeconds(resp);
      await discardResponse(resp);
      throw new PortalError(
        unavailable
          ? "The Portal is temporarily unavailable."
          : "Portal rejected the context request.",
        false,
        unavailable,
        { retryAfterSeconds }
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
    return validateActiveContext(body, email, opts.authorityMode === "request");
  } finally {
    done();
  }
}

// The whole directory is refused on any failed check (fail closed; no row is
// skipped). The thrown error's `detail` names that check by field and position,
// for example "people[3].email" or "locations[2].key duplicate", and never
// carries a value from the response.
function validateDirectory(value: unknown, options: PortalDirectoryOptions, startedAt: number): PortalAppDirectory {
  const invalid = (detail: string) =>
    new PortalError("The Portal returned an invalid directory response.", false, false, { detail });
  if (!isObject(value)) throw invalid("body");
  if (typeof value.syncedAt !== "string") throw invalid("syncedAt");
  if (!Array.isArray(value.locations)) throw invalid("locations");
  const locationsDetail = locationsProblem(value.locations, true);
  if (locationsDetail !== null) throw invalid(`locations${locationsDetail}`);
  if (!Array.isArray(value.people)) throw invalid("people");
  // Every call is a new read; the timestamp also rejects stale intermediary
  // responses. Permit 30 seconds of server clock skew, never a cached lease.
  const syncedAt = Date.parse(value.syncedAt);
  const receivedAt = Date.now();
  if (!Number.isFinite(syncedAt)) throw invalid("syncedAt");
  if (syncedAt < startedAt - 30_000 || Math.abs(receivedAt - syncedAt) > 30_000)
    throw invalid("syncedAt skew");
  const directory = value as unknown as PortalAppDirectory;
  if (!options.include_non_mule) {
    const nonMule = directory.locations.findIndex((location) => !location.is_mule);
    if (nonMule !== -1) throw invalid(`locations[${nonMule}].is_mule non-Mule`);
  }
  const locationsById = new Map(directory.locations.map((location) => [location.id, location]));
  const emails = new Set<string>();
  for (const [index, person] of directory.people.entries()) {
    const at = `people[${index}]`;
    if (!isObject(person)) throw invalid(at);
    if (!validEmail(person.email)) throw invalid(`${at}.email`);
    if (emails.has(person.email.toLowerCase())) throw invalid(`${at}.email duplicate`);
    if (typeof person.name !== "string") throw invalid(`${at}.name`);
    if (!validRoles(person.roles, person.role)) throw invalid(`${at}.roles`);
    if (!["active", "disabled"].includes(person.status)) throw invalid(`${at}.status`);
    if (!stringSet(person.permissions)) throw invalid(`${at}.permissions`);
    if (!Number.isSafeInteger(person.ctx_version) || person.ctx_version < 1)
      throw invalid(`${at}.ctx_version`);
    if (!(person.last_login === null || (typeof person.last_login === "string" && Number.isFinite(Date.parse(person.last_login)))))
      throw invalid(`${at}.last_login`);
    const personLocationsDetail = locationsProblem(person.locations, true);
    if (personLocationsDetail !== null) throw invalid(`${at}.locations${personLocationsDetail}`);
    if (person.role === "ops" ? person.locations !== "all" : person.locations === "all")
      throw invalid(`${at}.locations scope`);
    emails.add(person.email.toLowerCase());
    if (person.locations !== "all") {
      const contradiction = person.locations.findIndex((location) => {
        const canonical = locationsById.get(location.id);
        return !canonical || canonical.key !== location.key || canonical.name !== location.name || canonical.is_mule !== location.is_mule;
      });
      if (contradiction !== -1) throw invalid(`${at}.locations[${contradiction}] not canonical`);
    }
  }
  return directory;
}

export async function fetchAppDirectory(
  opts: PortalClientOpts,
  options: PortalDirectoryOptions = {}
): Promise<PortalAppDirectory> {
  const endpoint = portalEndpoint(opts.portalUrl, "/api/app-directory");
  // The query is required only by the legacy fallback. Portal ignores it as
  // an authority source for app credentials and verifies that it matches.
  endpoint.searchParams.set("app", opts.appName);
  if (options.include_non_mule !== undefined && typeof options.include_non_mule !== "boolean")
    throw new PortalError("Invalid Portal directory options.");
  if (options.include_non_mule) endpoint.searchParams.set("include_non_mule", "true");
  const startedAt = Date.now();
  const { signal, done } = requestSignal(opts.requestTimeoutMs);
  try {
    let response: Response;
    try {
      response = await opts.serviceAuth.request(endpoint.toString(), { signal, cache: "no-store" });
    } catch (error) {
      if (error instanceof PortalError) throw error;
      throw new PortalError("Couldn't reach the Portal directory.", false, true);
    }
    if (!response.ok) {
      const unavailable = unavailableForStatus(response.status);
      await discardResponse(response);
      throw new PortalError(
        unavailable
          ? "The Portal directory is temporarily unavailable."
          : "Portal rejected the directory request.",
        false,
        unavailable
      );
    }
    try {
      return validateDirectory(await response.json(), options, startedAt);
    } catch (error) {
      // Keep validation's field/position detail; an unreadable body has none.
      throw new PortalError("The Portal returned an invalid directory response.", false, false, {
        detail: error instanceof PortalError ? error.detail : undefined,
      });
    }
  } finally {
    done();
  }
}
