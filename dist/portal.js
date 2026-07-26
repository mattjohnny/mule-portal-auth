// Thin HTTP client for the Portal service endpoints this connector uses.
// Production uses an app-bound rotating credential. x-portal-key remains only
// session — see the Portal's /api/redeem-sso and /api/context.
export class PortalError extends Error {
    // `signedOut` marks the specific case the Portal told us the person is no
    // longer valid (disabled / removed / off-domain), so callers can sign them
    // out rather than showing a generic error.
    signedOut;
    unavailable;
    constructor(message, signedOut = false, unavailable = false) {
        super(message);
        this.name = "PortalError";
        this.signedOut = signedOut;
        this.unavailable = unavailable;
    }
}
export class PortalServiceAuth {
    provider;
    legacyKey;
    portalUrl;
    refreshMs;
    provenCredentials = new Set();
    proofTimer;
    static PROOF_TIMEOUT_MS = 5_000;
    constructor(provider, legacyKey, portalUrl, refreshMs) {
        this.provider = provider;
        this.legacyKey = legacyKey;
        this.portalUrl = portalUrl;
        this.refreshMs = refreshMs;
        if (provider?.configured()) {
            void this.proveCredentials().catch(() => undefined);
            this.proofTimer = setInterval(() => void this.proveCredentials().catch(() => undefined), refreshMs);
            this.proofTimer.unref?.();
        }
    }
    configured() {
        return !!this.legacyKey || !!this.provider?.configured();
    }
    hasCredentialProvider() {
        return !!this.provider?.configured();
    }
    hasLegacyFallback() {
        return !!this.legacyKey;
    }
    close() {
        if (this.proofTimer)
            clearInterval(this.proofTimer);
        this.provider?.close?.();
    }
    async request(endpoint, init, mode = "normal") {
        if (mode === "legacy-only") {
            if (!this.legacyKey)
                throw new PortalError("Legacy Portal authentication is unavailable.");
            return fetch(endpoint, this.withLegacy(init));
        }
        if (!this.provider?.configured()) {
            if (this.legacyKey)
                return fetch(endpoint, this.withLegacy(init));
            throw new PortalError("Portal service authentication isn't configured.");
        }
        let lastUnauthorized;
        const attempted = new Set();
        for (const forceRefresh of [false, true]) {
            let credentials;
            try {
                credentials = await this.candidates(forceRefresh);
            }
            catch (error) {
                // A configured credential provider owns normal service authentication.
                // Never turn a cold-cache provider failure into shared-key access: doing
                // so would let a restart bypass per-app credential revocation. The AWS
                // provider itself may return a previously loaded credential during an
                // outage, and Portal still validates that credential.
                if (lastUnauthorized)
                    return lastUnauthorized;
                throw error;
            }
            for (const credential of credentials) {
                if (attempted.has(credential.credentialId))
                    continue;
                attempted.add(credential.credentialId);
                const response = await fetch(endpoint, this.withCredential(init, credential));
                if (response.status !== 401)
                    return response;
                // A pending credential can be visible in Secrets Manager before the
                // controller's setSecret step registers it with Portal. A 401 therefore
                // falls through to AWSCURRENT instead of interrupting authentication.
                await discardResponse(response);
                lastUnauthorized = response;
            }
        }
        if (lastUnauthorized)
            return lastUnauthorized;
        throw new PortalError("The Portal credential provider returned no usable credentials.");
    }
    async candidates(forceRefresh) {
        if (!this.provider?.configured())
            return [];
        const all = await this.provider.getCredentials(forceRefresh);
        const pending = all.find((credential) => credential.stage === "AWSPENDING" &&
            this.provenCredentials.has(credential.credentialId));
        const current = all.find((credential) => credential.stage === "AWSCURRENT");
        return [pending, current].filter((credential) => !!credential);
    }
    withCredential(init, credential) {
        const headers = new Headers(init.headers);
        headers.delete("x-portal-key");
        headers.set("Authorization", `PortalCredential ${credential.credentialId}.${credential.secret}`);
        return { ...init, headers };
    }
    withLegacy(init) {
        const headers = new Headers(init.headers);
        headers.delete("Authorization");
        headers.set("x-portal-key", this.legacyKey);
        return { ...init, headers };
    }
    async proveCredentials() {
        if (!this.provider?.configured())
            return;
        const credentials = await this.provider.getCredentials();
        const endpoint = portalEndpoint(this.portalUrl, "/api/credential-proof").toString();
        for (const credential of credentials) {
            if (this.provenCredentials.has(credential.credentialId))
                continue;
            let response;
            const { signal, done } = requestSignal(PortalServiceAuth.PROOF_TIMEOUT_MS);
            try {
                response = await fetch(endpoint, this.withCredential({ method: "POST", signal }, credential));
            }
            catch {
                done();
                continue;
            }
            done();
            if (response.ok) {
                this.provenCredentials.add(credential.credentialId);
                await discardResponse(response);
                continue;
            }
            // 401 is the expected createSecret -> setSecret race. Keep current active
            // and try again on the next refresh tick.
            if (response.status !== 401) {
                console.warn(JSON.stringify({
                    timestamp: new Date().toISOString(),
                    level: "warn",
                    event: "portal_credential_proof_failed",
                    stage: credential.stage,
                    status: response.status,
                }));
            }
            await discardResponse(response);
        }
    }
}
async function discardResponse(response) {
    try {
        await response.body?.cancel();
    }
    catch {
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
function requestSignal(timeoutMs) {
    // AbortSignal.timeout() was doing double duty: bounding the request AND rejecting a
    // nonsensical timeout. setTimeout() does not — it clamps a negative delay to 1ms and
    // carries on. Without this guard an invalid `portalRequestTimeoutMs` would stop being
    // a local configuration error and start looking like a retryable Portal outage, which
    // is precisely what can activate outage-only admin access. Validate explicitly, and
    // throw the same TypeError the platform did so callers classify it unchanged.
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
        throw new TypeError(`Portal request timeout must be a non-negative number of milliseconds; received ${timeoutMs}.`);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => {
        controller.abort(new DOMException("The operation was aborted due to timeout", "TimeoutError"));
    }, timeoutMs);
    return { signal: controller.signal, done: () => clearTimeout(timer) };
}
function portalEndpoint(portalUrl, path) {
    let endpoint;
    try {
        endpoint = new URL(`${portalUrl}${path}`);
    }
    catch {
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
function unavailableForStatus(status) {
    return RETRYABLE_PORTAL_STATUSES.has(status);
}
const PORTAL_ROLES = new Set(["ops", "franchisee", "gm", "manager", "chef"]);
function isObject(value) {
    return !!value && typeof value === "object" && !Array.isArray(value);
}
function validateActiveContext(value, expectedEmail) {
    if (!isObject(value))
        throw new PortalError("The Portal returned an invalid context response.");
    const ctx = value;
    const email = typeof ctx.email === "string" ? ctx.email.toLowerCase() : "";
    const roleIsValid = typeof ctx.role === "string" && PORTAL_ROLES.has(ctx.role);
    const adminInvariant = roleIsValid && ctx.is_admin === (ctx.role === "ops");
    const locationsInvariant = ctx.is_admin
        ? ctx.locations === "all"
        : Array.isArray(ctx.locations) &&
            ctx.locations.every((location) => isObject(location) &&
                Number.isInteger(location.id) &&
                location.id > 0 &&
                typeof location.key === "string" &&
                !!location.key &&
                typeof location.name === "string" &&
                !!location.name);
    const appsInvariant = Array.isArray(ctx.apps) && ctx.apps.every((app) => typeof app === "string" && !!app);
    if (ctx.active !== true ||
        ctx.status !== "active" ||
        !email ||
        email !== expectedEmail.toLowerCase() ||
        typeof ctx.name !== "string" ||
        !adminInvariant ||
        !locationsInvariant ||
        !appsInvariant ||
        !Number.isInteger(ctx.ctx_version) ||
        ctx.ctx_version < 1) {
        throw new PortalError("The Portal returned an invalid context response.");
    }
    return { ...ctx, email };
}
// Redeem a one-time SSO token the Portal minted. Returns the legacy fields plus
// the full context (the Portal attaches it under `context`). Throws PortalError
// on an invalid/expired token, an unreachable Portal, or a disabled person.
export async function redeemSso(opts, ssoToken) {
    // Constructing the URL, headers, or timeout signal can fail because of bad
    // local configuration. Keep those failures outside the network-error catch so
    // they can never activate outage-only admin access.
    const endpoint = portalEndpoint(opts.portalUrl, "/api/redeem-sso").toString();
    const headers = new Headers({ "Content-Type": "application/json" });
    const { signal, done } = requestSignal(opts.requestTimeoutMs);
    // The timeout stays armed until this function returns, so a slow body read is
    // bounded too — same scope as the previous AbortSignal.timeout().
    try {
        let resp;
        try {
            resp = await opts.serviceAuth.request(endpoint, {
                method: "POST",
                headers,
                body: JSON.stringify({ token: ssoToken, app: opts.appName }),
                signal,
            });
        }
        catch {
            throw new PortalError("Couldn't reach the Portal to complete sign-in.", false, true);
        }
        if (resp.status === 403)
            throw new PortalError("That account has been disabled.", true);
        if (!resp.ok) {
            const unavailable = unavailableForStatus(resp.status);
            throw new PortalError(unavailable
                ? "The Portal is temporarily unavailable. Please try again."
                : "That sign-in link is invalid or has expired.", false, unavailable);
        }
        let body;
        try {
            body = (await resp.json());
        }
        catch {
            throw new PortalError("The Portal returned an invalid sign-in response.");
        }
        if (!body?.email)
            throw new PortalError("The Portal didn't return a valid account.");
        if (!body.context)
            throw new PortalError("The Portal didn't return current access details.");
        if (!body.revalidation_handle && opts.serviceAuth.hasCredentialProvider())
            throw new PortalError("The Portal didn't return a revalidation handle.");
        const context = validateActiveContext(body.context, body.email);
        return {
            email: body.email,
            name: body.name || body.email,
            role: body.role || "user",
            context,
            revalidationHandle: body.revalidation_handle || "",
        };
    }
    finally {
        done();
    }
}
// Fetch the current context for a person by email (the re-fetchable read used at
// direct sign-in and for periodic re-validation, §7). Returns null when the
// person is signed out (inactive / unknown) so the caller can end the session.
export async function fetchContext(opts, revalidationHandle, email) {
    const endpoint = portalEndpoint(opts.portalUrl, "/api/context");
    const useHandle = !!revalidationHandle && opts.serviceAuth.hasCredentialProvider();
    if (!useHandle)
        endpoint.searchParams.set("email", email);
    const headers = new Headers(useHandle ? { "Content-Type": "application/json" } : undefined);
    const { signal, done } = requestSignal(opts.requestTimeoutMs);
    // Armed until return, so the body read is bounded too.
    try {
        let resp;
        try {
            resp = await opts.serviceAuth.request(endpoint.toString(), useHandle
                ? {
                    method: "POST",
                    headers,
                    body: JSON.stringify({ handle: revalidationHandle }),
                    signal,
                }
                : { headers, signal }, useHandle ? "normal" : "legacy-only");
        }
        catch {
            throw new PortalError("Couldn't reach the Portal.", false, true);
        }
        if (!resp.ok) {
            const unavailable = unavailableForStatus(resp.status);
            throw new PortalError(unavailable
                ? "The Portal is temporarily unavailable."
                : "Portal rejected the context request.", false, unavailable);
        }
        let body;
        try {
            body = await resp.json();
        }
        catch {
            throw new PortalError("The Portal returned an invalid context response.");
        }
        if (isObject(body) && body.active === false) {
            if (typeof body.email === "string" && body.email.toLowerCase() === email.toLowerCase())
                return null;
            throw new PortalError("The Portal returned an invalid context response.");
        }
        return validateActiveContext(body, email);
    }
    finally {
        done();
    }
}
export async function fetchAppDirectory(opts) {
    const endpoint = portalEndpoint(opts.portalUrl, "/api/app-directory");
    // The query is required only by the legacy fallback. Portal ignores it as
    // an authority source for app credentials and verifies that it matches.
    endpoint.searchParams.set("app", opts.appName);
    const { signal, done } = requestSignal(opts.requestTimeoutMs);
    try {
        let response;
        try {
            response = await opts.serviceAuth.request(endpoint.toString(), { signal });
        }
        catch {
            throw new PortalError("Couldn't reach the Portal directory.", false, true);
        }
        if (!response.ok) {
            throw new PortalError(unavailableForStatus(response.status)
                ? "The Portal directory is temporarily unavailable."
                : "Portal rejected the directory request.", false, unavailableForStatus(response.status));
        }
        try {
            return await response.json();
        }
        catch {
            throw new PortalError("The Portal returned an invalid directory response.");
        }
    }
    finally {
        done();
    }
}
