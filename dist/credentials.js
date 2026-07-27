import { GetSecretValueCommand, SecretsManagerClient, } from "@aws-sdk/client-secrets-manager";
import { safeErrorName } from "./safe-error.js";
const DEFAULT_REFRESH_MS = 60_000;
function parseSecret(raw, expectedApp, stage) {
    let parsed;
    try {
        parsed = JSON.parse(raw || "");
    }
    catch {
        throw new Error(`Portal credential ${stage} is not valid JSON.`);
    }
    if (parsed.schemaVersion !== 1 ||
        parsed.appKey !== expectedApp ||
        typeof parsed.credentialId !== "string" ||
        !/^[A-Za-z0-9_-]{8,128}$/.test(parsed.credentialId) ||
        typeof parsed.secret !== "string" ||
        !/^[A-Za-z0-9_-]{32,512}$/.test(parsed.secret)) {
        throw new Error(`Portal credential ${stage} is invalid or bound to another app.`);
    }
    return {
        schemaVersion: 1,
        appKey: expectedApp,
        credentialId: parsed.credentialId,
        secret: parsed.secret,
        stage,
    };
}
export class AwsPortalCredentialProvider {
    secretArn;
    appKey;
    refreshMs;
    client;
    cached = [];
    refreshAfter = 0;
    inFlight;
    constructor(secretArn, appKey, region, refreshMs = DEFAULT_REFRESH_MS, client) {
        this.secretArn = secretArn;
        this.appKey = appKey;
        this.refreshMs = refreshMs;
        this.client = client ?? new SecretsManagerClient({ region });
    }
    configured() {
        return !!this.secretArn;
    }
    async getCredentials(forceRefresh = false, signal) {
        throwIfAborted(signal);
        if (!forceRefresh && this.cached.length && Date.now() < this.refreshAfter) {
            return this.cached;
        }
        if (!this.inFlight) {
            const controller = new AbortController();
            const load = {
                controller,
                waiters: 0,
                settled: false,
            };
            load.promise = this.load(controller.signal).finally(() => {
                load.settled = true;
                if (this.inFlight === load)
                    this.inFlight = undefined;
            });
            this.inFlight = load;
        }
        const load = this.inFlight;
        load.waiters += 1;
        try {
            return await awaitWithSignal(load.promise, signal);
        }
        finally {
            load.waiters -= 1;
            // The SDK request belongs to the group, not to whichever caller happened
            // to arrive first. Cancel it only after every independently bounded
            // waiter has left.
            if (!load.settled && load.waiters === 0) {
                load.controller.abort(new DOMException("All Portal credential waiters were aborted.", "AbortError"));
            }
        }
    }
    close() {
        this.inFlight?.controller.abort(new DOMException("The Portal credential provider was closed.", "AbortError"));
        this.client.destroy();
    }
    async load(signal) {
        try {
            const current = await this.client.send(new GetSecretValueCommand({
                SecretId: this.secretArn,
                VersionStage: "AWSCURRENT",
            }), { abortSignal: signal });
            const values = [
                parseSecret(current.SecretString, this.appKey, "AWSCURRENT"),
            ];
            try {
                const pending = await this.client.send(new GetSecretValueCommand({
                    SecretId: this.secretArn,
                    VersionStage: "AWSPENDING",
                }), { abortSignal: signal });
                values.unshift(parseSecret(pending.SecretString, this.appKey, "AWSPENDING"));
            }
            catch (error) {
                if (signal.aborted)
                    throw error;
                if (!isMissingPendingStage(error)) {
                    // AWSCURRENT is already parsed and usable. Pending is an optional
                    // early-rotation candidate, so its independent discovery/parse
                    // failure must not discard current or take the app offline.
                    console.warn(JSON.stringify({
                        timestamp: new Date().toISOString(),
                        level: "warn",
                        event: "portal_pending_credential_ignored",
                        error_name: safeErrorName(error),
                    }));
                }
            }
            this.cached = values;
            this.refreshAfter = Date.now() + this.refreshMs;
            return values;
        }
        catch (error) {
            if (signal.aborted)
                throw error;
            // A temporary Secrets Manager outage must not take a previously loaded
            // connector offline. Portal still validates the stale credential and will
            // reject it after revocation, so this remains fail-closed.
            if (this.cached.length && canUseStaleCredentials(error))
                return this.cached;
            throw error;
        }
    }
}
function abortReason(signal) {
    return signal.reason ??
        new DOMException("The operation was aborted.", "AbortError");
}
function throwIfAborted(signal) {
    if (signal?.aborted)
        throw abortReason(signal);
}
async function awaitWithSignal(promise, signal) {
    if (!signal)
        return promise;
    throwIfAborted(signal);
    return new Promise((resolve, reject) => {
        const onAbort = () => reject(abortReason(signal));
        const cleanup = () => signal.removeEventListener("abort", onAbort);
        signal.addEventListener("abort", onAbort, { once: true });
        promise.then((value) => {
            cleanup();
            if (signal.aborted)
                reject(abortReason(signal));
            else
                resolve(value);
        }, (error) => {
            cleanup();
            reject(error);
        });
    });
}
function isMissingPendingStage(error) {
    const named = error;
    if (named.name === "ResourceNotFoundException")
        return true;
    if (named.name !== "InvalidRequestException")
        return false;
    return /AWSPENDING|version stage|staging label/i.test(named.message || "");
}
function canUseStaleCredentials(error) {
    const named = error;
    if (named.$metadata?.httpStatusCode &&
        named.$metadata.httpStatusCode >= 500)
        return true;
    const name = named.name || "";
    const code = named.code || "";
    return ([
        "ServiceUnavailableException",
        "InternalServiceError",
        "InternalFailure",
        "TimeoutError",
        "RequestTimeout",
        "NetworkingError",
    ].includes(name) ||
        [
            "ECONNRESET",
            "ECONNREFUSED",
            "EHOSTUNREACH",
            "ENETUNREACH",
            "ETIMEDOUT",
            "EAI_AGAIN",
        ].includes(code));
}
export class StaticPortalCredentialProvider {
    credentials;
    constructor(credentials) {
        this.credentials = credentials;
    }
    configured() {
        return this.credentials.length > 0;
    }
    async getCredentials() {
        return this.credentials.map((credential) => ({ ...credential }));
    }
}
export function defaultCredentialProvider(appKey, injected, secretArn, region, refreshMs) {
    if (injected)
        return injected;
    if (secretArn) {
        if (!region)
            throw new Error("AWS_REGION is required for the Portal credential secret.");
        return new AwsPortalCredentialProvider(secretArn, appKey, region, refreshMs);
    }
    const local = (process.env.PORTAL_APP_CREDENTIAL || "").trim();
    if (local && process.env.NODE_ENV !== "production" && !process.env.RENDER) {
        return new StaticPortalCredentialProvider([
            parseSecret(local, appKey, "AWSCURRENT"),
        ]);
    }
    return undefined;
}
