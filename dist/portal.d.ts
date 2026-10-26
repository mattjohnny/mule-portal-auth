import type { Context, PortalAuthorityMode, PortalAppDirectory, PortalDirectoryOptions, PortalCredentialProvider } from "./types.js";
export declare class PortalError extends Error {
    signedOut: boolean;
    unavailable: boolean;
    retryAfterSeconds?: number;
    detail?: string;
    constructor(message: string, signedOut?: boolean, unavailable?: boolean, extra?: {
        retryAfterSeconds?: number;
        detail?: string;
    });
}
export declare class PortalCredentialError extends PortalError {
    constructor(message?: string);
}
export interface PortalClientOpts {
    portalUrl: string;
    appName: string;
    requestTimeoutMs: number;
    serviceAuth: PortalServiceAuth;
    authorityMode?: PortalAuthorityMode;
}
export declare class PortalServiceAuth {
    private readonly provider;
    private readonly legacyKey;
    private readonly portalUrl;
    private readonly refreshMs;
    private readonly appName;
    private readonly provenCredentials;
    private readonly proofTimer?;
    private static readonly PROOF_TIMEOUT_MS;
    constructor(provider: PortalCredentialProvider | undefined, legacyKey: string, portalUrl: string, refreshMs: number, appName?: string);
    configured(): boolean;
    hasCredentialProvider(): boolean;
    hasLegacyFallback(): boolean;
    close(): void;
    request(endpoint: string, init: RequestInit, mode?: "normal" | "legacy-only"): Promise<Response>;
    private candidates;
    private withCredential;
    private withLegacy;
    private proveCredentials;
}
export declare const MIN_RETRY_AFTER_SECONDS = 1;
export declare const MAX_RETRY_AFTER_SECONDS = 300;
export declare function redeemSso(opts: PortalClientOpts, ssoToken: string): Promise<{
    email: string;
    name: string;
    role: string;
    context: Context;
    revalidationHandle: string;
}>;
export declare function fetchContext(opts: PortalClientOpts, revalidationHandle: string | undefined, email: string): Promise<Context | null>;
export declare function fetchAppDirectory(opts: PortalClientOpts, options?: PortalDirectoryOptions): Promise<PortalAppDirectory>;
