import type { Context, PortalCredentialProvider } from "./types.js";
export declare class PortalError extends Error {
    signedOut: boolean;
    unavailable: boolean;
    constructor(message: string, signedOut?: boolean, unavailable?: boolean);
}
export interface PortalClientOpts {
    portalUrl: string;
    appName: string;
    requestTimeoutMs: number;
    serviceAuth: PortalServiceAuth;
}
export declare class PortalServiceAuth {
    private readonly provider;
    private readonly legacyKey;
    private readonly portalUrl;
    private readonly refreshMs;
    private readonly provenCredentials;
    private readonly proofTimer?;
    private static readonly PROOF_TIMEOUT_MS;
    constructor(provider: PortalCredentialProvider | undefined, legacyKey: string, portalUrl: string, refreshMs: number);
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
export declare function redeemSso(opts: PortalClientOpts, ssoToken: string): Promise<{
    email: string;
    name: string;
    role: string;
    context: Context;
    revalidationHandle: string;
}>;
export declare function fetchContext(opts: PortalClientOpts, revalidationHandle: string | undefined, email: string): Promise<Context | null>;
export declare function fetchAppDirectory(opts: PortalClientOpts): Promise<unknown>;
