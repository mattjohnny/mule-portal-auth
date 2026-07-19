import type { Context } from "./types.js";
export declare class PortalError extends Error {
    signedOut: boolean;
    unavailable: boolean;
    constructor(message: string, signedOut?: boolean, unavailable?: boolean);
}
export interface PortalClientOpts {
    portalUrl: string;
    sharedKey: string;
    appName: string;
    requestTimeoutMs: number;
}
export declare function redeemSso(opts: PortalClientOpts, ssoToken: string): Promise<{
    email: string;
    name: string;
    role: string;
    context: Context;
}>;
export declare function fetchContext(opts: PortalClientOpts, email: string): Promise<Context | null>;
