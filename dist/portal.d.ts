import type { Context } from "./types.js";
export declare class PortalError extends Error {
    signedOut: boolean;
    constructor(message: string, signedOut?: boolean);
}
export interface PortalClientOpts {
    portalUrl: string;
    sharedKey: string;
    appName: string;
}
export declare function redeemSso(opts: PortalClientOpts, ssoToken: string): Promise<{
    email: string;
    name: string;
    role: string;
    context: Context;
}>;
export declare function fetchContext(opts: PortalClientOpts, email: string): Promise<Context | null>;
