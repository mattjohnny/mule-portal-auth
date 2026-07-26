import type { PortalCredentialProvider, PortalServiceCredential } from "./types.js";
export declare class AwsPortalCredentialProvider implements PortalCredentialProvider {
    private readonly secretArn;
    private readonly appKey;
    private readonly refreshMs;
    private readonly client;
    private cached;
    private refreshAfter;
    private inFlight?;
    constructor(secretArn: string, appKey: string, region: string, refreshMs?: number);
    configured(): boolean;
    getCredentials(forceRefresh?: boolean): Promise<PortalServiceCredential[]>;
    close(): void;
    private load;
}
export declare class StaticPortalCredentialProvider implements PortalCredentialProvider {
    private readonly credentials;
    constructor(credentials: PortalServiceCredential[]);
    configured(): boolean;
    getCredentials(): Promise<PortalServiceCredential[]>;
}
export declare function defaultCredentialProvider(appKey: string, injected: PortalCredentialProvider | undefined, secretArn: string, region: string, refreshMs: number): PortalCredentialProvider | undefined;
