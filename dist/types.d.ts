import type { Request } from "express";
export interface PortalLocation {
    id: number;
    key: string;
    name: string;
    is_mule?: boolean;
}
export interface PortalDirectoryLocation extends PortalLocation {
    is_mule: boolean;
}
export interface PortalDirectoryPerson {
    email: string;
    name: string;
    role: string;
    roles: string[];
    status: "active" | "disabled";
    locations: PortalDirectoryLocation[] | "all";
    permissions: string[];
    ctx_version: number;
    last_login: string | null;
}
export interface PortalAppDirectory {
    syncedAt: string;
    locations: PortalDirectoryLocation[];
    people: PortalDirectoryPerson[];
}
export interface PortalDirectoryOptions {
    include_non_mule?: boolean;
}
export interface Context {
    email: string;
    name: string;
    role: string;
    roles?: string[];
    app_permissions?: Record<string, string[]>;
    is_admin: boolean;
    status: string;
    locations: PortalLocation[] | "all";
    apps: string[];
    ctx_version: number;
    active: boolean;
}
export interface Session {
    token: string;
    email: string;
    name: string;
    role: string;
    context: Context;
    revalidationHandle?: string;
}
export type PortalCredentialStage = "AWSCURRENT" | "AWSPENDING";
export interface PortalServiceCredential {
    schemaVersion: 1;
    appKey: string;
    credentialId: string;
    secret: string;
    stage: PortalCredentialStage;
}
export interface PortalCredentialProvider {
    configured(): boolean;
    getCredentials(forceRefresh?: boolean, signal?: AbortSignal): Promise<PortalServiceCredential[]>;
    close?(): void;
}
export type PortalAuthorityMode = "cached" | "request";
export interface PortalAuthedRequest extends Request {
    portal?: Session;
}
export interface PortalAuthConfig {
    db: import("better-sqlite3").Database;
    appName: string;
    portalUrl?: string;
    sharedKey?: string;
    credentialProvider?: PortalCredentialProvider;
    credentialSecretArn?: string;
    awsRegion?: string;
    credentialRefreshMs?: number;
    googleClientId?: string;
    allowedDomains?: string[];
    adminEmails?: string[];
    sessionTtlMs?: number;
    revalidateMs?: number;
    authorityMode?: PortalAuthorityMode;
    portalRequestTimeoutMs?: number;
    allowOfflineAdmin?: boolean;
}
export interface PortalSessionRow {
    token: string;
    email: string;
    name: string;
    context: string;
    created_at: number;
    expires_at: number;
    last_validated: number;
    source: string;
    revalidation_handle?: string;
}
export interface PortalSessionStore {
    init(): Promise<void>;
    insert(row: PortalSessionRow): Promise<void>;
    get(token: string): Promise<PortalSessionRow | null>;
    delete(token: string): Promise<void>;
    updateContext(token: string, context: Context, validatedAt: number, source?: string): Promise<void>;
    sweep(expiredBefore: number): Promise<void>;
    withRevalidationLock?<T>(token: string, callback: () => Promise<T>): Promise<T>;
}
export interface AsyncPortalAuthConfig extends Omit<PortalAuthConfig, "db"> {
    sessionStore: PortalSessionStore;
}
