import type { Request } from "express";
export interface PortalLocation {
    id: number;
    key: string;
    name: string;
}
export interface Context {
    email: string;
    name: string;
    role: string;
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
}
export interface PortalAuthedRequest extends Request {
    portal?: Session;
}
export interface PortalAuthConfig {
    db: import("better-sqlite3").Database;
    appName: string;
    portalUrl?: string;
    sharedKey?: string;
    googleClientId?: string;
    allowedDomains?: string[];
    adminEmails?: string[];
    sessionTtlMs?: number;
    revalidateMs?: number;
}
