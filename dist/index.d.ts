import type { Response, NextFunction } from "express";
import type { Context, PortalAuthConfig, PortalAuthedRequest, Session } from "./types.js";
export type { Context, PortalLocation, Session, PortalAuthConfig, PortalAuthedRequest, } from "./types.js";
export { PortalError } from "./portal.js";
export declare function createPortalAuth(config: PortalAuthConfig): {
    signInWithPortalToken: (ssoToken: string) => Promise<Session>;
    signInWithGoogle: (idToken: string) => Promise<Session>;
    logout: (token: string) => void;
    requireAuth: (req: PortalAuthedRequest, res: Response, next: NextFunction) => void;
    requireAdmin: (req: PortalAuthedRequest, res: Response, next: NextFunction) => void;
    revalidateIfStale: (session: Session) => Promise<Session | null>;
    getContext: (src: Session | PortalAuthedRequest) => Context | null;
    locationIds: (src: Session | Context | PortalAuthedRequest) => number[] | "all";
    locationKeys: (src: Session | Context | PortalAuthedRequest) => string[] | "all";
    isConfigured: () => boolean;
    isAdminEmail: (email: string) => boolean;
};
