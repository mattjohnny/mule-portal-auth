// The consumer-side check SEC-13 enables must compile against the emitted
// declarations under --strict, with the field optional (absent on most errors).
import { PortalCredentialError, PortalError } from "../../dist/index.js";

export function signInThrottled(error: unknown): boolean {
  return error instanceof PortalError && !(error instanceof PortalCredentialError) && error.portalStatus === 429;
}

export function backOffSeconds(error: PortalError): number | undefined {
  const status: number | undefined = error.portalStatus;
  return status === 429 ? error.retryAfterSeconds : undefined;
}

// Existing positional construction still compiles, with or without the new field.
export const legacy = new PortalError("synthetic", false, true, { retryAfterSeconds: 5 });
export const withStatus = new PortalError("synthetic", false, false, { portalStatus: 429 });
