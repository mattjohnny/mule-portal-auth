// Error names that are safe to emit in structured logs.
//
// Connector failures can carry AWS error objects whose messages contain secret
// names, ARNs, and account identifiers, and Portal failures can carry URLs
// holding session tokens. Logging only an allow-listed `name` keeps a
// diagnostic signal without ever putting that material into an app's log
// stream. Anything unrecognized collapses to the generic "Error".
const SAFE_ERROR_NAMES = new Set([
  "AbortError",
  "AccessDeniedException",
  "DecryptionFailure",
  "Error",
  "InternalFailure",
  "InternalServiceError",
  "InvalidParameterException",
  "InvalidRequestException",
  "NetworkingError",
  "RequestTimeout",
  "ResourceNotFoundException",
  "ServiceUnavailableException",
  "ThrottlingException",
  "TimeoutError",
  "TooManyRequestsException",
  "TypeError",
]);

export function safeErrorName(error: unknown): string {
  const candidate =
    error && typeof error === "object" && "name" in error
      ? String((error as { name?: unknown }).name || "")
      : "";
  return SAFE_ERROR_NAMES.has(candidate) ? candidate : "Error";
}
