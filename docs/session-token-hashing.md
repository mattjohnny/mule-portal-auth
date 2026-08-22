# Session token hashing migration

The connector stores a SHA-256 digest of the Portal session bearer, never the
reusable raw token. The raw token is still what the browser holds as its cookie;
it hashes to the stored digest on every request. A digest copied out of the
database is inert as a bearer.

## Synchronous connector (`createPortalAuth`, better-sqlite3)

Hashing at rest landed in 0.2.3. Existing rows migrate automatically when the
connector starts (a one-time boot pass rewrites any raw token to its digest).

## Asynchronous connector (`createPortalAuthAsync`, app-supplied store)

Hashing at rest lands in 0.2.4. **Apps on 0.2.4 need no store code change** — the
connector hashes at the store boundary using only the existing
`AsyncSessionStore` methods (`insert` / `get` / `delete` / `updateContext`).
Before 0.2.4 the async path stored and looked up the raw token, and apps were
told to digest it themselves; that is no longer required and should not be done
in the app store (the connector would then double-hash).

There is **no boot-migration loop** for the async path: an app-supplied store has
no bulk-enumerate method in the interface. Instead:

- Legacy rows migrate **lazily, per row**, inside `getRow`: on a digest miss the
  connector falls back once to the raw-token row, authenticates it, and re-stores
  it under the digest (insert the digest row, then delete the raw row) before
  removing the raw copy. The migration is best-effort — a failed re-store still
  authenticates the request and simply retries on the next one; it never signs a
  valid session out.
- The connector `sweep` clears expired legacy rows that are never read again.

## Rules for shared session databases

Applications that read or update the session table directly must pass the bearer
through the exported `sessionTokenDigest()` helper before matching the `token`
column.

If two or more apps share **one** session database, upgrade them together: a
0.2.4 write is a digest, and an app still on ≤0.2.3 (async) looks up the raw
token, so it will miss that row and force a re-sign-in. Most apps have their own
session database, so this is rare — but shared-DB apps must all be on ≥0.2.4
before relying on hashing there.

A copied digest value is never accepted as a browser bearer: a bearer that
already looks like a digest (`sha256:` prefix) never gets the raw legacy
fallback.
