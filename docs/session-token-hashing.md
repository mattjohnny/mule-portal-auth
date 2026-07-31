# Session token hashing migration

Version 0.2.3 stores SHA-256 digests instead of reusable Portal session bearer
tokens. Existing rows migrate automatically when the connector starts.

Applications using only the connector API need no code changes. Applications
that read or update `portal_sessions` directly must pass the bearer through the
exported `sessionTokenDigest()` helper before matching the `token` column.

Upgrade all writers for a shared session database together. A 0.2.3 connector
can read one legacy raw row and migrate it, but copied digest values are never
accepted as browser bearer tokens.
