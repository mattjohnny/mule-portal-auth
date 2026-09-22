# Portal transport

When changing Portal transport, preserve the shared boundary for synchronous and
asynchronous connectors: production (`NODE_ENV=production`) or any nonempty
`RENDER` requires HTTPS before credential-bearing requests. HTTP remains usable
outside those environments. Configuration failures are not Portal outages.

Never follow redirects for SSO, context, directory or background credential-proof
requests, including legacy authentication. A redirect must not replay a body,
forward credentials, or prove a pending credential.

After a transport change, build the committed `dist` and run the real transport
tests and `node scripts/verify-c2-mutations.mjs` without concurrent builds. The
localhost TLS key under `test/fixtures` is a disposable public test fixture; its
certificate is trusted only by the spawned test process. Do not disable TLS
verification to run these tests.

Package review/merge does not establish consumer adoption. Verify each adopted
lockfile's resolved commit, installed artifact and consumer behavior separately.
