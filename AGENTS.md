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

# Request authority

Keep `authorityMode: "request"` opt-in for both public connectors. Every
protected request must begin its own Portal lookup; neither TTL-zero nor an
earlier in-flight lookup satisfies that guarantee. Request results are local to
that request, never saved over later authority. Preserve cached-mode behavior
for existing apps. Strict claims and directory validation must fail closed.

`validRoles` accepts `finance` and `hr` (`ADDITIONAL_PORTAL_ROLES`) as
additional roles, and a present unknown role fails validation in both modes.
Before the Portal emits any other additional role, ship a connector release that
names it and have every consumer adopt that release. Add each role by name;
never make the check accept unknown roles.

Request mode makes one Portal `POST /api/context` per protected request. Each
call counts against the Portal's allowance of 60 a minute for that app, which is
per authenticated app since mule-portal#122 (README, "Request authority").
Never add retries, caching, or coalescing to request mode to stay under that
limit. More capacity has to come from the Portal side.

Run `test/authority-contract.test.js` against real localhost HTTP and Express,
and `scripts/verify-authority-mutations.mjs` after building emitted artifacts.
Do not run builds or integration tests concurrently with mutation scripts.
