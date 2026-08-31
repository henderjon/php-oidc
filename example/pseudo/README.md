# Pseudo-code examples

These are not runnable. Each file mirrors one script in `example/`, but strips out the mock
HTTP fetcher, JWT signing, and `echo` narration that make the real scripts runnable in
isolation, leaving only how a real application would call the library: a login route, a
callback route, a background job.

Read these to see the shape of a real integration. Run the scripts in `example/` to see the
library's behavior actually verified against a fake provider.

- `app-simple.php` - build a login redirect; request a client-credentials token with a
  provider-specific `extraParams` entry.
- `app-pkce-required.php` - `PkceMode::Required`; a login route and a callback route, with
  the callback failing closed if the PKCE verifier is gone by completion time.
- `app-pkce-optional.php` - the same shape with `PkceMode::Optional`, which proceeds instead
  of failing closed.
- `app-url-policy.php` - the default host restriction on discovered endpoints, and
  `withAllowAnyHost(true)` for a provider that splits endpoints across hosts.
- `app-algorithm-policy.php` - the default RS256-only allowlist, `withAllowedAlgorithms()`
  for a provider signing HS256, and why a public client refuses HS256 regardless.
- `app-tls-policy.php` - `CurlHttpFetcher`'s always-on TLS verification, and the
  local-development-only escape hatch.
- `app-response-limits.php` - `CurlHttpFetcher`'s `maxResponseBytes` cap, and discovery's
  Content-Type check.
- `app-claim-validation.php` - required-claim and claim-sanity failures, and the opt-in
  `maxTokenLifetimeSeconds` cap.
- `app-audience-validation.php` - the two halves of `aud` validation, `withAudience()`, and
  `withAllowUntrustedAudiences()`.
- `app-userinfo-validation.php` - `fetchUserInfo()`'s subject check, and the extra
  issuer/audience checks that only apply to a signed response.
- `app-refresh-token.php` - the proactive path: checking `expiresIn` before calling the
  resource server and refreshing ahead of time, persisting a session across an access-token
  expiry, and `refresh()`'s subject validation and refresh-token rotation.
- `app-refresh-token-reactive.php` - the reactive path: calling the resource server first,
  refreshing only on a 401, retrying once, and never looping on a second 401. This is the
  path actually load-bearing for correctness; the proactive check is an optimization on top
  of it, not a replacement, since a provider can revoke a token early for reasons that have
  nothing to do with its nominal `expires_in`.
- `app-exception-handling.php` - one catch block per exception type (login route, callback
  route, a client-credentials call, `fetchUserInfo()`), each using that type's own discrete
  getters - `getIdToken()`, `getHttpStatus()`/`getRawBody()` - alongside the `getState()`
  every one of them carries. Has no runnable counterpart in `example/` - it exists purely to
  show every getter side by side.
- `app-exception-type-narrowing.php` - the same set of failures caught with a single
  `OpenIDConnectException` clause instead, narrowed with `instanceof` to reach whichever
  discrete getters a given subtype actually carries. Also has no runnable counterpart.
