# Example applications

These examples wire the library into a small application without contacting a real OpenID Connect provider.

`MockHttpFetcher` supplies canned discovery and token responses while recording requests. `InMemoryCache` provides the PSR-16 cache used to store authorization state, nonce, and PKCE code verifier values.

From the repository root, run:

```sh
composer install
php example/app-simple.php
php example/app-pkce-required.php
php example/app-pkce-optional.php
php example/app-url-policy.php
php example/app-algorithm-policy.php
php example/app-tls-policy.php
php example/app-response-limits.php
php example/app-claim-validation.php
php example/app-audience-validation.php
php example/app-userinfo-validation.php
php example/app-refresh-token.php
```

- `app-simple.php` builds an authorization redirect and requests a client-credentials token - including an `audience` extra param, a provider-specific extension the library does not model itself - with PKCE left at its default (`PkceMode::Disabled`).
- `app-pkce-required.php` builds a redirect with `PkceMode::Required`, shows the `code_challenge` it carries and the `code_verifier` sent back at token exchange, then simulates the verifier going missing (evicted from the cache, TTL expired, or the redirect and completion configs disagreeing) to show that Required fails closed before ever contacting the token endpoint.
- `app-pkce-optional.php` builds the same kind of redirect with `PkceMode::Optional`, then simulates the same missing verifier to show that Optional fails open instead - it still calls the token endpoint, just without a `code_verifier`.
- `app-url-policy.php` shows a normal discovery document succeeding, then simulates one that has been tampered with to point `token_endpoint` at a different host. With no `allowedHosts` set, that hijacked endpoint is rejected before any request reaches it - by default, a resolved endpoint has to stay on the provider's own host (`issuer`, or `providerUrl` when `issuer` is not set); `https` and a matching `issuer` are not by themselves a guarantee that every endpoint inside a discovery document is safe to call. It closes by showing `withAllowAnyHost(true)` opting back out of that default, for a provider that legitimately splits its endpoints across several hosts (Google's token/JWKS/userinfo endpoints, for instance, each live on a different host than its issuer) - the same hijacked endpoint is followed once that opt-out is set, which is exactly why it needs to be an explicit statement rather than the default.
- `app-algorithm-policy.php` shows an id_token signed HS256 being rejected under the default allowlist (RS256 only) - the token's own `alg` header never gets to pick its own verification strategy. Explicitly allowlisting HS256 with `withAllowedAlgorithms()` accepts the same kind of token for a confidential client, but a public client (no client secret) is refused HS256 outright, regardless of the allowlist.
- `app-tls-policy.php` uses `CurlHttpFetcher` directly (one of two examples that do - every other one fakes `HttpFetcherInterface`) to show that TLS verification is never something a normal request can opt out of, and that `disableTlsVerificationForLocalDevelopmentOnly` logs an alert on every single request while it is active, not just once - every request made while it is on is actively unauthenticated. It cannot demonstrate curl actually rejecting a bad certificate - this repository's dependencies do not include a test transport capable of serving an invalid/self-signed HTTPS endpoint.
- `app-response-limits.php` shows `CurlHttpFetcher`'s `maxResponseBytes` cap accepting a response under the limit and aborting one over it, with the error it logs when that happens - and, through the full client, a discovery response with an unexpected `Content-Type` (`text/html` instead of JSON) being rejected before its body is ever parsed.
- `app-claim-validation.php` shows a token missing the required `sub` or `exp` claim being rejected, and one whose `exp` is not after its own `iat` - all cases `firebase/php-jwt`'s own `JWT::decode()` does not catch, since it only checks `exp`/`iat`/`nbf` when they happen to be present. It also shows the separate, opt-in `maxTokenLifetimeSeconds` cap rejecting a token whose `exp - iat` is unreasonably long even though every claim is otherwise well-formed, and accepting one that fits within the cap.
- `app-audience-validation.php` shows a token naming an audience beyond this client rejected outright, then the same shape accepted once that second audience is explicitly trusted via `withAudience()` - confirming aud contains this client is not enough on its own (OpenID Connect Core 1.0 §3.1.3.7 step 3 is two separate MUSTs). It then shows `withAllowUntrustedAudiences(true)` opting back out of that second half entirely, for a caller that cannot safely declare every audience a provider's tokens might carry - and logs an `alert`, not silently, since an untrusted value actually being let through is exactly the case that opt-out exists for. It also shows a malformed `aud` entry (a non-string value mixed into an otherwise well-formed array) being rejected outright by default rather than silently discarded.

- `app-userinfo-validation.php` completes a normal authorization code flow, then shows `fetchUserInfo()` validating the userinfo response against the authenticated ID token: a valid signed response is accepted, one with the wrong `iss` or `aud` is rejected (OpenID Connect Core 1.0 §5.3.2 requires both, but only "if signed"), one naming a different `sub` is rejected, and one missing `sub` entirely is rejected (§5.3.2's sub requirement is unconditional). It closes by showing a plain JSON response with no `iss`/`aud` at all still accepted once its `sub` matches, confirming those two checks do not apply outside the signed case.

- `app-refresh-token.php` completes a normal authorization code flow, then shows `refresh()`: a refresh response with no new `id_token` at all carries the original ID token and claims forward unchanged (OpenID Connect Core 1.0 §12.2 permits the response to omit one); a refresh response with a matching new `id_token` is accepted; and one naming a different subject than the original authentication is rejected. It also shows `expiresIn` on `AuthenticationResult` and that a rotated `refresh_token` in the response is exactly what the app must persist going forward.

A real application would replace `MockHttpFetcher` with an `HttpFetcherInterface` implementation that uses its HTTP client, and `InMemoryCache` with its PSR-16 cache adapter. The client configuration and factory wiring can remain the same.
