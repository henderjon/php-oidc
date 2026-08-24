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
```

- `app-simple.php` builds an authorization redirect and requests a client-credentials token - including an `audience` extra param, a provider-specific extension the library does not model itself - with PKCE left at its default (`PkceMode::Disabled`).
- `app-pkce-required.php` builds a redirect with `PkceMode::Required`, shows the `code_challenge` it carries and the `code_verifier` sent back at token exchange, then simulates the verifier going missing (evicted from the cache, TTL expired, or the redirect and completion configs disagreeing) to show that Required fails closed before ever contacting the token endpoint.
- `app-pkce-optional.php` builds the same kind of redirect with `PkceMode::Optional`, then simulates the same missing verifier to show that Optional fails open instead - it still calls the token endpoint, just without a `code_verifier`.
- `app-url-policy.php` shows a normal discovery document succeeding, then simulates one that has been tampered with to point `token_endpoint` at a different host. Without `allowedHosts` set, that hijacked endpoint is still followed - `https` and a matching `issuer` are not by themselves a guarantee that every endpoint inside a discovery document is safe to call. With `allowedHosts` set to the hosts this integration actually expects, the same document is rejected before any request reaches the unexpected host.
- `app-algorithm-policy.php` shows an id_token signed HS256 being rejected under the default allowlist (RS256 only) - the token's own `alg` header never gets to pick its own verification strategy. Explicitly allowlisting HS256 with `withAllowedAlgorithms()` accepts the same kind of token for a confidential client, but a public client (no client secret) is refused HS256 outright, regardless of the allowlist.
- `app-tls-policy.php` uses `CurlHttpFetcher` directly (one of two examples that do - every other one fakes `HttpFetcherInterface`) to show that TLS verification is never something a normal request can opt out of, and that `disableTlsVerificationForLocalDevelopmentOnly` logs an alert on every single request while it is active, not just once - every request made while it is on is actively unauthenticated. It cannot demonstrate curl actually rejecting a bad certificate - this repository's dependencies do not include a test transport capable of serving an invalid/self-signed HTTPS endpoint.
- `app-response-limits.php` shows `CurlHttpFetcher`'s `maxResponseBytes` cap accepting a response under the limit and aborting one over it, with the error it logs when that happens - and, through the full client, a discovery response with an unexpected `Content-Type` (`text/html` instead of JSON) being rejected before its body is ever parsed.
- `app-claim-validation.php` shows a token missing the required `sub` or `exp` claim being rejected, and one whose `exp` is not after its own `iat` - all cases `firebase/php-jwt`'s own `JWT::decode()` does not catch, since it only checks `exp`/`iat`/`nbf` when they happen to be present. It also shows the separate, opt-in `maxTokenLifetimeSeconds` cap rejecting a token whose `exp - iat` is unreasonably long even though every claim is otherwise well-formed, and accepting one that fits within the cap.

A real application would replace `MockHttpFetcher` with an `HttpFetcherInterface` implementation that uses its HTTP client, and `InMemoryCache` with its PSR-16 cache adapter. The client configuration and factory wiring can remain the same.
