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
```

- `app-simple.php` builds an authorization redirect and requests a client-credentials token - including an `audience` extra param, a provider-specific extension the library does not model itself - with PKCE left at its default (`PkceMode::Disabled`).
- `app-pkce-required.php` builds a redirect with `PkceMode::Required`, shows the `code_challenge` it carries and the `code_verifier` sent back at token exchange, then simulates the verifier going missing (evicted from the cache, TTL expired, or the redirect and completion configs disagreeing) to show that Required fails closed before ever contacting the token endpoint.
- `app-pkce-optional.php` builds the same kind of redirect with `PkceMode::Optional`, then simulates the same missing verifier to show that Optional fails open instead - it still calls the token endpoint, just without a `code_verifier`.
- `app-url-policy.php` shows a normal discovery document succeeding, then simulates one that has been tampered with to point `token_endpoint` at a different host. Without `allowedHosts` set, that hijacked endpoint is still followed - `https` and a matching `issuer` are not by themselves a guarantee that every endpoint inside a discovery document is safe to call. With `allowedHosts` set to the hosts this integration actually expects, the same document is rejected before any request reaches the unexpected host.
- `app-algorithm-policy.php` shows an id_token signed HS256 being rejected under the default allowlist (RS256 only) - the token's own `alg` header never gets to pick its own verification strategy. Explicitly allowlisting HS256 with `withAllowedAlgorithms()` accepts the same kind of token for a confidential client, but a public client (no client secret) is refused HS256 outright, regardless of the allowlist.

A real application would replace `MockHttpFetcher` with an `HttpFetcherInterface` implementation that uses its HTTP client, and `InMemoryCache` with its PSR-16 cache adapter. The client configuration and factory wiring can remain the same.
