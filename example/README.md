# Example applications

These examples wire the library into a small application without contacting a real OpenID Connect provider.

`MockHttpFetcher` supplies canned discovery and token responses while recording requests. `InMemoryCache` provides the PSR-16 cache used to store authorization state, nonce, and PKCE code verifier values.

From the repository root, run:

```sh
composer install
php example/app-simple.php
php example/app-pkce-required.php
php example/app-pkce-optional.php
```

- `app-simple.php` builds an authorization redirect and requests a client-credentials token, with PKCE left at its default (`PkceMode::Disabled`).
- `app-pkce-required.php` builds a redirect with `PkceMode::Required`, shows the `code_challenge` it carries and the `code_verifier` sent back at token exchange, then simulates the verifier going missing (evicted from the cache, TTL expired, or the redirect and completion configs disagreeing) to show that Required fails closed before ever contacting the token endpoint.
- `app-pkce-optional.php` builds the same kind of redirect with `PkceMode::Optional`, then simulates the same missing verifier to show that Optional fails open instead - it still calls the token endpoint, just without a `code_verifier`.

A real application would replace `MockHttpFetcher` with an `HttpFetcherInterface` implementation that uses its HTTP client, and `InMemoryCache` with its PSR-16 cache adapter. The client configuration and factory wiring can remain the same.
