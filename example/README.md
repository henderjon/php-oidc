# Example application

This example wires the library into a small application without contacting a real OpenID Connect provider.

`MockHttpFetcher` supplies canned discovery and token responses while recording requests. `InMemoryCache` provides the PSR-16 cache used to store authorization state and nonce values.

From the repository root, run:

```sh
composer install
php example/app.php
```

A real application would replace `MockHttpFetcher` with an `HttpFetcherInterface` implementation that uses its HTTP client, and `InMemoryCache` with its PSR-16 cache adapter. The client configuration and factory wiring can remain the same.
