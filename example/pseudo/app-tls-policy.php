<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-tls-policy.php for the runnable version, and example/pseudo/README.md.

use Oidc\CurlHttpFetcher;
use Oidc\OpenIDConnectClientFactory;

// TLS certificate and hostname verification is always on - there is no per-request way to
// turn it off, and no config value for it either. Every call this fetcher makes verifies.
$fetcher = new CurlHttpFetcher();
$client  = (new OpenIDConnectClientFactory($fetcher))->make($psr16Cache);

// The one narrow escape hatch, meant for local development only - a self-signed cert on a
// laptop, never a real deployment. Decided once for this fetcher instance's whole
// lifetime, with a name that cannot be mistaken for a normal setting.
$insecureFetcher = new CurlHttpFetcher(
	disableTlsVerificationForLocalDevelopmentOnly: true,
	logger: $localDevLogger,
);

// Every single request this fetcher makes while that flag is set logs an alert - not a
// one-time notice easy to lose in a log stream - because for as long as it is on, every
// request, including ones carrying bearer credentials, is actively unauthenticated.
