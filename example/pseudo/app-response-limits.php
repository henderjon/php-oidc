<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-response-limits.php for the runnable version, and example/pseudo/README.md.

use Oidc\CurlHttpFetcher;
use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;

// maxResponseBytes bounds the response body regardless of connection speed - a fast
// connection could otherwise still push an unbounded amount of data within the timeout.
$fetcher = new CurlHttpFetcher(maxResponseBytes: 5 * 1024 * 1024);
$client  = (new OpenIDConnectClientFactory($fetcher))->make($psr16Cache);

$config = new OpenIDConnectClientConfig(
	clientId: 'my-client-id',
	clientSecret: 'my-client-secret',
	redirectUrl: 'https://app.example.com/oidc/callback',
	providerUrl: 'https://idp.example.com',
);

try {
	$token = $client->requestClientCredentialsToken($config);
} catch (HttpTransportException $e) {
	// A response over the cap is aborted mid-transfer, not buffered in full before being
	// rejected after the fact.
	log_and_fail($e);
}

// A discovery response is also checked by Content-Type before its body is ever parsed as
// JSON - a provider (or an intermediary) returning an HTML error page instead of a real
// discovery document is rejected outright rather than fed to json_decode().
try {
	$redirect = $client->buildAuthorizationCodeRedirect($config);
} catch (ProviderDiscoveryException $e) {
	log_and_fail($e);
}
