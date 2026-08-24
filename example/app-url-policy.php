<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/InMemoryCache.php';
require __DIR__ . '/MockHttpFetcher.php';

use Example\InMemoryCache;
use Example\MockHttpFetcher;
use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\FetchResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;

$providerUrl = 'https://mock-idp.example.test';
$discoveryEndpoint = $providerUrl . '/.well-known/openid-configuration';
$legitimateTokenEndpoint = $providerUrl . '/oauth2/token';
$hijackedTokenEndpoint = 'https://attacker.example.net/token';

$config = new OpenIDConnectClientConfig(
	clientId: 'example-client',
	clientSecret: 'example-secret',
	redirectUrl: 'https://application.example.test/oidc/callback',
	providerUrl: $providerUrl,
	issuer: $providerUrl,
);

// A normal, well-formed discovery document: https, and its own issuer matches the URL used
// to fetch it. The client-credentials request succeeds.
$http = new MockHttpFetcher;
$http->respondTo($discoveryEndpoint, new FetchResponse(
	json_encode([ 'issuer' => $providerUrl, 'token_endpoint' => $legitimateTokenEndpoint ]),
	200,
	'application/json',
));
$http->respondTo($legitimateTokenEndpoint, new FetchResponse(
	json_encode([ 'access_token' => 'mock-access-token', 'token_type' => 'Bearer', 'expires_in' => 3600 ]),
	200,
	'application/json',
));

$client = (new OpenIDConnectClientFactory($http))->make(new InMemoryCache());
$token  = $client->requestClientCredentialsToken($config, [ 'api.read' ]);
echo "Trusted provider: got a token ({$token->accessToken})\n\n";

// Now simulate a compromised or misconfigured provider: same issuer, but the document now
// points token_endpoint at a different host entirely - a network attacker tampering with the
// response, or a compromised backend serving hijacked configuration. The issuer check above
// does not catch this: it only checks the issuer field against the URL used to fetch
// discovery, not where the endpoints *inside* that document point. https and a matching
// issuer are not, by themselves, a guarantee that every endpoint in the document is safe to
// call - that is exactly what allowedHosts is for, demonstrated below.
$http = new MockHttpFetcher;
$http->respondTo($discoveryEndpoint, new FetchResponse(
	json_encode([ 'issuer' => $providerUrl, 'token_endpoint' => $hijackedTokenEndpoint ]),
	200,
	'application/json',
));
$http->respondTo($hijackedTokenEndpoint, new FetchResponse(
	json_encode([ 'access_token' => 'attacker-issued-token', 'token_type' => 'Bearer', 'expires_in' => 3600 ]),
	200,
	'application/json',
));

$client = (new OpenIDConnectClientFactory($http))->make(new InMemoryCache());
$token  = $client->requestClientCredentialsToken($config, [ 'api.read' ]);
echo "Without an allowlist, the hijacked endpoint is still followed: got \"{$token->accessToken}\"\n";
echo "Requests actually sent:\n";
foreach ($http->requests as $request) {
	echo "- {$request['url']}\n";
}
echo "\n";

// The same hijacked document, but this time the config also sets allowedHosts to the hosts
// this integration actually expects - useful for a multi-tenant app that resolves provider
// configuration per request and cannot fully trust it. Discovery itself still succeeds
// (mock-idp.example.test is allowed and the issuer still matches), but the endpoint it
// returns is not on the allowlist, so it is rejected before any request reaches it.
$restrictedConfig = $config->withAllowedHosts([ 'mock-idp.example.test' ]);
$http = new MockHttpFetcher;
$http->respondTo($discoveryEndpoint, new FetchResponse(
	json_encode([ 'issuer' => $providerUrl, 'token_endpoint' => $hijackedTokenEndpoint ]),
	200,
	'application/json',
));

$client = (new OpenIDConnectClientFactory($http))->make(new InMemoryCache());

try {
	$client->requestClientCredentialsToken($restrictedConfig, [ 'api.read' ]);
} catch (ProviderDiscoveryException $e) {
	echo "With allowedHosts set: rejected before any request reached it ({$e->getMessage()})\n";
}
echo 'Requests actually sent: ' . count($http->requests) . " (only the discovery fetch)\n";
foreach ($http->requests as $request) {
	echo "- {$request['url']}\n";
}
