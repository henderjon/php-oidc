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
// call.
//
// No allowedHosts is set on this config, and no allowAnyHost either - by default, a resolved
// endpoint still has to stay on the provider's own host (issuer, here) to be followed. The
// hijacked endpoint is rejected before any request reaches it.
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

try {
	$client->requestClientCredentialsToken($config, [ 'api.read' ]);
} catch (ProviderDiscoveryException $e) {
	echo "Hijacked endpoint on a different host, no allowlist needed: rejected before any request reached it ({$e->getMessage()})\n";
}
echo 'Requests actually sent: ' . count($http->requests) . " (only the discovery fetch)\n";
foreach ($http->requests as $request) {
	echo "- {$request['url']}\n";
}
echo "\n";

// A provider that legitimately splits its endpoints across several hosts (Google's
// token/JWKS/userinfo endpoints, for instance, each live on a different host than its
// issuer) needs to say so explicitly - either by listing every host it actually uses, or by
// opting out of the host check entirely with allowAnyHost. Demonstrated here with the same
// hijacked document: allowedHosts naming the attacker's host too would "fix" this the same
// way, but that is exactly the kind of explicit statement this default is designed to force
// a caller to make, rather than something to demonstrate as a good example.
$permissiveConfig = $config->withAllowAnyHost(true);
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
$token  = $client->requestClientCredentialsToken($permissiveConfig, [ 'api.read' ]);
echo "With allowAnyHost(true), the same hijacked endpoint is still followed: got \"{$token->accessToken}\"\n";
