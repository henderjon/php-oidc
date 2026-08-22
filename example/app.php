<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/InMemoryCache.php';
require __DIR__ . '/MockHttpFetcher.php';

use Example\InMemoryCache;
use Example\MockHttpFetcher;
use Oidc\FetchResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;

$providerUrl = 'https://mock-idp.example.test';
$authorizationEndpoint = $providerUrl . '/oauth2/authorize';
$tokenEndpoint = $providerUrl . '/oauth2/token';
$discoveryEndpoint = $providerUrl . '/.well-known/openid-configuration';

$http = new MockHttpFetcher;
$http->respondTo($discoveryEndpoint, new FetchResponse(
	json_encode([
		'issuer' => $providerUrl,
		'authorization_endpoint' => $authorizationEndpoint,
		'token_endpoint' => $tokenEndpoint,
		'jwks_uri' => $providerUrl . '/oauth2/keys',
	]),
	200,
	'application/json',
));
$http->respondTo($tokenEndpoint, new FetchResponse(
	json_encode([
		'access_token' => 'mock-access-token',
		'token_type' => 'Bearer',
		'expires_in' => 3600,
	]),
	200,
	'application/json',
));

$config = new OpenIDConnectClientConfig(
	clientId: 'example-client',
	clientSecret: 'example-secret',
	redirectUrl: 'https://application.example.test/oidc/callback',
	providerUrl: $providerUrl,
	issuer: $providerUrl,
	scopes: [ 'profile', 'email' ],
);

$client = (new OpenIDConnectClientFactory($http))->make(new InMemoryCache(), 'example-app');

$redirect = $client->buildAuthorizationCodeRedirect($config);
echo "Send the browser to:\n{$redirect->url}\n\n";

$token = $client->requestClientCredentialsToken($config, [ 'api.read' ]);
echo "Mock client-credentials token: {$token->accessToken}\n\n";

echo "Recorded mock requests:\n";
foreach ($http->requests as $request) {
	echo "- {$request['url']}\n";
}
