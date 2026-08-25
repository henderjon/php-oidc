<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/InMemoryCache.php';
require __DIR__ . '/MockHttpFetcher.php';

use Example\InMemoryCache;
use Example\MockHttpFetcher;
use Firebase\JWT\JWT;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\FetchResponse;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClient;
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

$config = new OpenIDConnectClientConfig(
	clientId: 'example-client',
	clientSecret: 'example-secret-0123456789abcdef0123456789',
	redirectUrl: 'https://application.example.test/oidc/callback',
	providerUrl: $providerUrl,
	issuer: $providerUrl,
	allowedAlgorithms: [ 'HS256' ],
);

$cache = new InMemoryCache();
$client = (new OpenIDConnectClientFactory($http))->make($cache, 'example-app');

/**
 * Builds a redirect, signs an id_token carrying exactly $claims (no defaults filled in, unlike
 * the test fixtures) plus the nonce the redirect generated, and completes the flow.
 *
 * @param array<string,mixed> $claims
 */
function completeFlowWithClaims( OpenIDConnectClient $client, OpenIDConnectClientConfig $config, MockHttpFetcher $http, string $tokenEndpoint, array $claims ): void {
	$redirect = $client->buildAuthorizationCodeRedirect($config);
	parse_str((string)parse_url($redirect->url, PHP_URL_QUERY), $params);

	$idToken = JWT::encode([ ...$claims, 'nonce' => $params['nonce'] ], $config->clientSecret, 'HS256');

	$http->respondTo($tokenEndpoint, new FetchResponse(
		json_encode([ 'access_token' => 'mock-access-token', 'token_type' => 'Bearer', 'expires_in' => 3600, 'id_token' => $idToken ]),
		200,
		'application/json',
	));

	$client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
		'code' => 'mock-code',
		'state' => $params['state'],
	]));
}

$validClaims = [
	'iss' => $providerUrl,
	'sub' => 'user-1',
	'aud' => $config->clientId,
	'exp' => time() + 3600,
	'iat' => time(),
];

// firebase/php-jwt's own JWT::decode() only checks exp/iat/nbf when they are present - a
// token that omits them entirely sails through with no check at all. This library requires
// them explicitly instead of trusting that every provider will always send them.
try {
	completeFlowWithClaims($client, $config, $http, $tokenEndpoint, [ ...$validClaims, 'sub' => null ]);
} catch (AuthenticationFailedException $e) {
	echo "A token missing the required sub claim is rejected: {$e->getMessage()}\n\n";
}

try {
	completeFlowWithClaims($client, $config, $http, $tokenEndpoint, [ ...$validClaims, 'exp' => null ]);
} catch (AuthenticationFailedException $e) {
	echo "A token missing the required exp claim is rejected: {$e->getMessage()}\n\n";
}

// exp equal to (or before) iat is nonsensical regardless of whether either claim's presence
// requirement was met - a token cannot expire at or before the moment it says it was issued.
// Both claims sit at exactly "now" here (neither in the future nor expired), so this is
// caught by ClaimsValidator's own check, not firebase/php-jwt's separate exp/iat-vs-now ones.
try {
	completeFlowWithClaims($client, $config, $http, $tokenEndpoint, [ ...$validClaims, 'iat' => time(), 'exp' => time() ]);
} catch (AuthenticationFailedException $e) {
	echo "A token whose exp is not after its own iat is rejected: {$e->getMessage()}\n\n";
}

// maxTokenLifetimeSeconds is a separate, opt-in cap on exp - iat: even a token with well-formed,
// correctly-ordered claims can still claim an unreasonably long validity window.
$boundedConfig = $config->withMaxTokenLifetimeSeconds(300);

try {
	completeFlowWithClaims($client, $boundedConfig, $http, $tokenEndpoint, $validClaims);
} catch (AuthenticationFailedException $e) {
	echo "With maxTokenLifetimeSeconds(300), a token with a one-hour exp - iat is rejected: {$e->getMessage()}\n\n";
}

completeFlowWithClaims($client, $boundedConfig, $http, $tokenEndpoint, [ ...$validClaims, 'exp' => time() + 300 ]);
echo "The same cap accepts a token whose exp - iat fits within it.\n";
