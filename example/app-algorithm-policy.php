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
	// HS256 needs at least 256 bits (32 bytes) of key material - firebase/php-jwt rejects
	// anything shorter on both sign and verify, so this is long enough for the HS256
	// scenarios below to reach this library's own algorithm policy instead of failing
	// earlier for an unrelated reason.
	clientSecret: 'example-secret-0123456789abcdef0123456789',
	redirectUrl: 'https://application.example.test/oidc/callback',
	providerUrl: $providerUrl,
	issuer: $providerUrl,
);

$cache = new InMemoryCache();
$client = (new OpenIDConnectClientFactory($http))->make($cache, 'example-app');

/**
 * Builds a redirect, signs an id_token with $secret using $alg for the nonce it carries,
 * registers it as the token endpoint's response, and completes the flow.
 */
function completeFlowWithSignedIdToken(
	OpenIDConnectClient $client,
	OpenIDConnectClientConfig $config,
	MockHttpFetcher $http,
	string $tokenEndpoint,
	string $providerUrl,
	string $alg,
	string $secret,
): void {
	$redirect = $client->buildAuthorizationCodeRedirect($config);
	parse_str((string)parse_url($redirect->url, PHP_URL_QUERY), $params);

	$idToken = JWT::encode([
		'iss' => $providerUrl,
		'sub' => 'user-1',
		'aud' => $config->clientId,
		'exp' => time() + 3600,
		'iat' => time(),
		'nonce' => $params['nonce'],
	], $secret, $alg);

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

// A provider that signs id_token with HS256 instead of the expected RS256 - maybe a
// misconfiguration, maybe an attacker who found a way to make the token endpoint respond with
// something it signed itself. Either way, the token's own alg header does not get to pick how
// it gets verified: the default allowlist is RS256 only, so this is rejected before the
// signature (valid or not) is even checked.
try {
	completeFlowWithSignedIdToken($client, $config, $http, $tokenEndpoint, $providerUrl, 'HS256', $config->clientSecret);
} catch (AuthenticationFailedException $e) {
	echo "Default allowlist (RS256 only) rejects an HS256 id_token: {$e->getMessage()}\n\n";
}

// Some providers genuinely do sign with HS256 for a confidential client (a real secret only
// the client and provider know) - that is a legitimate choice this config can opt into.
$hmacConfig = $config->withAllowedAlgorithms([ 'HS256' ]);

try {
	completeFlowWithSignedIdToken($client, $hmacConfig, $http, $tokenEndpoint, $providerUrl, 'HS256', $hmacConfig->clientSecret);
	echo "With HS256 explicitly allowlisted, the same kind of token is accepted.\n\n";
} catch (AuthenticationFailedException $e) {
	echo "Unexpected failure: {$e->getMessage()}\n\n";
}

// A public client (no client secret) has nothing to keep an HMAC signature honest - an
// attacker forging a token only needs to guess a key nobody else needs to know, since there
// is no real secret standing behind it. This is refused outright, even with HS256
// allowlisted - the attacker's guessed secret below never even gets checked.
$publicClientConfig = $hmacConfig->withClientSecret('');

try {
	completeFlowWithSignedIdToken($client, $publicClientConfig, $http, $tokenEndpoint, $providerUrl, 'HS256', 'attacker-guessed-secret-0123456789abcdef');
} catch (AuthenticationFailedException $e) {
	echo "A public client is refused HS256 outright, regardless of the allowlist: {$e->getMessage()}\n";
}
