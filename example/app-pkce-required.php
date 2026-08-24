<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/InMemoryCache.php';
require __DIR__ . '/MockHttpFetcher.php';

use Example\InMemoryCache;
use Example\MockHttpFetcher;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\FetchResponse;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;
use Oidc\PkceMode;

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
	pkce: PkceMode::Required,
);

// A real application shares one cache across every user, so the suffix must come from
// the current user's session (a cookie-backed session ID, for example) rather than a
// static string - otherwise two users authenticating at once would overwrite each
// other's state, nonce, and code_verifier. This stands in for that session ID.
$sessionId = bin2hex(random_bytes(8));

$cache = new InMemoryCache();
$client = (new OpenIDConnectClientFactory($http))->make($cache, $sessionId);

// A normal round trip: the redirect carries a code_challenge, and the verifier that
// produced it travels back to the provider on the token exchange.
$redirect = $client->buildAuthorizationCodeRedirect($config);
echo "Send the browser to:\n{$redirect->url}\n\n";

parse_str((string)parse_url($redirect->url, PHP_URL_QUERY), $params);
echo "code_challenge_method: {$params['code_challenge_method']}\n";
echo "code_challenge: {$params['code_challenge']}\n\n";

try {
	$client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
		'code' => 'mock-code',
		'state' => $params['state'],
	]));
} catch (AuthenticationFailedException $e) {
	// This mock provider never returns an id_token, so completion always fails past this
	// point. What this example is actually checking is what went out on the wire.
	echo "Completion failed as expected for this mock (no id_token): {$e->getMessage()}\n";
}

$tokenRequest = end($http->requests);
parse_str((string)$tokenRequest['body'], $tokenParams);
echo 'code_verifier sent with the token exchange: ' . (isset($tokenParams['code_verifier']) ? 'yes' : 'no') . "\n\n";

// Required mode fails closed if the verifier is gone by completion time (evicted from the
// cache, TTL expired, or the redirect and completion configs disagree). Simulate that
// directly instead of waiting for a real cache eviction - overwriting the flow entry in
// place (rather than deleting it outright) loses only the verifier, not the state/nonce
// match too, which is a different failure AuthorizationStateStore itself already logs.
$redirect = $client->buildAuthorizationCodeRedirect($config);
parse_str((string)parse_url($redirect->url, PHP_URL_QUERY), $params);
$flowKey = "henderjon.oidc.flow.{$sessionId}.{$params['state']}";
$flow = $cache->get($flowKey);
$cache->set($flowKey, [ 'nonce' => $flow['nonce'], 'code_verifier' => null ], 600);

$requestsBefore = count($http->requests);

try {
	$client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
		'code' => 'mock-code',
		'state' => $params['state'],
	]));
} catch (AuthenticationFailedException $e) {
	echo "Required mode failed closed with a missing verifier: {$e->getMessage()}\n";
}

echo 'Token endpoint was called during that failure: ' . (count($http->requests) > $requestsBefore ? 'yes' : 'no') . "\n";
