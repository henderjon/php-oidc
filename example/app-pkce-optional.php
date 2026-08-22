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
	pkce: PkceMode::Optional,
);

// A real application shares one cache across every user, so the suffix must come from
// the current user's session (a cookie-backed session ID, for example) rather than a
// static string - otherwise two users authenticating at once would overwrite each
// other's state, nonce, and code_verifier. This stands in for that session ID.
$sessionId = bin2hex(random_bytes(8));

$cache = new InMemoryCache();
$client = (new OpenIDConnectClientFactory($http))->make($cache, $sessionId);

// Optional still sends a code_challenge on every redirect, same as Required - the two
// modes only differ in what happens if the verifier goes missing by completion time.
$redirect = $client->buildAuthorizationCodeRedirect($config);
echo "Send the browser to:\n{$redirect->url}\n\n";

parse_str((string)parse_url($redirect->url, PHP_URL_QUERY), $params);
echo "code_challenge_method: {$params['code_challenge_method']}\n";
echo "code_challenge: {$params['code_challenge']}\n\n";

// Simulate the same eviction as the Required example (evicted from the cache, TTL
// expired, or the redirect and completion configs disagree). Optional proceeds anyway
// and lets the token endpoint decide, instead of failing before ever contacting it.
$cache->delete("henderjon.oidc.code_verifier.{$sessionId}");

try {
	$client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
		'code' => 'mock-code',
		'state' => $params['state'],
	]));
} catch (AuthenticationFailedException $e) {
	// This mock provider never returns an id_token, so completion still fails - but not
	// because of the missing verifier. Compare this to the Required example, which fails
	// closed on the missing verifier before ever reaching the token endpoint.
	echo "Completion still failed, but only because this mock never returns an id_token: {$e->getMessage()}\n";
}

$tokenRequest = end($http->requests);
parse_str((string)$tokenRequest['body'], $tokenParams);
echo 'code_verifier sent with the token exchange: ' . (isset($tokenParams['code_verifier']) ? 'yes' : 'no') . "\n";
