<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/InMemoryCache.php';
require __DIR__ . '/MockHttpFetcher.php';
require __DIR__ . '/StdoutLogger.php';

use Example\InMemoryCache;
use Example\MockHttpFetcher;
use Example\StdoutLogger;
use Firebase\JWT\JWT;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\FetchResponse;
use Oidc\IncomingAuthorizationResponse;
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
	// anything shorter on both sign and verify.
	clientSecret: 'example-secret-0123456789abcdef0123456789',
	redirectUrl: 'https://application.example.test/oidc/callback',
	providerUrl: $providerUrl,
	issuer: $providerUrl,
	allowedAlgorithms: [ 'HS256' ],
);

$cache = new InMemoryCache();
$client = (new OpenIDConnectClientFactory($http, logger: new StdoutLogger))->make($cache, 'example-app');

// A normal login, same as every other example - this is what an app persists (idToken, claims,
// refreshToken) to redeem a refresh token later, possibly in an entirely different request.
$redirect = $client->buildAuthorizationCodeRedirect($config);
parse_str((string)parse_url($redirect->url, PHP_URL_QUERY), $params);

$idToken = JWT::encode([
	'iss' => $providerUrl,
	'sub' => 'user-1',
	'aud' => $config->clientId,
	'exp' => time() + 3600,
	'iat' => time(),
	'nonce' => $params['nonce'],
], $config->clientSecret, 'HS256');

$http->respondTo($tokenEndpoint, new FetchResponse(
	json_encode([
		'access_token' => 'mock-access-token',
		'refresh_token' => 'mock-refresh-token',
		'token_type' => 'Bearer',
		'expires_in' => 3600,
		'id_token' => $idToken,
	]),
	200,
	'application/json',
));

$loginResult = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
	'code' => 'mock-code',
	'state' => $params['state'],
]));

echo "Logged in: sub={$loginResult->claims->get('sub')}, expires_in={$loginResult->expiresIn}\n\n";

// Later - a different request, the access token has expired. OpenID Connect Core 1.0 §12.2:
// the refresh response might not carry a new id_token at all - when it does not, the original
// ID token and claims are still valid and carried forward unchanged.
$http->respondTo($tokenEndpoint, new FetchResponse(
	json_encode([
		'access_token' => 'mock-refreshed-access-token',
		'refresh_token' => 'mock-rotated-refresh-token',
		'expires_in' => 3600,
	]),
	200,
	'application/json',
));

$refreshed = $client->refresh($config, (string)$loginResult->refreshToken, $loginResult->idToken, $loginResult->claims);
echo "Refreshed with no new id_token: sub={$refreshed->claims->get('sub')} (carried forward), access_token={$refreshed->accessToken}\n";
echo "The refresh token was rotated - the app must persist the new one: {$refreshed->refreshToken}\n\n";

// The provider can also return a new id_token on refresh. §12.2 requires its iss/sub/aud to
// match the original - here they do, so this succeeds.
$newIdToken = JWT::encode([
	'iss' => $providerUrl,
	'sub' => 'user-1',
	'aud' => $config->clientId,
	'exp' => time() + 3600,
	'iat' => time(),
], $config->clientSecret, 'HS256');

$http->respondTo($tokenEndpoint, new FetchResponse(
	json_encode([ 'access_token' => 'mock-refreshed-access-token-2', 'id_token' => $newIdToken ]),
	200,
	'application/json',
));

$refreshedWithNewIdToken = $client->refresh($config, (string)$refreshed->refreshToken, $refreshed->idToken, $refreshed->claims);
echo "Refreshed with a matching new id_token: sub={$refreshedWithNewIdToken->claims->get('sub')}\n\n";

// A new id_token naming a different subject than the original authentication must be rejected -
// otherwise a compromised or misconfigured provider could hand back a different user's identity
// under this session's refresh token.
$mismatchedIdToken = JWT::encode([
	'iss' => $providerUrl,
	'sub' => 'someone-elses-subject',
	'aud' => $config->clientId,
	'exp' => time() + 3600,
	'iat' => time(),
], $config->clientSecret, 'HS256');

$http->respondTo($tokenEndpoint, new FetchResponse(
	json_encode([ 'access_token' => 'mock-refreshed-access-token-3', 'id_token' => $mismatchedIdToken ]),
	200,
	'application/json',
));

try {
	$client->refresh($config, (string)$refreshedWithNewIdToken->refreshToken, $refreshedWithNewIdToken->idToken, $refreshedWithNewIdToken->claims);
} catch (AuthenticationFailedException $e) {
	echo "A refreshed id_token naming a different subject is rejected: {$e->getMessage()}\n";
}
