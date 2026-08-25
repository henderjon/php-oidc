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
	// anything shorter on both sign and verify.
	clientSecret: 'example-secret-0123456789abcdef0123456789',
	redirectUrl: 'https://application.example.test/oidc/callback',
	providerUrl: $providerUrl,
	issuer: $providerUrl,
	allowedAlgorithms: [ 'HS256' ],
);

$cache = new InMemoryCache();
$client = (new OpenIDConnectClientFactory($http, logger: new StdoutLogger))->make($cache, 'example-app');

/**
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

// OpenID Connect Core 1.0 §3.1.3.7 step 3 is two separate requirements: aud must contain this
// client, AND it must not contain anything this client does not trust. Confirming only the
// first half - the old behavior here - let a token naming an unexpected second audience
// through unnoticed.
try {
	completeFlowWithClaims($client, $config, $http, $tokenEndpoint, [
		...$validClaims,
		'aud' => [ $config->clientId, 'an-unexpected-second-audience' ],
	]);
} catch (AuthenticationFailedException $e) {
	echo "A token naming an untrusted extra audience is rejected: {$e->getMessage()}\n\n";
}

// A caller that genuinely intends to accept a second audience states that explicitly via
// OpenIDConnectClientConfig::$audience, rather than the extra value simply passing unnoticed.
$multiAudienceConfig = $config->withAudience([ $config->clientId, 'a-trusted-resource-audience' ]);
completeFlowWithClaims($client, $multiAudienceConfig, $http, $tokenEndpoint, [
	...$validClaims,
	'aud' => [ $config->clientId, 'a-trusted-resource-audience' ],
]);
echo "The same shape of token is accepted once that second audience is explicitly trusted.\n\n";

// Some integrations cannot safely enumerate every audience a provider's tokens might
// legitimately carry - allowUntrustedAudiences opts back out of that half of the check
// entirely, keeping only the requirement that this client's own expected value be present.
$permissiveConfig = $config->withAllowUntrustedAudiences(true);
completeFlowWithClaims($client, $permissiveConfig, $http, $tokenEndpoint, [
	...$validClaims,
	'aud' => [ $config->clientId, 'an-audience-this-config-never-declared' ],
]);
echo "With allowUntrustedAudiences(true), the same token is accepted without declaring anything.\n\n";

// azp is genuinely optional - most providers never send it - but §3.1.3.7 step 5 says that
// when it IS present, it SHOULD equal this client's own client_id. A mismatch here is a
// meaningful signal even though the base spec never makes checking it a MUST.
try {
	completeFlowWithClaims($client, $config, $http, $tokenEndpoint, [
		...$validClaims,
		'azp' => 'a-different-client-id',
	]);
} catch (AuthenticationFailedException $e) {
	echo "A token whose azp does not match this client's own client_id is rejected: {$e->getMessage()}\n";
}
