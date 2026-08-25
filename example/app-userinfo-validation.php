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
use Oidc\Exceptions\UserInfoRequestException;
use Oidc\FetchResponse;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;

$providerUrl = 'https://mock-idp.example.test';
$authorizationEndpoint = $providerUrl . '/oauth2/authorize';
$tokenEndpoint = $providerUrl . '/oauth2/token';
$userinfoEndpoint = $providerUrl . '/oauth2/userinfo';
$discoveryEndpoint = $providerUrl . '/.well-known/openid-configuration';

$http = new MockHttpFetcher;
$http->respondTo($discoveryEndpoint, new FetchResponse(
	json_encode([
		'issuer' => $providerUrl,
		'authorization_endpoint' => $authorizationEndpoint,
		'token_endpoint' => $tokenEndpoint,
		'userinfo_endpoint' => $userinfoEndpoint,
		'jwks_uri' => $providerUrl . '/oauth2/keys',
	]),
	200,
	'application/json',
));

$config = new OpenIDConnectClientConfig(
	clientId: 'example-client',
	// HS256 needs at least 256 bits (32 bytes) of key material - firebase/php-jwt rejects
	// anything shorter on both sign and verify. Signing the UserInfo response with the same
	// secret keeps this example free of an RSA key pair and a JWKS document.
	clientSecret: 'example-secret-0123456789abcdef0123456789',
	redirectUrl: 'https://application.example.test/oidc/callback',
	providerUrl: $providerUrl,
	issuer: $providerUrl,
	allowedAlgorithms: [ 'HS256' ],
);

$cache = new InMemoryCache();
$client = (new OpenIDConnectClientFactory($http, logger: new StdoutLogger))->make($cache, 'example-app');

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
	json_encode([ 'access_token' => 'mock-access-token', 'token_type' => 'Bearer', 'expires_in' => 3600, 'id_token' => $idToken ]),
	200,
	'application/json',
));

$result = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
	'code' => 'mock-code',
	'state' => $params['state'],
]));

$authenticatedSubject = (string)$result->claims->get('sub');

/**
 * @param array<string,mixed> $claims
 */
function signedUserInfo( array $claims, OpenIDConnectClientConfig $config ): string {
	return JWT::encode($claims, $config->clientSecret, 'HS256');
}

$validSignedClaims = [
	'iss' => $providerUrl,
	'sub' => 'user-1',
	'aud' => $config->clientId,
];

// OpenID Connect Core 1.0 §5.3.2: the sub Claim in the UserInfo Response MUST be verified to
// exactly match the sub Claim in the ID Token - this defends against token substitution, where
// an access token valid for a different session returns that session's claims under the
// caller's identity.
$http->respondTo($userinfoEndpoint, new FetchResponse(signedUserInfo($validSignedClaims, $config), 200, 'application/jwt'));
$claims = $client->fetchUserInfo($config, (string)$result->accessToken, $authenticatedSubject);
echo "A valid signed UserInfo response, with a matching sub, is accepted: sub={$claims->get('sub')}\n\n";

// §5.3.2: "If signed, the UserInfo Response MUST contain the Claims iss and aud... The iss
// value MUST be the OP's Issuer Identifier URL."
$http->respondTo($userinfoEndpoint, new FetchResponse(signedUserInfo([ ...$validSignedClaims, 'iss' => 'https://attacker.example.test' ], $config), 200, 'application/jwt'));
try {
	$client->fetchUserInfo($config, (string)$result->accessToken, $authenticatedSubject);
} catch (UserInfoRequestException $e) {
	echo "A signed UserInfo response with the wrong issuer is rejected: {$e->getMessage()}\n\n";
}

// §5.3.2: "The aud value MUST be or include the RP's Client ID value."
$http->respondTo($userinfoEndpoint, new FetchResponse(signedUserInfo([ ...$validSignedClaims, 'aud' => 'someone-elses-client-id' ], $config), 200, 'application/jwt'));
try {
	$client->fetchUserInfo($config, (string)$result->accessToken, $authenticatedSubject);
} catch (UserInfoRequestException $e) {
	echo "A signed UserInfo response with the wrong audience is rejected: {$e->getMessage()}\n\n";
}

// §5.3.2's sub match: a UserInfo response about a different subject than the one this access
// token was issued for must never be handed back as if it were the caller's own claims.
$http->respondTo($userinfoEndpoint, new FetchResponse(signedUserInfo([ ...$validSignedClaims, 'sub' => 'someone-elses-subject' ], $config), 200, 'application/jwt'));
try {
	$client->fetchUserInfo($config, (string)$result->accessToken, $authenticatedSubject);
} catch (UserInfoRequestException $e) {
	echo "A signed UserInfo response naming a different subject is rejected: {$e->getMessage()}\n\n";
}

// §5.3.2: "The sub (subject) Claim MUST always be returned in the UserInfo Response."
$missingSubjectClaims = $validSignedClaims;
unset($missingSubjectClaims['sub']);
$http->respondTo($userinfoEndpoint, new FetchResponse(signedUserInfo($missingSubjectClaims, $config), 200, 'application/jwt'));
try {
	$client->fetchUserInfo($config, (string)$result->accessToken, $authenticatedSubject);
} catch (UserInfoRequestException $e) {
	echo "A signed UserInfo response missing sub entirely is rejected: {$e->getMessage()}\n\n";
}

// §5.3.2 only requires iss/aud "if signed" - a plain JSON UserInfo response carries neither,
// and must still be accepted once its sub matches.
$http->respondTo($userinfoEndpoint, new FetchResponse(json_encode([ 'sub' => 'user-1', 'email' => 'user-1@example.test' ]), 200, 'application/json'));
$claims = $client->fetchUserInfo($config, (string)$result->accessToken, $authenticatedSubject);
echo "A plain JSON UserInfo response, with no iss/aud at all, is accepted once its sub matches: email={$claims->get('email')}\n";
