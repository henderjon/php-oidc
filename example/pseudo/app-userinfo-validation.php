<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-userinfo-validation.php for the runnable version, and example/pseudo/README.md.

use Oidc\Exceptions\UserInfoRequestException;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;

$config = new OpenIDConnectClientConfig(
	clientId: 'my-client-id',
	clientSecret: 'my-client-secret',
	redirectUrl: 'https://app.example.com/oidc/callback',
	providerUrl: 'https://idp.example.com',
);

$client = (new OpenIDConnectClientFactory())->make($psr16Cache);

// GET /oidc/callback
$result           = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse($_GET));
$authenticatedSub = $result->claims->get('sub');

// $expectedSubject must be the sub Claim from the authenticated ID token - OpenID Connect
// Core 1.0 §5.3.2 requires the UserInfo response's sub to be verified against it, to guard
// against token substitution (an access token valid for a different session returning
// that session's claims under the caller's identity).
try {
	$userInfo = $client->fetchUserInfo($config, (string)$result->accessToken, $authenticatedSub);
} catch (UserInfoRequestException $e) {
	// Thrown for a wrong sub, or - only when the response is a signed JWT - a wrong iss or
	// aud. A plain JSON response carries neither requirement.
	abort_login($e);
}

$email = $userInfo->get('email');
