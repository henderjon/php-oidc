<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-refresh-token.php for the runnable version, and example/pseudo/README.md.

use Oidc\Claims;
use Oidc\Exceptions\AuthenticationFailedException;
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

// GET /oidc/callback - what the app persists to redeem a refresh token later, possibly in
// an entirely different request.
$result = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse($_GET));

save_session([
	'id_token'      => $result->idToken,
	'claims'        => $result->claims->all(),
	'access_token'  => $result->accessToken,
	'refresh_token' => $result->refreshToken,
	// Convert to an absolute timestamp the moment it is received - the relative seconds
	// decay the instant time passes.
	'expires_at'    => time() + $result->expiresIn,
]);

// Later - a different request, the access token has expired.
$session = load_session();

if( time() >= $session['expires_at'] ) {
	try {
		$refreshed = $client->refresh(
			$config,
			$session['refresh_token'],
			$session['id_token'],
			new Claims($session['claims']),
		);
	} catch (AuthenticationFailedException $e) {
		// A refreshed id_token naming a different subject than the original authentication
		// is rejected - a compromised or misconfigured provider cannot hand back a
		// different user's identity under this session's refresh token.
		force_logout($e);
	}

	// OpenID Connect Core 1.0 §12.2: the response might not carry a new id_token at all -
	// when it does not, $refreshed->idToken and ->claims carry the original ones forward
	// unchanged.
	save_session([
		'id_token'      => $refreshed->idToken,
		'claims'        => $refreshed->claims->all(),
		'access_token'  => $refreshed->accessToken,
		// A rotated refresh_token is exactly what must be persisted going forward - do not
		// keep reusing the old one.
		'refresh_token' => $refreshed->refreshToken,
		'expires_at'    => time() + $refreshed->expiresIn,
	]);
}
