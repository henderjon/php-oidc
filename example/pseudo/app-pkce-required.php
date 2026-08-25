<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-pkce-required.php for the runnable version, and example/pseudo/README.md.

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;
use Oidc\PkceMode;

$config = (new OpenIDConnectClientConfig(
	clientId: 'my-client-id',
	clientSecret: 'my-client-secret',
	redirectUrl: 'https://app.example.com/oidc/callback',
	providerUrl: 'https://idp.example.com',
))->withPkce(PkceMode::Required);

// The cache suffix must come from the current user's session, not a static string -
// otherwise two users authenticating at once would overwrite each other's state, nonce,
// and code_verifier.
$client = (new OpenIDConnectClientFactory())->make($psr16Cache, $session->id);

// GET /oidc/login
// The redirect carries a code_challenge; the verifier that produced it is persisted
// alongside state/nonce, to travel back to the provider at token exchange.
$redirect = $client->buildAuthorizationCodeRedirect($config);
header("Location: {$redirect->url}");

// GET /oidc/callback
try {
	$result = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse($_GET));
} catch (AuthenticationFailedException $e) {
	// Required fails closed before the token endpoint is ever contacted if the verifier is
	// gone by completion time - evicted from the cache, TTL expired, or the redirect and
	// completion configs disagreeing.
	abort_login($e);
}
