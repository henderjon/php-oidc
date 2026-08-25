<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-algorithm-policy.php for the runnable version, and example/pseudo/README.md.

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;

$config = new OpenIDConnectClientConfig(
	clientId: 'my-client-id',
	clientSecret: 'my-client-secret',
	redirectUrl: 'https://app.example.com/oidc/callback',
	providerUrl: 'https://idp.example.com',
	// allowedAlgorithms defaults to ['RS256'] - a provider signing with anything else must
	// be allowlisted explicitly. The token's own alg header never gets to pick how it is
	// verified.
);

$client = (new OpenIDConnectClientFactory())->make($psr16Cache);

// GET /oidc/callback
try {
	$result = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse($_GET));
} catch (AuthenticationFailedException $e) {
	// An id_token signed HS256 against this default (RS256-only) config is rejected before
	// its signature - valid or not - is even checked.
	abort_login($e);
}

// Some providers genuinely sign with HS256 for a confidential client - a real secret only
// the client and provider know. That is a legitimate choice this config can opt into.
$hmacConfig = $config->withAllowedAlgorithms([ 'HS256' ]);

// A public client (no client secret) has nothing to keep an HMAC signature honest - an
// attacker forging a token only needs to guess a key nobody else needs to know. HS256 is
// refused outright for one, even with it explicitly allowlisted.
$publicClientConfig = $hmacConfig->withClientSecret('');
