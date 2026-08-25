<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-claim-validation.php for the runnable version, and example/pseudo/README.md.

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

// GET /oidc/callback
// firebase/php-jwt's own JWT::decode() only checks exp/iat/nbf when they happen to be
// present, and never checks that exp is actually after iat. A token missing sub or exp
// entirely, or one whose exp is not after its own iat, is rejected here regardless.
try {
	$result = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse($_GET));
} catch (AuthenticationFailedException $e) {
	abort_login($e);
}

// maxTokenLifetimeSeconds is a separate, opt-in cap on exp - iat - for a token that is
// otherwise well-formed but claims an unreasonably long validity window. Left null, every
// lifetime a provider issues is accepted; a sensible cap depends on that provider's own
// typical token lifetime, which this library cannot guess safely for every integration.
$boundedConfig = $config->withMaxTokenLifetimeSeconds(3600);
