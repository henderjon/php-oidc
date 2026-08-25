<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-pkce-optional.php for the runnable version, and example/pseudo/README.md.

use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;
use Oidc\PkceMode;

$config = (new OpenIDConnectClientConfig(
	clientId: 'my-client-id',
	clientSecret: 'my-client-secret',
	redirectUrl: 'https://app.example.com/oidc/callback',
	providerUrl: 'https://idp.example.com',
))->withPkce(PkceMode::Optional);

$client = (new OpenIDConnectClientFactory())->make($psr16Cache, $session->id);

// GET /oidc/login
// Optional still sends a code_challenge on every redirect, same as Required - the two
// modes only differ in what happens if the verifier goes missing by completion time.
$redirect = $client->buildAuthorizationCodeRedirect($config);
header("Location: {$redirect->url}");

// GET /oidc/callback
// If the verifier is gone (evicted, expired, or mismatched configs), Optional proceeds
// anyway and lets the token endpoint decide - no exception, just a code exchange sent
// without a code_verifier. Compare to app-pkce-required.php, which fails closed instead.
$result = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse($_GET));
