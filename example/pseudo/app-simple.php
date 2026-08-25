<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-simple.php for the runnable version, and example/pseudo/README.md.

use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;

$config = new OpenIDConnectClientConfig(
	clientId: 'my-client-id',
	clientSecret: 'my-client-secret',
	redirectUrl: 'https://app.example.com/oidc/callback',
	providerUrl: 'https://idp.example.com',
	scopes: [ 'profile', 'email' ],
);

$client = (new OpenIDConnectClientFactory())->make($psr16Cache);

// GET /oidc/login
$redirect = $client->buildAuthorizationCodeRedirect($config);
header("Location: {$redirect->url}");

// A service-to-service call, no user in the loop. extraParams passes a provider-specific
// extension straight through on the request body - here, an Auth0-style audience - without
// this library needing to model every provider's own extensions itself.
$token = $client->requestClientCredentialsToken(
	$config,
	scopes: [ 'api.read' ],
	extraParams: [ 'audience' => 'https://api.example.com' ],
);

call_api_with($token->accessToken);
