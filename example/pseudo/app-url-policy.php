<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-url-policy.php for the runnable version, and example/pseudo/README.md.

use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;

$config = new OpenIDConnectClientConfig(
	clientId: 'my-client-id',
	clientSecret: 'my-client-secret',
	redirectUrl: 'https://app.example.com/oidc/callback',
	providerUrl: 'https://idp.example.com',
);

$client = (new OpenIDConnectClientFactory())->make($psr16Cache);

// By default, every endpoint discovery resolves - authorization, token, jwks_uri,
// userinfo - has to stay on the provider's own host (issuer, or providerUrl when issuer
// is not set). https and a matching issuer are not, by themselves, a guarantee that every
// endpoint inside a discovery document is safe to call - a compromised or misconfigured
// provider, or a network attacker tampering with the response, could point token_endpoint
// anywhere.
try {
	$token = $client->requestClientCredentialsToken($config);
} catch (ProviderDiscoveryException $e) {
	// A discovered endpoint on an unexpected host is rejected before any request reaches it.
	log_and_fail($e);
}

// A provider that legitimately splits its endpoints across several hosts (Google's
// token/JWKS/userinfo endpoints, for instance, each live on a different host than its
// issuer) needs to say so explicitly - either allowedHosts naming every host it actually
// uses, or allowAnyHost to opt out of the check entirely.
$multiHostConfig = $config->withAllowAnyHost(true);
$token            = $client->requestClientCredentialsToken($multiHostConfig);
