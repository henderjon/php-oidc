<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/app-audience-validation.php for the runnable version, and example/pseudo/README.md.

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
// OpenID Connect Core 1.0 §3.1.3.7 step 3 is two separate MUSTs: aud must contain this
// client, AND it must not contain anything this client does not trust. A token naming an
// unexpected second audience is rejected outright by default.
try {
	$result = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse($_GET));
} catch (AuthenticationFailedException $e) {
	abort_login($e);
}

// A caller that genuinely intends to accept a second audience (e.g. a shared resource
// server) states that explicitly, rather than the extra value simply passing unnoticed.
$multiAudienceConfig = $config->withAudience([ $config->clientId, 'https://api.example.com' ]);

// Some integrations cannot safely enumerate every audience a provider's tokens might
// legitimately carry - this opts back out of the "no untrusted extras" half of the check
// entirely, keeping only the requirement that this client's own expected value be
// present. Logged at alert, since an untrusted value actually being let through is
// exactly the case this opt-out exists for.
$permissiveConfig = $config->withAllowUntrustedAudiences(true);
