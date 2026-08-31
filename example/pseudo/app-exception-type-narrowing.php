<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/pseudo/README.md and app-exception-handling.php, which covers the same set of
// failures with one catch block per exception type instead of instanceof narrowing.

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\OpenIDConnectException;
use Oidc\Exceptions\TokenRequestException;
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

$client = (new OpenIDConnectClientFactory())->make($psr16Cache, $session->id);

// GET /oidc/callback
// Every exception this library throws extends OpenIDConnectException, so a caller that
// only wants a single catch clause for "something in this library failed" always has one
// available - useful here since completeAuthorizationCodeFlow() and fetchUserInfo() can
// each fail for several different reasons and this route treats all of them the same way
// (log with whatever detail is available, then abort the login).
try {
	$result   = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse($_GET));
	$userInfo = $client->fetchUserInfo($config, (string)$result->accessToken, $result->claims->get('sub'));
} catch (OpenIDConnectException $e) {
	$context = [ 'state' => $e->getState() ];

	// Only AuthenticationFailedException, TokenRequestException, and
	// UserInfoRequestException carry anything beyond getState() (see docs/index.html's
	// Exceptions table). Narrowing with instanceof reaches their discrete getters without
	// putting those methods on the base class, where they would be meaningless for
	// AuthorizationStateException/ProviderDiscoveryException - neither of those has a token
	// or an HTTP response to attach.
	if ($e instanceof AuthenticationFailedException) {
		$context['id_token'] = $e->getIdToken();
	}

	// TokenRequestException and UserInfoRequestException are unrelated types - neither
	// extends the other - so this is two instanceof checks, not one, even though both carry
	// the identical getHttpStatus()/getRawBody() pair.
	if ($e instanceof TokenRequestException || $e instanceof UserInfoRequestException) {
		$context['http_status'] = $e->getHttpStatus();
		$context['raw_body']    = $e->getRawBody();
	}

	log_error('oidc callback failed', $context);
	abort_login($e);
}
