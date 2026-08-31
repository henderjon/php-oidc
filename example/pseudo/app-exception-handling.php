<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/pseudo/README.md. No single runnable script in example/ exercises every exception
// type below in one place - this file exists purely to show each one's discrete getters
// side by side, one catch block per type. See app-exception-type-narrowing.php for the same
// thing done with a single OpenIDConnectException catch and instanceof instead.
//
// HttpTransportException is deliberately not caught anywhere here - it is thrown only by
// CurlHttpFetcher, and every collaborator that calls it catches and rewraps it into one of
// the domain exceptions below before it ever reaches application code.

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\AuthorizationStateException;
use Oidc\Exceptions\ProviderDiscoveryException;
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

// GET /oidc/login
try {
	$redirect = $client->buildAuthorizationCodeRedirect($config);
	header("Location: {$redirect->url}");
} catch (AuthorizationStateException $e) {
	// The cache write that persists state/nonce/code_verifier itself failed - distinct from
	// a clean miss on lookup later (a forged, expired, or already-consumed state), which is
	// a normal outcome, not this. getState() is AuthorizationStateStore's own truncated copy
	// of the state it tried and failed to persist.
	log_error('oidc login: could not start authorization attempt', [ 'state' => $e->getState() ]);
	abort_login($e);
} catch (ProviderDiscoveryException $e) {
	// The provider's discovery document couldn't be fetched, parsed, or is missing the
	// authorization_endpoint - no flow has started yet, so getState() is always null here.
	log_error('oidc login: provider discovery failed', [ 'state' => $e->getState() ]);
	abort_login($e);
}

// GET /oidc/callback
try {
	$result = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse($_GET));
} catch (AuthenticationFailedException $e) {
	// A forged/expired state or nonce, a missing authorization code, a provider-returned
	// error, or an ID token that failed signature or claims validation. getIdToken() is the
	// raw token this failure happened against - null for every one of those EXCEPT the
	// claims/signature failure, where it is exactly the token that failed: validation is
	// fail-fast, so decoding the whole token is the only way to see every claim it carried,
	// not just the one that happened to trip the first check.
	log_error('oidc callback: authentication failed', [
		'state'    => $e->getState(),
		'id_token' => $e->getIdToken(),
	]);
	abort_login($e);
} catch (ProviderDiscoveryException $e) {
	log_error('oidc callback: provider discovery failed', [ 'state' => $e->getState() ]);
	abort_login($e);
} catch (TokenRequestException $e) {
	// The token endpoint rejected the exchange, or returned something unusable.
	// getHttpStatus()/getRawBody() are the actual response - both null only for a transport
	// failure that never reached the server at all.
	log_error('oidc callback: token request failed', [
		'state'       => $e->getState(),
		'http_status' => $e->getHttpStatus(),
		'raw_body'    => $e->getRawBody(),
	]);
	abort_login($e);
}

// A service-to-service call, no user in the loop - the same TokenRequestException/
// ProviderDiscoveryException as above can be thrown here too, just with no flow `state`
// ever in scope to report.
try {
	$token = $client->requestClientCredentialsToken($config, scopes: [ 'api.read' ]);
} catch (TokenRequestException $e) {
	log_error('client credentials: token request failed', [
		'http_status' => $e->getHttpStatus(),
		'raw_body'    => $e->getRawBody(),
	]);

	return;
}

// fetchUserInfo() - getState() is always null here too (not scoped to a stored flow the way
// the authorization/token/JWKS paths are). getHttpStatus()/getRawBody() cover both a plain
// HTTP-level failure and a signed (application/jwt) response that failed further
// verification or claims validation - getRawBody() is the JWT itself in that case, not a
// JSON body, and decoding it shows every claim it carried at once.
try {
	$userInfo = $client->fetchUserInfo($config, (string)$result->accessToken, $result->claims->get('sub'));
} catch (UserInfoRequestException $e) {
	log_error('oidc callback: userinfo request failed', [
		'http_status' => $e->getHttpStatus(),
		'raw_body'    => $e->getRawBody(),
	]);
	abort_login($e);
}
