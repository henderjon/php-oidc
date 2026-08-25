<?php

// Pseudo-code - illustrates how this looks in a real app, not a runnable script. See
// example/pseudo/README.md.
//
// Companion to app-refresh-token.php: that one shows the proactive path (refresh before
// expiresIn is up). This one shows the reactive path - call the resource server first, refresh
// only on a 401. The reactive path is the one that is actually load-bearing for correctness: a
// provider can revoke a token early for reasons that have nothing to do with its nominal
// expires_in - clock drift, an admin revoking access, the user's session getting killed
// elsewhere - so this path has to exist even when the proactive check is also in place. Best
// practice is usually both together: check first so the 401 path is rarely hit at all, but
// still handle it when it happens anyway.

use Oidc\Claims;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;

$config = new OpenIDConnectClientConfig(
	clientId: 'my-client-id',
	clientSecret: 'my-client-secret',
	redirectUrl: 'https://app.example.com/oidc/callback',
	providerUrl: 'https://idp.example.com',
);

$client = (new OpenIDConnectClientFactory())->make($psr16Cache);

// 1. Call the resource server with the access token on hand.
$session  = load_session();
$response = call_resource_server($session['access_token']);

// 2. A 401 means the access token is expired or revoked - the only signal this library or
// the resource server gives you for that; there is no separate "is this still good" check.
if ($response->status === 401) {
	// 3. Redeem the refresh token. $originalIdToken/$originalClaims are the ID token and
	// claims from the authentication this refresh token came from - carried in the session,
	// not re-derived.
	try {
		$refreshed = $client->refresh(
			$config,
			$session['refresh_token'],
			$session['id_token'],
			new Claims($session['claims']),
		);
	} catch (AuthenticationFailedException $e) {
		// The refresh token itself is dead or rejected - there is nothing left to retry.
		force_logout($e);
	}

	// 6. Persist before retrying - especially the (possibly rotated) refresh_token - so a
	// second 401 on the retry below does not lose it if the process dies before this write
	// happens. id_token/claims are often unchanged (OpenID Connect Core 1.0 §12.2 lets the
	// refresh response omit a new id_token entirely), but $refreshed carries the right
	// values forward either way.
	save_session([
		'id_token'      => $refreshed->idToken,
		'claims'        => $refreshed->claims->all(),
		'access_token'  => $refreshed->accessToken,
		'refresh_token' => $refreshed->refreshToken,
		'expires_at'    => time() + $refreshed->expiresIn,
	]);

	// 5. Retry the original call once, with the new access token.
	$response = call_resource_server($refreshed->accessToken);

	// Refresh-and-retry once per request, never in a loop. A second 401 here is not a
	// transient problem - the refresh itself may have handed back a token that is already
	// stale, or something else is wrong - so retrying indefinitely would just hammer the
	// token endpoint.
	if ($response->status === 401) {
		force_logout();
	}
}
