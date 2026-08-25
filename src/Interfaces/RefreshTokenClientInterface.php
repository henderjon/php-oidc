<?php

namespace Oidc\Interfaces;

use Oidc\AuthenticationResult;
use Oidc\Claims;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\Exceptions\TokenRequestException;
use Oidc\OpenIDConnectClientConfig;

/**
 * Stands alone rather than extending AuthorizationFlowClientInterface: nothing about redeeming
 * a refresh token requires having just completed an interactive flow in the same process - a
 * background job holding a refresh token loaded from a database has no state/nonce, no flow to
 * consume, nothing this interface's single method needs beyond the refresh token itself and the
 * original ID token's claims to validate a new one against, per OpenID Connect Core 1.0 §12.2.
 */
interface RefreshTokenClientInterface {

	/**
	 * $originalIdToken and $originalClaims are the ID token (string) and claims
	 * (AuthenticationResult::$idToken / ::$claims) from the authentication this refresh token
	 * came from. OpenID Connect Core 1.0 §12.2: the refresh response might not contain a new
	 * `id_token` at all - when it does not, the returned AuthenticationResult carries the
	 * original ID token and claims forward unchanged, alongside the new access/refresh tokens.
	 * When it does, the new ID token's `iss`, `sub`, and `aud` are validated against the
	 * original's, `auth_time` (if present) must still reflect the original authentication, and
	 * `nonce` (if present) must match the original's.
	 *
	 * @throws AuthenticationFailedException
	 * @throws ProviderDiscoveryException
	 * @throws TokenRequestException
	 */
	public function refresh(
		OpenIDConnectClientConfig $config,
		string $refreshToken,
		string $originalIdToken,
		Claims $originalClaims,
	): AuthenticationResult;

}
