<?php

namespace Henderjon\Oidc;

/**
 * The outcome of completing an authorization code or implicit flow.
 */
final class AuthenticationResult {

	public function __construct(
		public readonly string $idToken,
		public readonly Claims $claims,
		public readonly ?string $accessToken = null,
		public readonly ?string $refreshToken = null,
	) {
	}

}
