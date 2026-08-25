<?php

namespace Oidc;

/**
 * The outcome of completing an authorization code or implicit flow, or of refreshing one.
 *
 * $expiresIn is the access token's own lifetime in seconds (RFC 6749 §5.1's `expires_in`), not
 * the ID token's `exp` claim - two unrelated values, for two unrelated tokens, from two
 * unrelated sources. It is the only signal this library ever has for when the access token
 * itself needs refreshing; a caller intending to hold onto that token across requests should
 * convert it to an absolute timestamp at the moment it is received (`time() + $expiresIn`), not
 * store the relative seconds - those decay the instant time passes.
 */
final class AuthenticationResult {

	public function __construct(
		public readonly string $idToken,
		public readonly Claims $claims,
		public readonly ?string $accessToken = null,
		public readonly ?string $refreshToken = null,
		public readonly ?int $expiresIn = null,
	) {
	}

}
