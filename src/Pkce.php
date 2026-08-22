<?php

namespace Oidc;

/**
 * RFC 7636 PKCE verifier/challenge generation, split out of
 * OpenIDConnectClient so this crypto is its own independently-testable
 * collaborator rather than a couple of private methods on the orchestrator.
 *
 * The verifier is 256 bits of randomness, base64url-encoded to 43
 * characters - within the spec's required 43-128 range using only
 * unreserved characters, so no separate length/charset validation is needed.
 */
final class Pkce {

	public static function generateVerifier(): string {
		return self::base64UrlEncode(random_bytes(32));
	}

	public static function challengeFor( string $codeVerifier ): string {
		return self::base64UrlEncode(hash('sha256', $codeVerifier, true));
	}

	private static function base64UrlEncode( string $bytes ): string {
		return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
	}

}
