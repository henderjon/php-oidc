<?php

namespace Henderjon\Oidc;

use Henderjon\Oidc\Exceptions\AuthenticationFailedException;

/**
 * Validates the OIDC-specific claims that `Firebase\JWT\JWT::decode()`
 * cannot know about on its own: issuer, audience, and nonce. Signature
 * validity and the `exp`/`nbf`/`iat` time claims are already checked by
 * IdTokenVerifier before claims ever reach here.
 */
final class ClaimsValidator {

	/**
	 * @throws AuthenticationFailedException
	 */
	public function validate( Claims $claims, string $expectedIssuer, string $expectedClientId, ?string $expectedNonce ): void {
		$this->validateIssuer($claims, $expectedIssuer);
		$this->validateAudience($claims, $expectedClientId);
		$this->validateNonce($claims, $expectedNonce);
	}

	/**
	 * @throws AuthenticationFailedException
	 */
	public function validateIssuer( Claims $claims, string $expectedIssuer ): void {
		if( $claims->get('iss') !== $expectedIssuer ) {
			throw new AuthenticationFailedException('ID token issuer does not match the expected issuer');
		}
	}

	/**
	 * The `aud` claim itself can be a single string or a JSON array of
	 * strings per the JWT spec; `$expectedAudience` mirrors that so a
	 * caller can either pin one exact value or accept any of several.
	 *
	 * @param list<string>|string $expectedAudience
	 * @throws AuthenticationFailedException
	 */
	public function validateAudience( Claims $claims, array|string $expectedAudience ): void {
		$actual   = $this->toStringList($claims->get('aud'));
		$expected = $this->toStringList($expectedAudience);

		if( array_intersect($expected, $actual) === [] ) {
			throw new AuthenticationFailedException('ID token audience does not match any of the expected values');
		}
	}

	/**
	 * @return list<string>
	 */
	private function toStringList( mixed $value ): array {
		if( is_array($value) ) {
			return array_values(array_filter($value, 'is_string'));
		}

		return is_string($value) ? [ $value ] : [];
	}

	/**
	 * Stricter than jumbojett, which silently accepts an ID token with no
	 * nonce claim at all even when one was sent. If we sent a nonce, the
	 * token must echo it back - a missing nonce is a failure, not a pass.
	 *
	 * @throws AuthenticationFailedException
	 */
	public function validateNonce( Claims $claims, ?string $expectedNonce ): void {
		if( $expectedNonce === null ) {
			return;
		}

		if( $claims->get('nonce') !== $expectedNonce ) {
			throw new AuthenticationFailedException('ID token nonce does not match the expected value');
		}
	}

}
