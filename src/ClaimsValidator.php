<?php

namespace Oidc;

use Oidc\Exceptions\AuthenticationFailedException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Validates the OIDC-specific claims that `Firebase\JWT\JWT::decode()`
 * cannot know about on its own (issuer, audience, nonce), plus the claims
 * `JWT::decode()` knows about but does not require: `sub`, `exp`, and
 * `iat` are validated there only when present - a token that omits them
 * entirely sails through with no check at all. See
 * IdTokenVerifier's own docblock for exactly what `JWT::decode()` already
 * covers.
 *
 * A mismatch here is a stronger signal than a missing/wrong `state` - it
 * means a signature-valid token that simply was not meant for this
 * exchange, which is exactly what an attack or a misconfigured client
 * looks like. Every mismatch is logged with the expected and actual
 * values before the generic AuthenticationFailedException is thrown, so
 * that signal is not lost unless the caller happens to log the exception.
 */
final class ClaimsValidator {

	public function __construct(
		private readonly LoggerInterface $logger = new NullLogger,
		private readonly ?string $state = null,
	) {
	}

	/**
	 * Returns a copy of this validator carrying one flow's correlation id, so every log
	 * call it makes afterward can be tied back to the same `state` AuthorizationStateStore
	 * logs. Returns a new instance rather than mutating this one - this validator is a
	 * long-lived collaborator built once by OpenIDConnectClientFactory and shared, so
	 * scoping it must not leak one flow's state into another's log lines.
	 */
	public function withState( ?string $state ): self {
		return new self($this->logger, $state);
	}

	/**
	 * @throws AuthenticationFailedException
	 */
	public function validate(
		Claims $claims,
		string $expectedIssuer,
		string $expectedClientId,
		?string $expectedNonce,
		?int $maxLifetimeSeconds = null,
	): void {
		$this->validateRequiredClaims($claims);
		$this->validateIssuer($claims, $expectedIssuer);
		$this->validateAudience($claims, $expectedClientId);
		$this->validateNonce($claims, $expectedNonce);
		$this->validateTokenLifetime($claims, $maxLifetimeSeconds);
	}

	/**
	 * `sub`, `exp`, and `iat` are all REQUIRED claims in every ID token (OpenID Connect Core
	 * 1.0 §2) - not optional, and not merely "checked if present" the way `JWT::decode()`
	 * treats them (see IdTokenVerifier's own docblock). A token omitting any of the three, or
	 * carrying a non-numeric value for `exp`/`iat`, or claiming to expire before or at the
	 * moment it says it was issued, is rejected here before anything else about it is trusted.
	 *
	 * @throws AuthenticationFailedException
	 */
	public function validateRequiredClaims( Claims $claims ): void {
		$sub = $claims->get('sub');

		if( !is_string($sub) || $sub === '' ) {
			$this->logger->error('OIDC: ID token is missing the required sub claim', [ 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token is missing the required sub claim');
		}

		$exp = $claims->get('exp');

		if( !is_numeric($exp) ) {
			$this->logger->error('OIDC: ID token is missing the required exp claim, or it is not numeric', [
				'exp'   => $exp,
				'state' => $this->state,
			]);

			throw new AuthenticationFailedException('ID token is missing the required exp claim, or it is not numeric');
		}

		$iat = $claims->get('iat');

		if( !is_numeric($iat) ) {
			$this->logger->error('OIDC: ID token is missing the required iat claim, or it is not numeric', [
				'iat'   => $iat,
				'state' => $this->state,
			]);

			throw new AuthenticationFailedException('ID token is missing the required iat claim, or it is not numeric');
		}

		if( (float)$exp <= (float)$iat ) {
			$this->logger->error('OIDC: ID token exp is not after its own iat', [
				'exp'   => $exp,
				'iat'   => $iat,
				'state' => $this->state,
			]);

			throw new AuthenticationFailedException('ID token exp is not after its own iat');
		}
	}

	/**
	 * `exp - iat` bounds how long a token claims to be valid for, from its own issuance -
	 * independent of clock skew, and independent of whatever leeway the verifier itself
	 * allows (see IdTokenVerifier::$leewaySeconds, a different concern: clock disagreement,
	 * not token lifetime). Null skips the check - deliberately opt-in, since a sensible cap
	 * depends on a given provider's own typical token lifetime, which this library cannot
	 * guess safely for every integration. Assumes validateRequiredClaims() has already
	 * confirmed `exp`/`iat` are present and numeric.
	 *
	 * @throws AuthenticationFailedException
	 */
	public function validateTokenLifetime( Claims $claims, ?int $maxLifetimeSeconds ): void {
		if( $maxLifetimeSeconds === null ) {
			return;
		}

		$lifetime = (float)$claims->get('exp') - (float)$claims->get('iat');

		if( $lifetime > $maxLifetimeSeconds ) {
			$this->logger->error('OIDC: ID token lifetime exceeds the configured maximum', [
				'lifetime_seconds'     => $lifetime,
				'max_lifetime_seconds' => $maxLifetimeSeconds,
				'state'                => $this->state,
			]);

			throw new AuthenticationFailedException('ID token lifetime exceeds the configured maximum');
		}
	}

	/**
	 * @throws AuthenticationFailedException
	 */
	public function validateIssuer( Claims $claims, string $expectedIssuer ): void {
		$actual = $claims->get('iss');

		if( $actual !== $expectedIssuer ) {
			$this->logger->error('OIDC: ID token issuer does not match the expected issuer', [
				'expected' => $expectedIssuer,
				'actual'   => $actual,
				'state'    => $this->state,
			]);

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
			$this->logger->error('OIDC: ID token audience does not match any of the expected values', [
				'expected' => $expected,
				'actual'   => $actual,
				'state'    => $this->state,
			]);

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

		$actual = $claims->get('nonce');

		if( $actual !== $expectedNonce ) {
			$this->logger->error('OIDC: ID token nonce does not match the expected value', [
				'expected' => $expectedNonce,
				'actual'   => $actual,
				'state'    => $this->state,
			]);

			throw new AuthenticationFailedException('ID token nonce does not match the expected value');
		}
	}

}
