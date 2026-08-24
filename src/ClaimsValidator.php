<?php

namespace Oidc;

use Oidc\Exceptions\AuthenticationFailedException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Validates the OIDC-specific claims that `Firebase\JWT\JWT::decode()`
 * cannot know about on its own: issuer, audience, and nonce. Signature
 * validity and the `exp`/`nbf`/`iat` time claims are already checked by
 * IdTokenVerifier before claims ever reach here.
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
	public function validate( Claims $claims, string $expectedIssuer, string $expectedClientId, ?string $expectedNonce ): void {
		$this->validateIssuer($claims, $expectedIssuer);
		$this->validateAudience($claims, $expectedClientId);
		$this->validateNonce($claims, $expectedNonce);
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
