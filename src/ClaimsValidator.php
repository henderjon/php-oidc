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
		bool $allowUntrustedAudiences = false,
	): void {
		$this->validateRequiredClaims($claims);
		$this->validateIssuer($claims, $expectedIssuer);
		$this->validateAudience($claims, $expectedClientId, $allowUntrustedAudiences);
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
	 * OpenID Connect Core 1.0 §3.1.3.7 step 3 is two separate MUSTs, not one: the token
	 * "MUST be rejected if [it] does not list the Client as a valid audience, OR IF IT
	 * CONTAINS ADDITIONAL AUDIENCES NOT TRUSTED BY THE CLIENT." Both are checked by default -
	 * a caller widening `$expectedAudience` beyond its own client ID is an explicit statement
	 * of which extra audiences it trusts, and anything in `aud` outside that set is, by
	 * definition, untrusted. `$allowUntrustedAudiences` (see
	 * OpenIDConnectClientConfig::$allowUntrustedAudiences) opts back out of that second half
	 * for the rare case where a caller cannot safely enumerate every audience a provider's
	 * tokens might legitimately carry - the first half (the client's own expected value must
	 * be present) is never optional.
	 *
	 * The full expected and actual audience sets are logged whenever an untrusted value is
	 * involved - on rejection, or on an `allowUntrustedAudiences` opt-out that actually let
	 * one through - not just the offending values. Debugging should never require separately
	 * reconstructing what a token actually claimed or what this call expected.
	 *
	 * A malformed `aud` array - one containing a non-string entry alongside otherwise valid
	 * ones - is a different problem from an untrusted-but-well-formed extra value, and
	 * `$allowUntrustedAudiences` governs both the same way: by default (`false`), a malformed
	 * entry is rejected outright rather than silently discarded, since silently discarding it
	 * would let a token with a genuinely malformed claim pass as if it had never carried the
	 * bad entry at all. `true` relaxes this the same way it relaxes untrusted-but-well-formed
	 * extras - a malformed entry is filtered out and validation proceeds on whatever
	 * well-formed values remain, same as before this check existed.
	 *
	 * @param list<string>|string $expectedAudience
	 * @throws AuthenticationFailedException
	 */
	public function validateAudience( Claims $claims, array|string $expectedAudience, bool $allowUntrustedAudiences = false ): void {
		$actual   = $this->toActualAudienceList($claims->get('aud'), $allowUntrustedAudiences);
		$expected = $this->toStringList($expectedAudience);

		if( array_intersect($expected, $actual) === [] ) {
			$this->logger->error('OIDC: ID token audience does not match any of the expected values', [
				'expected' => $expected,
				'actual'   => $actual,
				'state'    => $this->state,
			]);

			throw new AuthenticationFailedException('ID token audience does not match any of the expected values');
		}

		$untrusted = array_values(array_diff($actual, $expected));

		if( $untrusted === [] ) {
			return;
		}

		if( $allowUntrustedAudiences ) {
			// Not a rejection - allowUntrustedAudiences deliberately lets this through - but
			// an untrusted value actually being present (not just theoretically possible) is
			// exactly the case this opt-out exists for, and it warrants standing out from
			// routine operational noise rather than passing completely silently.
			$this->logger->alert('OIDC: ID token audience contains untrusted values, allowed through by configuration', [
				'expected'  => $expected,
				'actual'    => $actual,
				'untrusted' => $untrusted,
				'state'     => $this->state,
			]);

			return;
		}

		$this->logger->error('OIDC: ID token audience contains additional values not trusted by this client', [
			'expected'  => $expected,
			'actual'    => $actual,
			'untrusted' => $untrusted,
			'state'     => $this->state,
		]);

		throw new AuthenticationFailedException('ID token audience contains additional values not trusted by this client');
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
	 * Like toStringList(), but for the actual `aud` claim specifically - an untrusted value,
	 * unlike an `$expectedAudience` a caller wrote themselves - so a malformed entry here
	 * gets a real decision instead of toStringList()'s silent array_filter(). A bare non-array,
	 * non-string `aud` (already handled correctly as an empty list - it fails the "must
	 * contain the expected value" check on its own) is unaffected; this only changes behavior
	 * for an array containing a mix of valid strings and something else.
	 *
	 * @throws AuthenticationFailedException
	 * @return list<string>
	 */
	private function toActualAudienceList( mixed $value, bool $allowUntrustedAudiences ): array {
		if( !is_array($value) ) {
			return $this->toStringList($value);
		}

		$malformed = array_values(array_filter($value, static fn ( mixed $item ): bool => !is_string($item)));

		if( $malformed !== [] && !$allowUntrustedAudiences ) {
			$this->logger->error('OIDC: ID token audience contains a malformed value', [
				'aud'       => $value,
				'malformed' => $malformed,
				'state'     => $this->state,
			]);

			throw new AuthenticationFailedException('ID token audience contains a malformed value');
		}

		return array_values(array_filter($value, 'is_string'));
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

	/**
	 * OpenID Connect Core 1.0 §5.3.2 (Successful UserInfo Response): "The sub (subject) Claim
	 * MUST always be returned in the UserInfo Response... The sub Claim in the UserInfo
	 * Response MUST be verified to exactly match the sub Claim in the ID Token; if they do not
	 * match, the UserInfo Response values MUST NOT be used." This guards against token
	 * substitution - an access token valid for a different session, presented to the userinfo
	 * endpoint, would otherwise return a different user's claims under the caller's identity.
	 *
	 * Unconditional on whether the response was signed - unlike validateUserInfoIssuer() and
	 * validateUserInfoAudience() below, §5.3.2 does not scope this requirement to "if signed".
	 *
	 * @throws AuthenticationFailedException
	 */
	public function validateUserInfoSubject( Claims $claims, string $expectedSubject ): void {
		$actual = $claims->get('sub');

		if( !is_string($actual) || $actual === '' ) {
			$this->logger->error('OIDC: UserInfo response is missing the required sub claim', [
				'state' => $this->state,
			]);

			throw new AuthenticationFailedException('UserInfo response is missing the required sub claim');
		}

		if( $actual !== $expectedSubject ) {
			$this->logger->error('OIDC: UserInfo response subject does not match the authenticated ID token subject', [
				'expected' => $expectedSubject,
				'actual'   => $actual,
				'state'    => $this->state,
			]);

			throw new AuthenticationFailedException('UserInfo response subject does not match the authenticated ID token subject');
		}
	}

}
