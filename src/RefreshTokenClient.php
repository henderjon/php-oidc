<?php

namespace Oidc;

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Interfaces\RefreshTokenClientInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Redeems a refresh token at the Token Endpoint (OpenID Connect Core 1.0 §12). Stands apart
 * from OpenIDConnectClient's own flow-completion methods rather than growing one of them: a
 * refresh call has no state/nonce, no in-flight AuthorizationStateStore entry, and nothing else
 * those methods need - it composes the same lower-level collaborators OpenIDConnectClient does
 * (TokenEndpointClient, IdTokenVerifier, ClaimsValidator), freshly injected here rather than
 * reached into that class's own private ones.
 *
 * OpenID Connect Core 1.0 §12.2's validation rules apply only when the refresh response
 * actually includes a new `id_token` - the spec is explicit it might not. When it does not,
 * the original ID token and claims are still valid and are carried forward unchanged.
 *
 * Every FAILURE this class can produce is still detected and logged by whichever collaborator
 * actually finds it (TokenEndpointClient, IdTokenVerifier, ClaimsValidator) - this class has no
 * failure condition of its own. `$logger` exists for what is specific to a refresh and would
 * otherwise be invisible even on success: whether the response carried a new `id_token` at all,
 * and, when it did, that it actually passed §12.2's checks against the original claims -
 * neither belongs to a deeper collaborator to log, since TokenEndpointClient only logs the
 * token response's own shape and IdTokenVerifier/ClaimsValidator log claim checks only on the
 * failure path, so without a debug log here "why isn't my refresh rotating the ID token" has
 * nothing in this class to look at even when nothing failed. It also covers one silent
 * transformation of caller-controlled input: normalizedAudience() below normalizes a malformed
 * `originalClaims` `aud` away rather than rejecting it, and that normalization is itself logged
 * - see that method's own docblock. No `state` is logged alongside any of these: unlike every
 * other collaborator's debug logging, a refresh has no in-flight flow to correlate with (see
 * above) - there is no `state` here to log in the first place.
 */
final class RefreshTokenClient implements RefreshTokenClientInterface {

	public function __construct(
		private readonly ProviderMetadataResolver $providerMetadataResolver,
		private readonly IdTokenVerifier $idTokenVerifier,
		private readonly ClaimsValidator $claimsValidator,
		private readonly TokenEndpointClient $tokenEndpointClient,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @throws AuthenticationFailedException
	 */
	public function refresh(
		OpenIDConnectClientConfig $config,
		string $refreshToken,
		string $originalIdToken,
		Claims $originalClaims,
	): AuthenticationResult {
		$tokenResult = $this->tokenEndpointClient->refreshToken($config, $refreshToken);

		if( $tokenResult->idToken === null ) {
			// accessToken is unconditionally present on any TokenResult - see its own
			// constructor - so only refreshToken is worth reporting presence of here.
			// client_id and sub are both available before the token endpoint is ever called -
			// there is no state for a refresh (see class docblock), but these two identify
			// which client and which user this refresh belongs to, which is what a caller
			// actually wants to filter these logs by.
			$this->logger->debug('OIDC: refresh response carried no new ID token - the original ID token and claims carry forward unchanged', [
				'client_id'         => $config->clientId,
				'sub'               => $originalClaims->get('sub'),
				'has_refresh_token' => $tokenResult->refreshToken !== null,
			]);

			return new AuthenticationResult($originalIdToken, $originalClaims, $tokenResult->accessToken, $tokenResult->refreshToken, $tokenResult->expiresIn);
		}

		try {
			$jwksUri = $this->providerMetadataResolver->resolve($config, ProviderMetadataResolver::JWKS_URI);
			$claims  = $this->idTokenVerifier->verify($tokenResult->idToken, $jwksUri, $config->clientSecret, $config->allowedAlgorithms);

			$this->claimsValidator->validateRequiredClaims($claims);
			$this->claimsValidator->validateTokenLifetime($claims, $config->maxTokenLifetimeSeconds);

			// Every comparison below is against the ORIGINAL ID token's own claims, per §12.2's
			// "MUST be the same as in the ID Token issued when the original authentication
			// occurred" - not against $config, even though those values usually agree with it.
			$this->claimsValidator->validateIssuer($claims, (string)$originalClaims->get('iss'));
			$this->claimsValidator->validateRefreshedSubject($claims, (string)$originalClaims->get('sub'));
			$this->claimsValidator->validateAudience($claims, $this->normalizedAudience($originalClaims->get('aud')));
			$this->claimsValidator->validateRefreshedAuthTime($claims, $originalClaims->get('auth_time'));

			$originalNonce = $originalClaims->get('nonce');
			$this->claimsValidator->validateRefreshedNonce($claims, is_string($originalNonce) ? $originalNonce : null);
		} catch( AuthenticationFailedException $e ) {
			// See OpenIDConnectClient::verifyAndValidateIdToken() for why this is caught and
			// rethrown here rather than threading the raw token into IdTokenVerifier/
			// ClaimsValidator themselves.
			throw new AuthenticationFailedException($e->getMessage(), idToken: $tokenResult->idToken, state: $e->getState(), previous: $e);
		}

		// sub/iss are standard, non-secret JWT claims - see OpenIDConnectClient's own equivalent
		// debug log for the same reasoning. Neither is redundant with the original claims logged
		// wherever the original authentication happened: this confirms what the REFRESHED token
		// itself validated to, not merely that it round-tripped the same values. client_id is
		// added for the same reason as the sibling debug log above - not itself validated here
		// (that already happened via ClientAuthenticator, further down the call chain), just
		// carried along so this log line can be filtered by client the same way.
		$this->logger->debug('OIDC: refreshed ID token validated against the original claims', [
			'client_id' => $config->clientId,
			'sub'       => $claims->get('sub'),
			'iss'       => $claims->get('iss'),
		]);

		return new AuthenticationResult($tokenResult->idToken, $claims, $tokenResult->accessToken, $tokenResult->refreshToken, $tokenResult->expiresIn);
	}

	/**
	 * Mirrors ClaimsValidator::toStringList()'s own normalization, since $originalClaims is
	 * caller-controlled data (the caller's own stored copy of a previously-validated token),
	 * the same trust level toStringList() already assumes for its own callers - so a malformed
	 * `aud` here is silently normalized away rather than rejected outright the way
	 * ClaimsValidator::toActualAudienceList() treats the same shape on the incoming token
	 * (untrusted, and rejected loudly by default). "Silently" only means no exception; logged
	 * at debug level either way, since $originalClaims should already be trustworthy by the
	 * time a caller has one to pass in - a malformed `aud` here is a caller-side surprise worth
	 * a trace, not a routine, expected shape.
	 *
	 * @return list<string>|string
	 */
	private function normalizedAudience( mixed $value ): array|string {
		if( is_array($value) ) {
			$normalized = array_values(array_filter($value, 'is_string'));

			if( count($normalized) !== count($value) ) {
				$this->logger->debug('OIDC: originalClaims aud contained non-string entries, dropped', [
					'aud'       => $value,
					'malformed' => array_values(array_filter($value, static fn ( mixed $item ): bool => !is_string($item))),
				]);
			}

			return $normalized;
		}

		if( is_string($value) ) {
			return $value;
		}

		$this->logger->debug('OIDC: originalClaims aud was not a string or array, treated as empty', [
			'aud'  => $value,
			'type' => get_debug_type($value),
		]);

		return '';
	}

}
