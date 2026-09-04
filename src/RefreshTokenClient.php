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
 * failure condition of its own. `$logger` exists only for the one thing that is specific to a
 * refresh and would otherwise be invisible even on success: whether the response carried a new
 * `id_token` at all, and, when it did, that it actually passed §12.2's checks against the
 * original claims. Neither of those two outcomes belongs to a deeper collaborator to log -
 * TokenEndpointClient already logs the token response's own shape, and IdTokenVerifier/
 * ClaimsValidator log the individual claim checks only on the failure path - so without a
 * debug log here, "why isn't my refresh rotating the ID token" has nothing in this class to
 * look at even when nothing failed. No `state` is logged alongside either record: unlike every
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
			$this->logger->debug('OIDC: refresh response carried no new ID token - the original ID token and claims carry forward unchanged', [
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
			$this->claimsValidator->validateAudience($claims, self::normalizedAudience($originalClaims->get('aud')));
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
		// itself validated to, not merely that it round-tripped the same values.
		$this->logger->debug('OIDC: refreshed ID token validated against the original claims', [
			'sub' => $claims->get('sub'),
			'iss' => $claims->get('iss'),
		]);

		return new AuthenticationResult($tokenResult->idToken, $claims, $tokenResult->accessToken, $tokenResult->refreshToken, $tokenResult->expiresIn);
	}

	/**
	 * Mirrors ClaimsValidator::toStringList()'s own normalization, since $originalClaims is
	 * caller-controlled data (the caller's own stored copy of a previously-validated token),
	 * the same trust level toStringList() already assumes for its own callers.
	 *
	 * @return list<string>|string
	 */
	private static function normalizedAudience( mixed $value ): array|string {
		if( is_array($value) ) {
			return array_values(array_filter($value, 'is_string'));
		}

		return is_string($value) ? $value : '';
	}

}
