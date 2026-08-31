<?php

namespace Oidc;

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Interfaces\RefreshTokenClientInterface;

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
 * Takes no LoggerInterface of its own, unlike its sibling collaborators - every failure this
 * class can produce is already detected and logged by whichever collaborator actually finds
 * it (TokenEndpointClient, IdTokenVerifier, ClaimsValidator). This class has no failure
 * condition of its own to log.
 */
final class RefreshTokenClient implements RefreshTokenClientInterface {

	public function __construct(
		private readonly ProviderMetadataResolver $providerMetadataResolver,
		private readonly IdTokenVerifier $idTokenVerifier,
		private readonly ClaimsValidator $claimsValidator,
		private readonly TokenEndpointClient $tokenEndpointClient,
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
