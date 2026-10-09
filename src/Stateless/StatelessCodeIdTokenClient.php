<?php

namespace Oidc\Stateless;

use Oidc\AuthenticationResult;
use Oidc\Claims;
use Oidc\ClaimsValidator;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\ConfigurationException;
use Oidc\IdTokenVerifier;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\ProviderError;
use Oidc\ProviderMetadataResolver;
use Oidc\TokenEndpointClient;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Completes one vendor-driven login shape, and only that one: a provider starts the login
 * itself and redirects the user here with `?code=...` and no `state`. This client never sent
 * an authorization request, so it holds no `state`, `nonce`, or PKCE verifier to check.
 *
 * It accepts exactly this response:
 *
 * - an authorization `code`, and nothing that names another shape (no `state`, no `error`, no
 *   `id_token`, no `access_token`)
 * - redeemed at the token endpoint with the configured client authentication
 * - answered by a token response that contains an ID token
 *
 * Anything else throws. The ID token then gets the same checks the main flow gives a code-flow
 * token - signature, `iss`, `aud`, `azp`, `exp`, token lifetime, `auth_time` - minus the nonce,
 * plus one new check: its `iat` must be no older than the caller's maximum.
 *
 * This is not defined by OpenID Connect Core. The standard answer is third-party initiated
 * login (Core §4): the provider sends the user to a login initiation URL, and the client then
 * starts an ordinary flow with its own `state` and `nonce`. Prefer that wherever the provider
 * allows it. This class exists for the provider that re-prompts for credentials when you do.
 *
 * What it gives up, and what stands in:
 *
 * - Login CSRF protection. `state` is how a client knows a callback answers a request it made.
 *   An attacker can send a victim a link carrying the attacker's own valid `code`, and this
 *   class cannot tell that from a real login.
 * - Replay protection by nonce. The only replay defense is the `iat` age check, so a captured
 *   code-and-token pair stays usable until that window closes. Keep the window short.
 * - PKCE. An intercepted `code` is not bound to a verifier this client holds.
 *
 * A different vendor shape (no ID token, an access token and UserInfo only, an `id_token`
 * posted straight to the callback) needs its own class. Do not add an option here to cover one.
 * Every flag would widen what this class accepts, and the narrowness is the safety property.
 *
 * Deliberately composes the main client's public collaborators instead of extending or
 * modifying OpenIDConnectClient, so nothing about the stateful flow can change by accident.
 * It touches no AuthorizationStateStore and no cache.
 *
 * The validation sequence in verifyAndValidateIdToken() mirrors OpenIDConnectClient's. A test
 * fails when the two lists of validator calls drift apart, so a check added to one cannot
 * silently go missing from the other.
 */
final class StatelessCodeIdTokenClient implements StatelessCodeIdTokenClientInterface {

	public function __construct(
		private readonly ProviderMetadataResolver $providerMetadataResolver,
		private readonly IdTokenVerifier $idTokenVerifier,
		private readonly ClaimsValidator $claimsValidator,
		private readonly TokenEndpointClient $tokenEndpointClient,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	public function completeStatelessCodeFlow(
		OpenIDConnectClientConfig $config,
		IncomingAuthorizationResponse $response,
		int $maxIdTokenAgeSeconds,
		?string $redirectUriOverride = null,
	): AuthenticationResult {
		if( $maxIdTokenAgeSeconds < 1 ) {
			$this->logger->error('OIDC: stateless code flow needs a positive maximum ID token age', [
				'max_id_token_age_seconds' => $maxIdTokenAgeSeconds,
				'security_relevant'        => false,
			]);

			throw new ConfigurationException('The maximum ID token age for the stateless code flow must be positive');
		}

		$this->assertNoProviderError($response);
		$this->assertExpectedShape($response);

		$code   = (string)$response->code;
		$issuer = $config->issuer;

		// Checked before the code is redeemed: a code is single use, so failing after the
		// exchange would burn it for a mistake this check could have caught first.
		if( $issuer === null ) {
			$this->logger->error('OIDC: no issuer configured against which to validate the ID token', [ 'state' => null, 'security_relevant' => false ]);

			throw new AuthenticationFailedException('No issuer configured against which to validate the ID token');
		}

		$exchangeConfig = $redirectUriOverride !== null ? $config->withRedirectUri($redirectUriOverride) : $config;

		$providerMetadataResolver = $this->providerMetadataResolver->withState(null);
		$tokenEndpointClient      = $this->tokenEndpointClient->withState(null, $providerMetadataResolver);

		// No code verifier: nothing stored one, and the provider started this login.
		$tokenResult = $tokenEndpointClient->exchangeAuthorizationCode($exchangeConfig, $code, null);

		if( $tokenResult->idToken === null ) {
			$endpoint = $providerMetadataResolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);

			$this->logger->error('OIDC: token endpoint response is missing id_token', [ 'endpoint' => $endpoint, 'state' => null, 'security_relevant' => false ]);

			throw new AuthenticationFailedException("Token response from {$endpoint} is missing id_token");
		}

		$claims = $this->verifyAndValidateIdToken($config, $tokenResult->idToken, $tokenResult->accessToken, $providerMetadataResolver, $issuer, $maxIdTokenAgeSeconds);

		// warning: a deliberate downgrade of three protections the main flow always applies.
		// Logged on every completion so it can never pass without a trace.
		$this->logger->warning('OIDC: stateless code flow completed without verifying state, nonce, or PKCE', [
			'issuer' => $issuer,
			'sub'    => $claims->get('sub'),
		]);

		return new AuthenticationResult($tokenResult->idToken, $claims, $tokenResult->accessToken, $tokenResult->refreshToken, $tokenResult->expiresIn);
	}

	/**
	 * Same handling as OpenIDConnectClient: log, then throw with the ProviderError attached.
	 * Runs first so a provider-reported error is never hidden behind a shape failure.
	 *
	 * @throws AuthenticationFailedException
	 */
	private function assertNoProviderError( IncomingAuthorizationResponse $response ): void {
		$summary = $response->errorSummary();

		if( $summary === null ) {
			return;
		}

		$providerError = new ProviderError($response->error, $response->errorDescription, $response->errorUri);

		$this->logger->error('OIDC: provider returned an error on the callback', [
			'error'             => $providerError->error,
			'error_description' => $providerError->errorDescription,
			'error_uri'         => $providerError->errorUri,
			'state'             => $response->state,
			'security_relevant' => false,
		]);

		throw new AuthenticationFailedException("Provider returned an error: {$summary}", providerError: $providerError, state: $response->state);
	}

	/**
	 * Fails closed on every response that is not exactly a bare code. A `state` means the main
	 * flow's own request is being answered, an `id_token` or `access_token` means another shape
	 * entirely, and each belongs to a different code path.
	 *
	 * @throws AuthenticationFailedException
	 */
	private function assertExpectedShape( IncomingAuthorizationResponse $response ): void {
		if( $response->state !== null ) {
			$this->logger->error('OIDC: stateless code flow received a response carrying a state', [ 'state' => $response->state, 'security_relevant' => false ]);

			throw new AuthenticationFailedException('Response carries a state and belongs to the stateful flow', state: $response->state);
		}

		if( $response->idToken !== null || $response->accessToken !== null ) {
			$this->logger->error('OIDC: stateless code flow received a response carrying a token directly', [ 'state' => null, 'security_relevant' => false ]);

			throw new AuthenticationFailedException('Response carries a token directly and is not a bare authorization code');
		}

		if( $response->code === null ) {
			$this->logger->error('OIDC: callback is missing the authorization code', [ 'state' => null, 'security_relevant' => false ]);

			throw new AuthenticationFailedException('Callback is missing the authorization code');
		}
	}

	/**
	 * Mirrors OpenIDConnectClient::verifyAndValidateIdToken() for a code-flow token, minus
	 * validateNonce() and plus validateIssuedAtAge(). Keep the two in step: a test compares them.
	 *
	 * @throws AuthenticationFailedException
	 */
	private function verifyAndValidateIdToken(
		OpenIDConnectClientConfig $config,
		string $idToken,
		?string $accessToken,
		ProviderMetadataResolver $providerMetadataResolver,
		string $issuer,
		int $maxIdTokenAgeSeconds,
	): Claims {
		try {
			$jwksUri = $providerMetadataResolver->resolve($config, ProviderMetadataResolver::JWKS_URI);

			// requireAtHash: false - the ID token comes from the token endpoint, where at_hash is
			// OPTIONAL (OpenID Connect Core 1.0 §3.1.3.6), same as the main code flow.
			$claims = $this->idTokenVerifier->withState(null)->verify($idToken, $jwksUri, $config->clientSecret, $config->allowedAlgorithms, $accessToken, false);

			$claimsValidator = $this->claimsValidator->withState(null);

			$claimsValidator->validateRequiredClaims($claims);
			$claimsValidator->validateIssuer($claims, $issuer);
			$claimsValidator->validateAudience($claims, $config->audience ?? $config->clientId, $config->allowUntrustedAudiences);
			$claimsValidator->validateAuthorizedParty($claims, $config->clientId);
			$claimsValidator->validateTokenLifetime($claims, $config->maxTokenLifetimeSeconds);
			$claimsValidator->validateAuthTime($claims, $config->maxAgeSeconds);

			// The replay defense. With no nonce to bind the token to a request, how recently it
			// was issued is all that limits reuse of a captured one.
			$claimsValidator->validateIssuedAtAge($claims, $maxIdTokenAgeSeconds);

			$this->logger->debug('OIDC: ID token claims validated', [
				'state'  => null,
				'issuer' => $issuer,
				'sub'    => $claims->get('sub'),
				'aud'    => $claims->get('aud'),
				'exp'    => $claims->get('exp'),
			]);

			return $claims;
		} catch( AuthenticationFailedException $e ) {
			throw new AuthenticationFailedException($e->getMessage(), idToken: $idToken, state: $e->getState(), previous: $e);
		}
	}

}
