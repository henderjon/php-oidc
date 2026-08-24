<?php

namespace Oidc;

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\UserInfoRequestException;
use Oidc\Interfaces\TokenGrantClientInterface;
use Oidc\Interfaces\UserInfoClientInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * The real engine behind every capability interface in this module.
 * Composes (never extends) a handful of small, independently-testable
 * collaborators - nothing here talks to curl, JWKS, or a cache directly.
 *
 * Takes every collaborator as a constructor argument rather than building
 * any of them itself - OpenIDConnectClientFactory is where they get
 * assembled. Construct this class directly only from a factory or test code.
 *
 * UserInfoClientInterface already extends AuthorizationFlowClientInterface,
 * so implementing it here covers both without listing the base interface
 * separately.
 */
final class OpenIDConnectClient implements
	TokenGrantClientInterface,
	UserInfoClientInterface {

	private const DEFAULT_SCOPE = 'openid';

	public function __construct(
		private readonly AuthorizationStateStore $stateStore,
		private readonly ProviderMetadataResolver $providerMetadataResolver,
		private readonly IdTokenVerifier $idTokenVerifier,
		private readonly ClaimsValidator $claimsValidator,
		private readonly TokenEndpointClient $tokenEndpointClient,
		private readonly HttpFetcherInterface $httpFetcher,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	public function buildAuthorizationCodeRedirect( OpenIDConnectClientConfig $config ): AuthorizationRedirect {
		return $this->buildRedirect($config, responseType: 'code');
	}

	public function completeAuthorizationCodeFlow(
		OpenIDConnectClientConfig $config,
		IncomingAuthorizationResponse $response,
	): AuthenticationResult {
		$flow = $this->consumeFlow($response);

		$this->assertNoProviderError($response);

		if( $flow === null ) {
			throw new AuthenticationFailedException('Unable to verify state');
		}

		if( $response->code === null ) {
			throw new AuthenticationFailedException('Callback is missing the authorization code');
		}

		if( $config->pkce === PkceMode::Required && $flow->codeVerifier === null ) {
			$this->logger->warning('OIDC: PKCE code verifier missing for a Required flow', [ 'state' => $flow->state ]);

			throw new AuthenticationFailedException('Unable to verify PKCE code verifier');
		}

		$tokenResult = $this->tokenEndpointClient->exchangeAuthorizationCode($config, $response->code, $flow->codeVerifier);

		if( $tokenResult->idToken === null ) {
			$this->logger->warning('OIDC: token endpoint response is missing id_token');

			throw new AuthenticationFailedException('Token response is missing id_token');
		}

		$claims = $this->verifyAndValidateIdToken($config, $tokenResult->idToken, $flow->nonce, $tokenResult->accessToken, $config->audience);

		return new AuthenticationResult($tokenResult->idToken, $claims, $tokenResult->accessToken, $tokenResult->refreshToken);
	}

	public function buildImplicitFlowRedirect( OpenIDConnectClientConfig $config ): AuthorizationRedirect {
		return $this->buildRedirect($config, responseType: 'id_token');
	}

	public function completeImplicitFlow(
		OpenIDConnectClientConfig $config,
		IncomingAuthorizationResponse $response,
	): AuthenticationResult {
		$flow = $this->consumeFlow($response);

		$this->assertNoProviderError($response);

		if( $flow === null ) {
			throw new AuthenticationFailedException('Unable to verify state');
		}

		if( $response->idToken === null ) {
			$this->logger->warning('OIDC: callback is missing the id_token');

			throw new AuthenticationFailedException('Callback is missing the id_token');
		}

		$claims = $this->verifyAndValidateIdToken($config, $response->idToken, $flow->nonce, $response->accessToken, $config->audience);

		return new AuthenticationResult($response->idToken, $claims, $response->accessToken);
	}

	public function requestClientCredentialsToken( OpenIDConnectClientConfig $config, array $scopes = [] ): TokenResult {
		return $this->tokenEndpointClient->requestClientCredentialsToken($config, $scopes);
	}

	public function fetchUserInfo( OpenIDConnectClientConfig $config, string $accessToken ): Claims {
		$endpoint = $this->providerMetadataResolver->resolve($config, ProviderMetadataResolver::USERINFO_ENDPOINT);

		try {
			$response = $this->httpFetcher->fetch($endpoint, null, [
				'Authorization' => "Bearer {$accessToken}",
				'Accept'        => 'application/json',
			], $config->verifyTls);
		} catch( HttpTransportException $e ) {
			throw new UserInfoRequestException("Unable to reach userinfo endpoint {$endpoint}", previous: $e);
		}

		if( $response->status !== 200 ) {
			throw new UserInfoRequestException("Userinfo request failed with HTTP {$response->status}");
		}

		if( $response->contentType === 'application/jwt' ) {
			return $this->verifySignedUserInfo($config, $response->body);
		}

		$decoded = json_decode($response->body, true);

		if( !is_array($decoded) ) {
			throw new UserInfoRequestException("Userinfo endpoint {$endpoint} returned invalid JSON");
		}

		return new Claims($decoded);
	}

	private function buildRedirect( OpenIDConnectClientConfig $config, string $responseType ): AuthorizationRedirect {
		$authorizationEndpoint = $this->providerMetadataResolver->resolve($config, ProviderMetadataResolver::AUTHORIZATION_ENDPOINT);
		$codeVerifier          = $responseType === 'code' && $config->pkce !== PkceMode::Disabled ? Pkce::generateVerifier() : null;
		$flow                  = $this->stateStore->start(codeVerifier: $codeVerifier);

		$params = array_merge($config->extraAuthParams, [
			'response_type' => $responseType,
			'client_id'     => $config->clientId,
			'redirect_uri'  => $config->redirectUrl,
			'scope'         => implode(' ', array_unique([ self::DEFAULT_SCOPE, ...$config->scopes ])),
			'state'         => $flow->state,
			'nonce'         => $flow->nonce,
		]);

		if( $codeVerifier !== null ) {
			$params['code_challenge']        = Pkce::challengeFor($codeVerifier);
			$params['code_challenge_method'] = 'S256';
		}

		return new AuthorizationRedirect($this->appendQuery($authorizationEndpoint, $params));
	}

	/**
	 * @param array<string,string> $params
	 */
	private function appendQuery( string $url, array $params ): string {
		$separator = str_contains($url, '?') ? '&' : '?';

		return $url . $separator . http_build_query($params);
	}

	/**
	 * @throws AuthenticationFailedException
	 */
	private function assertNoProviderError( IncomingAuthorizationResponse $response ): void {
		$summary = $response->errorSummary();

		if( $summary !== null ) {
			throw new AuthenticationFailedException("Provider returned an error: {$summary}");
		}
	}

	/**
	 * Consumes the attempt identified by the callback's `state`, if any. Returns null
	 * when there is no state to look up, or no attempt matches it - the caller must
	 * fail closed either way; it is not this method's job to decide which message to
	 * throw, since a provider error should be reported ahead of a generic state failure.
	 * The distinction between "no state at all" and "state did not match" is logged
	 * (here and in AuthorizationStateStore respectively) rather than reflected in the
	 * exception, which stays generic for whoever ends up seeing it unhandled.
	 */
	private function consumeFlow( IncomingAuthorizationResponse $response ): ?FlowState {
		if( $response->state === null ) {
			$this->logger->warning('OIDC: callback is missing the state parameter');

			return null;
		}

		return $this->stateStore->consume($response->state);
	}

	/**
	 * @param list<string>|string|null $audience
	 * @throws AuthenticationFailedException
	 */
	private function verifyAndValidateIdToken(
		OpenIDConnectClientConfig $config,
		string $idToken,
		string $expectedNonce,
		?string $accessToken,
		array|string|null $audience,
	): Claims {
		$jwksUri = $this->providerMetadataResolver->resolve($config, ProviderMetadataResolver::JWKS_URI);
		$claims  = $this->idTokenVerifier->verify($idToken, $jwksUri, $config->clientSecret, $accessToken, $config->verifyTls);

		$issuer = $config->issuer ?? $config->providerUrl;

		if( $issuer === null ) {
			throw new AuthenticationFailedException('No issuer configured to validate the ID token against');
		}

		$this->claimsValidator->validateIssuer($claims, $issuer);
		$this->claimsValidator->validateNonce($claims, $expectedNonce);

		// The `aud` claim must always be checked (it's spec-mandated, not optional) - it just
		// defaults to clientId unless the config overrides it with a distinct expected audience.
		$this->claimsValidator->validateAudience($claims, $audience ?? $config->clientId);

		return $claims;
	}

	/**
	 * @throws UserInfoRequestException
	 */
	private function verifySignedUserInfo( OpenIDConnectClientConfig $config, string $jwt ): Claims {
		$jwksUri = $this->providerMetadataResolver->resolve($config, ProviderMetadataResolver::JWKS_URI);

		try {
			return $this->idTokenVerifier->verify($jwt, $jwksUri, $config->clientSecret, verifyTls: $config->verifyTls);
		} catch( AuthenticationFailedException $e ) {
			throw new UserInfoRequestException('Signed userinfo response failed verification', previous: $e);
		}
	}

}
