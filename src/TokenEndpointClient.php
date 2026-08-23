<?php

namespace Oidc;

use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\TokenRequestException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Posts to `token_endpoint` for the two grants this module supports:
 * authorization code exchange (the interactive login flows) and client
 * credentials (non-interactive, see TokenGrantClientInterface). Both share
 * the same request/response shape - only `grant_type` and its params
 * differ - so one collaborator handles both.
 */
final class TokenEndpointClient {

	public function __construct(
		private readonly HttpFetcherInterface $httpFetcher,
		private readonly ProviderMetadataResolver $providerMetadataResolver,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @throws TokenRequestException
	 */
	public function exchangeAuthorizationCode( OpenIDConnectClientConfig $config, string $code, ?string $codeVerifier = null ): TokenResult {
		$params = [
			'grant_type'   => 'authorization_code',
			'code'         => $code,
			'redirect_uri' => $config->redirectUrl,
		];

		if( $codeVerifier !== null ) {
			$params['code_verifier'] = $codeVerifier;
		}

		return $this->request($config, $params);
	}

	/**
	 * @param list<string> $scopes
	 * @throws TokenRequestException
	 */
	public function requestClientCredentialsToken( OpenIDConnectClientConfig $config, array $scopes = [] ): TokenResult {
		$params = [ 'grant_type' => 'client_credentials' ];

		if( $scopes !== [] ) {
			$params['scope'] = implode(' ', $scopes);
		}

		return $this->request($config, $params);
	}

	/**
	 * @param array<string,string> $params
	 * @throws TokenRequestException
	 */
	private function request( OpenIDConnectClientConfig $config, array $params ): TokenResult {
		$endpoint             = $this->providerMetadataResolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
		[ $params, $headers ] = ClientAuthenticator::apply($config, $params);

		try {
			$response = $this->httpFetcher->fetch($endpoint, http_build_query($params), $headers, $config->verifyTls);
		} catch( HttpTransportException $e ) {
			$this->logger->error('OIDC: token endpoint request could not be completed', [
				'endpoint'    => $endpoint,
				'http_status' => null,
				'exception'   => $e,
			]);

			throw new TokenRequestException("Unable to reach token endpoint {$endpoint}", previous: $e);
		}

		$decoded = json_decode($response->body, true);

		if( $response->status !== 200 ) {
			$error = is_array($decoded) && is_string($decoded['error'] ?? null) ? $decoded['error'] : "HTTP {$response->status}";

			$this->logger->error('OIDC: token endpoint returned an unsuccessful response', [
				'endpoint'       => $endpoint,
				'http_status'    => $response->status,
				'provider_error' => is_array($decoded) && is_string($decoded['error'] ?? null) ? $decoded['error'] : null,
				'content_type'   => $response->contentType,
			]);

			throw new TokenRequestException("Token request failed: {$error}", $response->status, $response->body);
		}

		if( !is_array($decoded) ) {
			$this->logger->error('OIDC: token endpoint returned invalid JSON', [
				'endpoint'     => $endpoint,
				'http_status'  => $response->status,
				'content_type' => $response->contentType,
			]);

			throw new TokenRequestException("Token endpoint {$endpoint} returned invalid JSON", $response->status, $response->body);
		}

		return new TokenResult($decoded, $this->logger);
	}

}
