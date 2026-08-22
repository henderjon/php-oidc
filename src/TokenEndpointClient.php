<?php

namespace Henderjon\Oidc;

use Henderjon\Oidc\Exceptions\HttpTransportException;
use Henderjon\Oidc\Exceptions\TokenRequestException;

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
	) {
	}

	/**
	 * @throws TokenRequestException
	 */
	public function exchangeAuthorizationCode( OpenIDConnectClientConfig $config, string $code ): TokenResult {
		return $this->request($config, [
			'grant_type'   => 'authorization_code',
			'code'         => $code,
			'redirect_uri' => $config->redirectUrl,
		]);
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
			throw new TokenRequestException("Unable to reach token endpoint {$endpoint}", previous: $e);
		}

		$decoded = json_decode($response->body, true);

		if( !is_array($decoded) ) {
			throw new TokenRequestException("Token endpoint {$endpoint} returned invalid JSON");
		}

		if( $response->status !== 200 ) {
			$error = is_string($decoded['error'] ?? null) ? $decoded['error'] : "HTTP {$response->status}";

			throw new TokenRequestException("Token request failed: {$error}");
		}

		return new TokenResult($decoded);
	}

}
