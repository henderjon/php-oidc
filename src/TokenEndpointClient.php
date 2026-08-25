<?php

namespace Oidc;

use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\TokenRequestException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Posts to `token_endpoint` for the three grants this module supports:
 * authorization code exchange (the interactive login flows), client
 * credentials (non-interactive, see TokenGrantClientInterface), and refresh
 * token (see RefreshTokenClientInterface). All three share the same
 * request/response shape - only `grant_type` and its params differ - so
 * one collaborator handles all of them.
 */
final class TokenEndpointClient {

	public function __construct(
		private readonly HttpFetcherInterface $httpFetcher,
		private readonly ProviderMetadataResolver $providerMetadataResolver,
		private readonly LoggerInterface $logger = new NullLogger,
		private readonly ?string $state = null,
	) {
	}

	/**
	 * Returns a copy of this client carrying one flow's correlation id - see
	 * ClaimsValidator::withState() for why this returns a new instance instead of mutating
	 * the shared one.
	 *
	 * Takes the caller's own already-scoped ProviderMetadataResolver rather than scoping
	 * `$this->providerMetadataResolver` itself, so both this client's token_endpoint
	 * resolution and whatever else the caller resolves during the same flow (jwks_uri, for
	 * one) share one discovery fetch instead of two independently-scoped copies each
	 * fetching it themselves.
	 */
	public function withState( ?string $state, ProviderMetadataResolver $providerMetadataResolver ): self {
		return new self($this->httpFetcher, $providerMetadataResolver, $this->logger, $state);
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
	 * @param list<string>                       $scopes
	 * @param array<string,string|list<string>>  $extraParams Provider-specific extensions to
	 *                                                         the request body. A string value
	 *                                                         is sent as-is - this covers a
	 *                                                         single `audience`, but also a
	 *                                                         provider whose multi-value
	 *                                                         convention is one space-separated
	 *                                                         string in that same key (e.g. Ory
	 *                                                         Hydra's `audience`, the same
	 *                                                         convention `scope` already uses) -
	 *                                                         join it yourself before passing it
	 *                                                         in. A list value is sent as that
	 *                                                         key repeated bare
	 *                                                         (`resource=a&resource=b`), which is
	 *                                                         the different convention RFC 8707
	 *                                                         specifically wants for `resource`;
	 *                                                         do not assume it is what any given
	 *                                                         provider wants for `audience` too.
	 *                                                         Merged in before `grant_type`/
	 *                                                         `scope` are set, so neither can be
	 *                                                         overridden this way, same as
	 *                                                         `OpenIDConnectClientConfig::$extraAuthParams`
	 *                                                         on the authorization request.
	 * @throws TokenRequestException
	 */
	public function requestClientCredentialsToken( OpenIDConnectClientConfig $config, array $scopes = [], array $extraParams = [] ): TokenResult {
		$params = array_merge($extraParams, [ 'grant_type' => 'client_credentials' ]);

		// scope is reserved even when $scopes is empty - "no scopes requested" must not leave
		// an extraParams-supplied scope to leak through unprotected.
		unset($params['scope']);

		if( $scopes !== [] ) {
			$params['scope'] = implode(' ', $scopes);
		}

		return $this->request($config, $params);
	}

	/**
	 * OpenID Connect Core 1.0 §12.1: the refresh request authenticates to the Token Endpoint
	 * the same way as any other token request - handled by request()'s existing
	 * ClientAuthenticator::apply() call, nothing specific to this grant.
	 *
	 * @throws TokenRequestException
	 */
	public function refreshToken( OpenIDConnectClientConfig $config, string $refreshToken ): TokenResult {
		return $this->request($config, [
			'grant_type'    => 'refresh_token',
			'refresh_token' => $refreshToken,
		]);
	}

	/**
	 * @param array<string,string|list<string>> $params
	 * @throws TokenRequestException
	 */
	private function request( OpenIDConnectClientConfig $config, array $params ): TokenResult {
		$endpoint             = $this->providerMetadataResolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
		[ $params, $headers ] = ClientAuthenticator::apply($config, $params);

		try {
			$response = $this->httpFetcher->fetch($endpoint, $this->buildRequestBody($params), $headers);
		} catch( HttpTransportException $e ) {
			$this->logger->error('OIDC: token endpoint request could not be completed', [
				'endpoint'    => $endpoint,
				'http_status' => null,
				'exception'   => $e,
				'state'       => $this->state,
			]);

			throw new TokenRequestException("Unable to reach token endpoint {$endpoint}", previous: $e);
		}

		if( !JsonContentTypePolicy::isAcceptable($response->contentType) ) {
			$this->logger->error('OIDC: token endpoint returned an unexpected content type', [
				'endpoint'     => $endpoint,
				'http_status'  => $response->status,
				'content_type' => $response->contentType,
				'state'        => $this->state,
			]);

			throw new TokenRequestException("Token endpoint {$endpoint} returned an unexpected content type", $response->status, $response->body);
		}

		$decoded = json_decode($response->body, true);

		if( $response->status !== 200 ) {
			$error = is_array($decoded) && is_string($decoded['error'] ?? null) ? $decoded['error'] : "HTTP {$response->status}";

			$this->logger->error('OIDC: token endpoint returned an unsuccessful response', [
				'endpoint'       => $endpoint,
				'http_status'    => $response->status,
				'provider_error' => is_array($decoded) && is_string($decoded['error'] ?? null) ? $decoded['error'] : null,
				'content_type'   => $response->contentType,
				'state'          => $this->state,
			]);

			throw new TokenRequestException("Token request failed: {$error}", $response->status, $response->body);
		}

		if( !is_array($decoded) ) {
			$this->logger->error('OIDC: token endpoint returned invalid JSON', [
				'endpoint'     => $endpoint,
				'http_status'  => $response->status,
				'content_type' => $response->contentType,
				'state'        => $this->state,
			]);

			throw new TokenRequestException("Token endpoint {$endpoint} returned invalid JSON", $response->status, $response->body);
		}

		return new TokenResult($decoded, $this->logger, $this->state);
	}

	/**
	 * `http_build_query()` cannot produce this shape on its own - it bracket-encodes an array
	 * value (`resource[0]=a&resource[1]=b`), not the bare-repeated-key form
	 * (`resource=a&resource=b`) RFC 8707 and most authorization servers expect for a
	 * multi-valued parameter like `resource`.
	 *
	 * @param array<string,string|list<string>> $params
	 */
	private function buildRequestBody( array $params ): string {
		$pairs = [];

		foreach( $params as $key => $value ) {
			foreach( (array)$value as $item ) {
				$pairs[] = urlencode($key) . '=' . urlencode($item);
			}
		}

		return implode('&', $pairs);
	}

}
