<?php

namespace Henderjon\Oidc;

use Henderjon\Oidc\Exceptions\HttpTransportException;
use Henderjon\Oidc\Exceptions\ProviderDiscoveryException;

/**
 * Resolves one provider endpoint value at a time: an explicit override on
 * the config wins outright; otherwise it falls back to fetching
 * `.well-known/openid-configuration` and memoizes that document per
 * provider URL for the life of this resolver, so asking for several
 * endpoints in the same request costs one discovery fetch, not several.
 */
final class ProviderMetadataResolver {

	public const AUTHORIZATION_ENDPOINT  = 'authorization_endpoint';
	public const TOKEN_ENDPOINT          = 'token_endpoint';
	public const JWKS_URI                = 'jwks_uri';
	public const USERINFO_ENDPOINT       = 'userinfo_endpoint';
	public const END_SESSION_ENDPOINT    = 'end_session_endpoint';
	public const INTROSPECTION_ENDPOINT  = 'introspection_endpoint';
	public const REVOCATION_ENDPOINT     = 'revocation_endpoint';
	public const REGISTRATION_ENDPOINT   = 'registration_endpoint';

	/** @var array<string,array<string,mixed>> Discovery documents already fetched, keyed by provider URL. */
	private array $discovered = [];

	public function __construct(
		private readonly HttpFetcherInterface $httpFetcher,
	) {
	}

	/**
	 * @throws ProviderDiscoveryException
	 */
	public function resolve( OpenIDConnectClientConfig $config, string $endpointKey ): string {
		if( isset($config->endpointOverrides[$endpointKey]) ) {
			return $config->endpointOverrides[$endpointKey];
		}

		$document = $this->fetchWellKnownConfiguration($config);
		$value    = $document[$endpointKey] ?? null;

		if( !is_string($value) || $value === '' ) {
			throw new ProviderDiscoveryException("Provider configuration is missing '{$endpointKey}'");
		}

		return $value;
	}

	/**
	 * @throws ProviderDiscoveryException
	 * @return array<string,mixed>
	 */
	private function fetchWellKnownConfiguration( OpenIDConnectClientConfig $config ): array {
		$providerUrl = $config->providerUrl ?? $config->issuer;

		if( $providerUrl === null ) {
			throw new ProviderDiscoveryException('Cannot discover provider configuration without a providerUrl or issuer');
		}

		if( isset($this->discovered[$providerUrl]) ) {
			return $this->discovered[$providerUrl];
		}

		$url = rtrim($providerUrl, '/') . '/.well-known/openid-configuration';

		try {
			$response = $this->httpFetcher->fetch($url, null, verifyTls: $config->verifyTls);
		} catch( HttpTransportException $e ) {
			throw new ProviderDiscoveryException("Unable to fetch provider configuration from {$url}", previous: $e);
		}

		if( $response->status !== 200 ) {
			throw new ProviderDiscoveryException("Provider configuration endpoint {$url} returned HTTP {$response->status}");
		}

		$decoded = json_decode($response->body, true);

		if( !is_array($decoded) ) {
			throw new ProviderDiscoveryException("Provider configuration endpoint {$url} returned invalid JSON");
		}

		return $this->discovered[$providerUrl] = $decoded;
	}

}
