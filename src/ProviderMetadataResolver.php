<?php

namespace Oidc;

use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Resolves one provider endpoint value at a time: an explicit override on
 * the config wins outright; otherwise it falls back to fetching
 * `.well-known/openid-configuration` and memoizes that document per
 * provider URL for the life of this resolver, so asking for several
 * endpoints in the same request costs one discovery fetch, not several.
 *
 * Every way discovery can fail - unreachable, non-200, invalid JSON, or a
 * document that just does not carry the endpoint asked for - is logged
 * before the generic ProviderDiscoveryException is thrown, matching
 * TokenEndpointClient's logging for the equivalent failures against the
 * token endpoint.
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
		private readonly LoggerInterface $logger = new NullLogger,
		private readonly ?string $state = null,
	) {
	}

	/**
	 * Returns a copy of this resolver carrying one flow's correlation id - see
	 * ClaimsValidator::withState() for why this returns a new instance instead of mutating
	 * the shared one. Carries over whatever is already memoized in `$discovered`, so a
	 * document already fetched before scoping (or by an earlier resolve() in the same flow)
	 * still only costs one fetch - scoping must not throw away that memoization.
	 */
	public function withState( ?string $state ): self {
		$scoped = new self($this->httpFetcher, $this->logger, $state);
		$scoped->discovered = $this->discovered;

		return $scoped;
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
			$this->logger->error('OIDC: provider configuration is missing the requested endpoint', [
				'endpoint_key' => $endpointKey,
				'state'        => $this->state,
			]);

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
			$this->logger->error('OIDC: cannot discover provider configuration without a providerUrl or issuer', [ 'state' => $this->state ]);

			throw new ProviderDiscoveryException('Cannot discover provider configuration without a providerUrl or issuer');
		}

		if( isset($this->discovered[$providerUrl]) ) {
			return $this->discovered[$providerUrl];
		}

		$url = rtrim($providerUrl, '/') . '/.well-known/openid-configuration';

		try {
			$response = $this->httpFetcher->fetch($url, null, verifyTls: $config->verifyTls);
		} catch( HttpTransportException $e ) {
			$this->logger->error('OIDC: unable to fetch provider configuration', [
				'url'       => $url,
				'exception' => $e,
				'state'     => $this->state,
			]);

			throw new ProviderDiscoveryException("Unable to fetch provider configuration from {$url}", previous: $e);
		}

		if( $response->status !== 200 ) {
			$this->logger->error('OIDC: provider configuration endpoint returned an unsuccessful response', [
				'url'         => $url,
				'http_status' => $response->status,
				'state'       => $this->state,
			]);

			throw new ProviderDiscoveryException("Provider configuration endpoint {$url} returned HTTP {$response->status}");
		}

		$decoded = json_decode($response->body, true);

		if( !is_array($decoded) ) {
			$this->logger->error('OIDC: provider configuration endpoint returned invalid JSON', [
				'url'         => $url,
				'http_status' => $response->status,
				'state'       => $this->state,
			]);

			throw new ProviderDiscoveryException("Provider configuration endpoint {$url} returned invalid JSON");
		}

		return $this->discovered[$providerUrl] = $decoded;
	}

}
