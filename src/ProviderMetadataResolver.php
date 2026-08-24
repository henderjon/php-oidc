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
 *
 * Every endpoint value this class ever returns - an override, or one read
 * out of a fetched discovery document - is checked against UrlPolicy
 * before it is handed back. This is the one place that check needs to
 * live: every endpoint this library ever calls (authorization, token,
 * JWKS, userinfo) is resolved through here, and no caller builds
 * credentials or sends a bearer token until resolve() returns, so gating
 * here means neither ever reaches a URL the policy rejects. The discovery
 * URL itself is checked the same way before it is ever fetched, and the
 * document's own `issuer` is checked against the URL used to fetch it -
 * both per OpenID Connect Discovery 1.0 §4.3.
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
		private readonly UrlPolicy $urlPolicy,
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
		$scoped = new self($this->httpFetcher, $this->urlPolicy, $this->logger, $state);
		$scoped->discovered = $this->discovered;

		return $scoped;
	}

	/**
	 * @throws ProviderDiscoveryException
	 */
	public function resolve( OpenIDConnectClientConfig $config, string $endpointKey ): string {
		if( isset($config->endpointOverrides[$endpointKey]) ) {
			$value = $config->endpointOverrides[$endpointKey];
			$this->assertUrlAllowed($value, $config, $endpointKey);

			return $value;
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

		$this->assertUrlAllowed($value, $config, $endpointKey);

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

		$this->assertUrlAllowed($url, $config, 'discovery');

		try {
			$response = $this->httpFetcher->fetch($url, null);
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

		if( !JsonContentTypePolicy::isAcceptable($response->contentType) ) {
			$this->logger->error('OIDC: provider configuration endpoint returned an unexpected content type', [
				'url'          => $url,
				'content_type' => $response->contentType,
				'state'        => $this->state,
			]);

			throw new ProviderDiscoveryException("Provider configuration endpoint {$url} returned an unexpected content type");
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

		$this->assertIssuerMatches($decoded, $providerUrl);

		return $this->discovered[$providerUrl] = $decoded;
	}

	/**
	 * @throws ProviderDiscoveryException
	 */
	private function assertUrlAllowed( string $url, OpenIDConnectClientConfig $config, string $endpointKey ): void {
		if( $this->urlPolicy->isAllowed($url, $config) ) {
			return;
		}

		$this->logger->error('OIDC: endpoint URL does not satisfy the configured URL policy', [
			'endpoint_key' => $endpointKey,
			'url'          => $url,
			'state'        => $this->state,
		]);

		throw new ProviderDiscoveryException("Endpoint '{$endpointKey}' resolved to a URL that does not satisfy the configured URL policy");
	}

	/**
	 * The issuer a discovery document reports must be identical to the URL used to fetch it
	 * (OpenID Connect Discovery 1.0 §4.3) - otherwise nothing else in the document can be
	 * trusted, since a network attacker or a compromised provider could otherwise redirect
	 * this client's endpoints anywhere. A trailing slash is normalized away first, since
	 * issuer identifiers are conventionally written without one and providerUrl/issuer are
	 * plain user-entered config - everything else (scheme, host, port, path) still has to
	 * match exactly.
	 *
	 * @param array<string,mixed> $document
	 * @throws ProviderDiscoveryException
	 */
	private function assertIssuerMatches( array $document, string $providerUrl ): void {
		$issuer = $document['issuer'] ?? null;

		if( is_string($issuer) && rtrim($issuer, '/') === rtrim($providerUrl, '/') ) {
			return;
		}

		$this->logger->error('OIDC: provider configuration issuer does not match the URL used to fetch it', [
			'expected' => $providerUrl,
			'actual'   => $issuer,
			'state'    => $this->state,
		]);

		throw new ProviderDiscoveryException('Provider configuration issuer does not match the URL used to fetch it');
	}

}
