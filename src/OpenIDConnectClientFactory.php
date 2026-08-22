<?php

namespace Oidc;

use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Assembles an OpenIDConnectClient and every collaborator it is composed of,
 * from a shared HTTP fetcher and clock, so a caller wiring up one client per
 * integration never reaches for `new` on the client or its collaborators
 * (AuthorizationStateStore, ProviderMetadataResolver, IdTokenVerifier,
 * ClaimsValidator, TokenEndpointClient, CurlHttpFetcher, CurrentClock) itself.
 */
class OpenIDConnectClientFactory {

	public function __construct(
		private readonly HttpFetcherInterface $httpFetcher = new CurlHttpFetcher,
		private readonly ClockInterface $clock = new CurrentClock,
	) {
	}

	public function make( CacheInterface $stateCache, string $cacheKeySuffix = "" ): OpenIDConnectClient {
		$providerMetadataResolver = new ProviderMetadataResolver($this->httpFetcher);

		return new OpenIDConnectClient(
			new AuthorizationStateStore($stateCache, $cacheKeySuffix),
			$providerMetadataResolver,
			new IdTokenVerifier($this->httpFetcher, $this->clock),
			new ClaimsValidator,
			new TokenEndpointClient($this->httpFetcher, $providerMetadataResolver),
			$this->httpFetcher,
		);
	}

}
