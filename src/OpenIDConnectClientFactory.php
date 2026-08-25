<?php

namespace Oidc;

use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * Assembles an OpenIDConnectClient and every collaborator it is composed of,
 * from a shared HTTP fetcher, clock, and logger, so a caller wiring up one
 * client per integration never reaches for `new` on the client or its
 * collaborators (AuthorizationStateStore, ProviderMetadataResolver,
 * IdTokenVerifier, ClaimsValidator, TokenEndpointClient, RefreshTokenClient,
 * CurlHttpFetcher, CurrentClock) itself.
 *
 * RefreshTokenClient shares this call's own ProviderMetadataResolver, IdTokenVerifier,
 * ClaimsValidator, and TokenEndpointClient instances rather than getting fresh ones - all four
 * are stateless collaborators already being constructed once per make() call regardless.
 *
 * The logger defaults to a no-op, so passing one is opt-in. It only ever
 * receives detail behind a failure that already produces (or is about to
 * produce) a deliberately generic exception - see AuthorizationStateStore
 * and OpenIDConnectClient for what gets logged and why.
 */
class OpenIDConnectClientFactory {

	public function __construct(
		private readonly HttpFetcherInterface $httpFetcher = new CurlHttpFetcher,
		private readonly ClockInterface $clock = new CurrentClock,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	public function make( CacheInterface $stateCache, string $cacheKeySuffix = "" ): OpenIDConnectClient {
		$providerMetadataResolver = new ProviderMetadataResolver($this->httpFetcher, new UrlPolicy, $this->logger);
		$idTokenVerifier          = new IdTokenVerifier($this->httpFetcher, $this->clock, logger: $this->logger);
		$claimsValidator          = new ClaimsValidator($this->logger);
		$tokenEndpointClient      = new TokenEndpointClient($this->httpFetcher, $providerMetadataResolver, $this->logger);

		return new OpenIDConnectClient(
			new AuthorizationStateStore($stateCache, $cacheKeySuffix, logger: $this->logger),
			$providerMetadataResolver,
			$idTokenVerifier,
			$claimsValidator,
			$tokenEndpointClient,
			$this->httpFetcher,
			new RefreshTokenClient($providerMetadataResolver, $idTokenVerifier, $claimsValidator, $tokenEndpointClient, $this->logger),
			$this->logger,
		);
	}

}
