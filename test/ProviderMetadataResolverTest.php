<?php

namespace Oidc;

use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\Fakes\ArrayLogger;
use Oidc\Fakes\FakeHttpFetcher;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

class ProviderMetadataResolverTest extends TestCase {

	/**
	 * @param array<string,string> $endpointOverrides
	 */
	private function configWithProviderUrl( array $endpointOverrides = [] ): OpenIDConnectClientConfig {
		return new OpenIDConnectClientConfig(
			clientId: 'client-id',
			clientSecret: 'client-secret',
			redirectUrl: 'https://example.com/callback',
			providerUrl: 'https://issuer.example.com',
			endpointOverrides: $endpointOverrides,
		);
	}

	public function testResolveReturnsAnOverrideWithoutFetching(): void {
		$fetcher  = new FakeHttpFetcher;
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);
		$config   = $this->configWithProviderUrl([ ProviderMetadataResolver::AUTHORIZATION_ENDPOINT => 'https://issuer.example.com/authorize' ]);

		$endpoint = $resolver->resolve($config, ProviderMetadataResolver::AUTHORIZATION_ENDPOINT);

		$this->assertSame('https://issuer.example.com/authorize', $endpoint);
		$this->assertSame([], $fetcher->requests);
	}

	public function testResolveRejectsAnOverrideThatViolatesTheUrlPolicy(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger);
		$config   = $this->configWithProviderUrl([ ProviderMetadataResolver::TOKEN_ENDPOINT => 'http://issuer.example.com/token' ]);

		try {
			$resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: endpoint URL does not satisfy the configured URL policy', $records[0]['message']);
		$this->assertSame(ProviderMetadataResolver::TOKEN_ENDPOINT, $records[0]['context']['endpoint_key']);
		$this->assertSame('http://issuer.example.com/token', $records[0]['context']['url']);
	}

	public function testResolveRejectsADiscoveredEndpointThatViolatesTheUrlPolicy(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'         => 'https://issuer.example.com',
				'token_endpoint' => 'http://attacker.example.net/token',
			], JSON_THROW_ON_ERROR), 200),
		);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);

		$this->expectException(ProviderDiscoveryException::class);

		$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);
	}

	public function testResolveDoesNotFetchDiscoveryWhenTheDiscoveryUrlItselfViolatesTheUrlPolicy(): void {
		$fetcher = new FakeHttpFetcher;
		$config  = new OpenIDConnectClientConfig(
			clientId: 'client-id',
			clientSecret: 'client-secret',
			redirectUrl: 'https://example.com/callback',
			providerUrl: 'http://issuer.example.com',
		);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);

		try {
			$resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$this->assertSame([], $fetcher->requests, 'a disallowed discovery URL must never be fetched');
	}

	public function testResolveAllowsHttpWhenInsecureSchemesAreOptedInto(): void {
		$fetcher = new FakeHttpFetcher;
		$config  = new OpenIDConnectClientConfig(
			clientId: 'client-id',
			clientSecret: 'client-secret',
			redirectUrl: 'https://example.com/callback',
			endpointOverrides: [ ProviderMetadataResolver::TOKEN_ENDPOINT => 'http://issuer.example.com/token' ],
			allowInsecureSchemes: true,
		);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);

		$this->assertSame('http://issuer.example.com/token', $resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT));
	}

	public function testResolveRejectsAHostNotInTheAllowlist(): void {
		$fetcher = new FakeHttpFetcher;
		$config  = $this->configWithProviderUrl([ ProviderMetadataResolver::TOKEN_ENDPOINT => 'https://issuer.example.com/token' ])
			->withAllowedHosts([ 'somewhere-else.example.com' ]);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);

		$this->expectException(ProviderDiscoveryException::class);

		$resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
	}

	public function testResolveAllowsAHostInTheAllowlist(): void {
		$fetcher = new FakeHttpFetcher;
		$config  = $this->configWithProviderUrl([ ProviderMetadataResolver::TOKEN_ENDPOINT => 'https://issuer.example.com/token' ])
			->withAllowedHosts([ 'issuer.example.com' ]);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);

		$this->assertSame('https://issuer.example.com/token', $resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT));
	}

	public function testResolveRejectsAMismatchedIssuerInTheDiscoveryDocument(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'         => 'https://attacker.example.net',
				'token_endpoint' => 'https://issuer.example.com/token',
			], JSON_THROW_ON_ERROR), 200),
		);
		$logger   = new ArrayLogger;
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger);

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: provider configuration issuer does not match the URL used to fetch it', $records[0]['message']);
		$this->assertSame('https://issuer.example.com', $records[0]['context']['expected']);
		$this->assertSame('https://attacker.example.net', $records[0]['context']['actual']);
	}

	public function testResolveTreatsATrailingSlashDifferenceInTheIssuerAsAMatch(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'         => 'https://issuer.example.com/',
				'token_endpoint' => 'https://issuer.example.com/token',
			], JSON_THROW_ON_ERROR), 200),
		);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);

		$this->assertSame('https://issuer.example.com/token', $resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT));
	}

	public function testResolveFetchesDiscoveryDocumentWhenNoOverride(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'         => 'https://issuer.example.com',
				'token_endpoint' => 'https://issuer.example.com/token',
			], JSON_THROW_ON_ERROR), 200),
		);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);

		$endpoint = $resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);

		$this->assertSame('https://issuer.example.com/token', $endpoint);
	}

	public function testResolveMemoizesTheDiscoveryDocumentPerProvider(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'                 => 'https://issuer.example.com',
				'token_endpoint'         => 'https://issuer.example.com/token',
				'authorization_endpoint' => 'https://issuer.example.com/authorize',
			], JSON_THROW_ON_ERROR), 200),
		);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);
		$config   = $this->configWithProviderUrl();

		$resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
		$resolver->resolve($config, ProviderMetadataResolver::AUTHORIZATION_ENDPOINT);

		$this->assertCount(1, $fetcher->requests, 'second resolve() for the same provider must not re-fetch discovery');
	}

	public function testResolveThrowsWithNoProviderUrlOrIssuer(): void {
		$resolver = new ProviderMetadataResolver(new FakeHttpFetcher, new UrlPolicy);
		$config   = new OpenIDConnectClientConfig('client-id', 'client-secret', 'https://example.com/callback');

		$this->expectException(ProviderDiscoveryException::class);

		$resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
	}

	public function testResolveFallsBackToIssuerWhenNoProviderUrl(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'         => 'https://issuer.example.com',
				'token_endpoint' => 'https://issuer.example.com/token',
			], JSON_THROW_ON_ERROR), 200),
		);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);
		$config   = new OpenIDConnectClientConfig(
			clientId: 'client-id',
			clientSecret: 'client-secret',
			redirectUrl: 'https://example.com/callback',
			issuer: 'https://issuer.example.com',
		);

		$this->assertSame('https://issuer.example.com/token', $resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT));
	}

	public function testResolveThrowsOnNonSuccessStatus(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo('https://issuer.example.com/.well-known/openid-configuration', new FetchResponse('not found', 404));
		$logger   = new ArrayLogger;
		$resolver = (new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger))->withState('the-state');

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException $e ) {
			$this->assertSame('the-state', $e->getState());
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: provider configuration endpoint returned an unsuccessful response', $records[0]['message']);
		$this->assertSame(404, $records[0]['context']['http_status']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testResolveThrowsOnUnexpectedContentType(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse('<html>not a discovery document</html>', 200, 'text/html'),
		);
		$logger   = new ArrayLogger;
		$resolver = (new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger))->withState('the-state');

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: provider configuration endpoint returned an unexpected content type', $records[0]['message']);
		$this->assertSame('text/html', $records[0]['context']['content_type']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testResolveThrowsOnInvalidJson(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo('https://issuer.example.com/.well-known/openid-configuration', new FetchResponse('not json', 200));
		$logger   = new ArrayLogger;
		$resolver = (new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger))->withState('the-state');

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException $e ) {
			$this->assertInstanceOf(\JsonException::class, $e->getPrevious());
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: provider configuration endpoint returned invalid JSON', $records[0]['message']);
		$this->assertInstanceOf(\JsonException::class, $records[0]['context']['exception']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testResolveThrowsWhenEndpointMissingFromDocument(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([ 'issuer' => 'https://issuer.example.com' ], JSON_THROW_ON_ERROR), 200),
		);
		$logger   = new ArrayLogger;
		$resolver = (new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger))->withState('the-state');

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: provider configuration is missing the requested endpoint', $records[0]['message']);
		$this->assertSame(ProviderMetadataResolver::TOKEN_ENDPOINT, $records[0]['context']['endpoint_key']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testResolveWrapsHttpTransportFailures(): void {
		$fetcher = new FakeHttpFetcher;
		$transport = new HttpTransportException('connection refused');
		$fetcher->failWith('https://issuer.example.com/.well-known/openid-configuration', $transport);
		$logger   = new ArrayLogger;
		$resolver = (new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger))->withState('the-state');

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: unable to fetch provider configuration', $records[0]['message']);
		$this->assertSame($transport, $records[0]['context']['exception']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testResolveDoesNotLogOnSuccess(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'         => 'https://issuer.example.com',
				'token_endpoint' => 'https://issuer.example.com/token',
			], JSON_THROW_ON_ERROR), 200),
		);
		$logger   = new ArrayLogger;
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger);

		$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);

		$this->assertSame([], $logger->recordsAboveDebug());
	}

	public function testResolveLogsAnOverrideAsItsOwnSource(): void {
		$fetcher  = new FakeHttpFetcher;
		$logger   = new ArrayLogger;
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger);
		$config   = $this->configWithProviderUrl([ ProviderMetadataResolver::AUTHORIZATION_ENDPOINT => 'https://issuer.example.com/authorize' ]);

		$resolver->resolve($config, ProviderMetadataResolver::AUTHORIZATION_ENDPOINT);

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$this->assertSame('OIDC: resolved endpoint from a config override', $records[0]['message']);
		$this->assertSame(ProviderMetadataResolver::AUTHORIZATION_ENDPOINT, $records[0]['context']['endpoint_key']);
		$this->assertSame('https://issuer.example.com/authorize', $records[0]['context']['value']);
	}

	public function testResolveLogsADiscoveredEndpointAndTheFreshFetchAndTheIssuerMatch(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'         => 'https://issuer.example.com',
				'token_endpoint' => 'https://issuer.example.com/token',
			], JSON_THROW_ON_ERROR), 200),
		);
		$logger   = new ArrayLogger;
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger);

		$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$this->assertSame('OIDC: provider configuration issuer matches the URL used to fetch it', $records[0]['message']);
		$this->assertSame('OIDC: fetched a fresh provider configuration', $records[1]['message']);
		$this->assertSame([ 'issuer', 'token_endpoint' ], $records[1]['context']['advertised_endpoints']);
		$this->assertSame('OIDC: resolved endpoint from provider discovery', $records[2]['message']);
		$this->assertSame('https://issuer.example.com/token', $records[2]['context']['value']);
	}

	public function testResolveLogsReusingAnAlreadyFetchedDocumentOnASecondCall(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'                 => 'https://issuer.example.com',
				'token_endpoint'         => 'https://issuer.example.com/token',
				'authorization_endpoint' => 'https://issuer.example.com/authorize',
			], JSON_THROW_ON_ERROR), 200),
		);
		$logger   = new ArrayLogger;
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger);
		$config   = $this->configWithProviderUrl();

		$resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
		$resolver->resolve($config, ProviderMetadataResolver::AUTHORIZATION_ENDPOINT);

		$reuseRecords = array_values(array_filter(
			$logger->recordsAt(LogLevel::DEBUG),
			static fn ( array $record ): bool => $record['message'] === 'OIDC: reusing an already-fetched provider configuration',
		));
		$this->assertCount(1, $reuseRecords);
		$this->assertSame('https://issuer.example.com', $reuseRecords[0]['context']['provider_url']);
	}

	public function testWithStateCarriesOverAlreadyDiscoveredDocuments(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'                 => 'https://issuer.example.com',
				'token_endpoint'         => 'https://issuer.example.com/token',
				'authorization_endpoint' => 'https://issuer.example.com/authorize',
			], JSON_THROW_ON_ERROR), 200),
		);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);
		$config   = $this->configWithProviderUrl();

		$resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
		$scoped = $resolver->withState('the-state');
		$scoped->resolve($config, ProviderMetadataResolver::AUTHORIZATION_ENDPOINT);

		$this->assertCount(1, $fetcher->requests, 'withState() must not throw away memoization already built up before scoping');
	}

	/**
	 * withState() copies `$discovered` into the new instance rather than mutating the
	 * original (see its docblock), which today is safe only because PHP arrays are
	 * copy-on-write value types - a later regression that shared the array by reference
	 * instead (e.g. `$scoped->discovered = &$this->discovered`) would make a document fetched
	 * through one instance silently show up as already-memoized in the other. Fetching
	 * something new through the scoped copy, then asking the ORIGINAL for the same provider,
	 * forces a second real fetch only if the two `$discovered` caches are genuinely
	 * independent.
	 */
	public function testWithStateDoesNotShareLaterMemoizationWithTheOriginalInstance(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'issuer'                 => 'https://issuer.example.com',
				'token_endpoint'         => 'https://issuer.example.com/token',
				'authorization_endpoint' => 'https://issuer.example.com/authorize',
			], JSON_THROW_ON_ERROR), 200),
		);
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy);
		$config   = $this->configWithProviderUrl();

		$scoped = $resolver->withState('the-state');
		$scoped->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
		$resolver->resolve($config, ProviderMetadataResolver::AUTHORIZATION_ENDPOINT);

		$this->assertCount(2, $fetcher->requests, 'a document fetched through a scoped copy must not appear pre-memoized on the original instance');
	}

	public function testWithStateDoesNotAffectTheOriginalInstance(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo('https://issuer.example.com/.well-known/openid-configuration', new FetchResponse('not found', 404));
		$logger   = new ArrayLogger;
		$resolver = new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger);

		$resolver->withState('the-state');

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$this->assertNull($logger->recordsAt(LogLevel::ERROR)[0]['context']['state']);
	}

}
