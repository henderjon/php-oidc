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
		$resolver = new ProviderMetadataResolver($fetcher);
		$config   = $this->configWithProviderUrl([ ProviderMetadataResolver::AUTHORIZATION_ENDPOINT => 'https://issuer.example.com/authorize' ]);

		$endpoint = $resolver->resolve($config, ProviderMetadataResolver::AUTHORIZATION_ENDPOINT);

		$this->assertSame('https://issuer.example.com/authorize', $endpoint);
		$this->assertSame([], $fetcher->requests);
	}

	public function testResolveFetchesDiscoveryDocumentWhenNoOverride(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([ 'token_endpoint' => 'https://issuer.example.com/token' ], JSON_THROW_ON_ERROR), 200),
		);
		$resolver = new ProviderMetadataResolver($fetcher);

		$endpoint = $resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);

		$this->assertSame('https://issuer.example.com/token', $endpoint);
	}

	public function testResolveMemoizesTheDiscoveryDocumentPerProvider(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([
				'token_endpoint'         => 'https://issuer.example.com/token',
				'authorization_endpoint' => 'https://issuer.example.com/authorize',
			], JSON_THROW_ON_ERROR), 200),
		);
		$resolver = new ProviderMetadataResolver($fetcher);
		$config   = $this->configWithProviderUrl();

		$resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
		$resolver->resolve($config, ProviderMetadataResolver::AUTHORIZATION_ENDPOINT);

		$this->assertCount(1, $fetcher->requests, 'second resolve() for the same provider must not re-fetch discovery');
	}

	public function testResolveThrowsWithNoProviderUrlOrIssuer(): void {
		$resolver = new ProviderMetadataResolver(new FakeHttpFetcher);
		$config   = new OpenIDConnectClientConfig('client-id', 'client-secret', 'https://example.com/callback');

		$this->expectException(ProviderDiscoveryException::class);

		$resolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);
	}

	public function testResolveFallsBackToIssuerWhenNoProviderUrl(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(
			'https://issuer.example.com/.well-known/openid-configuration',
			new FetchResponse(json_encode([ 'token_endpoint' => 'https://issuer.example.com/token' ], JSON_THROW_ON_ERROR), 200),
		);
		$resolver = new ProviderMetadataResolver($fetcher);
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
		$resolver = new ProviderMetadataResolver($fetcher, $logger);

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT, state: 'the-state');
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: provider configuration endpoint returned an unsuccessful response', $records[0]['message']);
		$this->assertSame(404, $records[0]['context']['http_status']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testResolveThrowsOnInvalidJson(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo('https://issuer.example.com/.well-known/openid-configuration', new FetchResponse('not json', 200));
		$logger   = new ArrayLogger;
		$resolver = new ProviderMetadataResolver($fetcher, $logger);

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT, state: 'the-state');
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: provider configuration endpoint returned invalid JSON', $records[0]['message']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testResolveThrowsWhenEndpointMissingFromDocument(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo('https://issuer.example.com/.well-known/openid-configuration', new FetchResponse(json_encode([], JSON_THROW_ON_ERROR), 200));
		$logger   = new ArrayLogger;
		$resolver = new ProviderMetadataResolver($fetcher, $logger);

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT, state: 'the-state');
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
		$resolver = new ProviderMetadataResolver($fetcher, $logger);

		try {
			$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT, state: 'the-state');
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
			new FetchResponse(json_encode([ 'token_endpoint' => 'https://issuer.example.com/token' ], JSON_THROW_ON_ERROR), 200),
		);
		$logger   = new ArrayLogger;
		$resolver = new ProviderMetadataResolver($fetcher, $logger);

		$resolver->resolve($this->configWithProviderUrl(), ProviderMetadataResolver::TOKEN_ENDPOINT);

		$this->assertSame([], $logger->records);
	}

}
