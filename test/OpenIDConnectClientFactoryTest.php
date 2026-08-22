<?php

namespace Oidc;

use Oidc\Fakes\FakeHttpFetcher;
use Oidc\Fakes\InMemoryCache;
use PHPUnit\Framework\TestCase;

class OpenIDConnectClientFactoryTest extends TestCase {

	private const TOKEN_ENDPOINT = 'https://issuer.example.com/token';

	public function testCreateReturnsAWorkingClient(): void {
		$client = (new OpenIDConnectClientFactory)->make(new InMemoryCache);

		$this->assertInstanceOf(Interfaces\TokenGrantClientInterface::class, $client);
		$this->assertInstanceOf(Interfaces\UserInfoClientInterface::class, $client);
	}

	public function testCreateUsesTheInjectedHttpFetcherRatherThanADefault(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(
			body: '{"access_token":"the-access-token","token_type":"Bearer"}',
			status: 200,
			contentType: 'application/json',
		));

		$factory = new OpenIDConnectClientFactory($fetcher);
		$client  = $factory->make(new InMemoryCache);

		$config = new OpenIDConnectClientConfig(
			clientId: 'the-client-id',
			clientSecret: 'the-client-secret',
			redirectUrl: '',
			endpointOverrides: [
				ProviderMetadataResolver::TOKEN_ENDPOINT => self::TOKEN_ENDPOINT,
			],
		);

		$result = $client->requestClientCredentialsToken($config);

		$this->assertSame('the-access-token', $result->accessToken);
		$this->assertCount(1, $fetcher->requests);
	}

	public function testCreatePassesTheCacheKeyThrough(): void {
		$cache = new InMemoryCache;
		$config = new OpenIDConnectClientConfig(
			clientId: 'the-client-id',
			clientSecret: 'the-client-secret',
			redirectUrl: 'https://example.com/callback',
			issuer: 'https://issuer.example.com',
			endpointOverrides: [
				ProviderMetadataResolver::AUTHORIZATION_ENDPOINT => 'https://issuer.example.com/authorize',
			],
		);

		$factory = new OpenIDConnectClientFactory(new FakeHttpFetcher);
		$first   = $factory->make($cache, 'first-key');
		$second  = $factory->make($cache, 'second-key');

		$first->buildAuthorizationCodeRedirect($config);

		$this->assertTrue($cache->has('henderjon.oidc.state.first-key'));
		$this->assertFalse($cache->has('henderjon.oidc.state.second-key'));

		$second->buildAuthorizationCodeRedirect($config);

		$this->assertTrue($cache->has('henderjon.oidc.state.second-key'));
	}

}
