<?php

namespace Henderjon\Oidc;

use Henderjon\Oidc\Exceptions\TokenRequestException;
use Henderjon\Oidc\Fakes\FakeHttpFetcher;
use PHPUnit\Framework\TestCase;

class TokenEndpointClientTest extends TestCase {

	private const TOKEN_ENDPOINT = 'https://issuer.example.com/token';

	private function config(): OpenIDConnectClientConfig {
		return new OpenIDConnectClientConfig(
			clientId: 'the-client-id',
			clientSecret: 'the-client-secret',
			redirectUrl: 'https://example.com/callback',
			endpointOverrides: [ ProviderMetadataResolver::TOKEN_ENDPOINT => self::TOKEN_ENDPOINT ],
		);
	}

	private function makeClient( FakeHttpFetcher $fetcher ): TokenEndpointClient {
		return new TokenEndpointClient($fetcher, new ProviderMetadataResolver($fetcher));
	}

	public function testExchangeAuthorizationCode(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'the-access-token', 'id_token' => 'the-id-token' ], JSON_THROW_ON_ERROR), 200));

		$result = $this->makeClient($fetcher)->exchangeAuthorizationCode($this->config(), 'the-code');

		$this->assertSame('the-access-token', $result->accessToken);
		$this->assertSame('the-id-token', $result->idToken);

		$request = $fetcher->requests[0];
		$this->assertStringContainsString('grant_type=authorization_code', $request['body']);
		$this->assertStringContainsString('code=the-code', $request['body']);
		$this->assertStringContainsString('redirect_uri=', $request['body']);
		$this->assertSame('Basic ' . base64_encode('the-client-id:the-client-secret'), $request['headers']['Authorization']);
	}

	public function testRequestClientCredentialsTokenWithScopes(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));

		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config(), [ 'read', 'write' ]);

		$body = $fetcher->requests[0]['body'];
		$this->assertStringContainsString('grant_type=client_credentials', $body);
		$this->assertStringContainsString('scope=read+write', $body);
	}

	public function testRequestClientCredentialsTokenWithNoScopesOmitsScopeParam(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));

		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config());

		$this->assertStringNotContainsString('scope=', $fetcher->requests[0]['body']);
	}

	public function testThrowsOnNonSuccessStatusWithErrorField(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'error' => 'invalid_grant' ], JSON_THROW_ON_ERROR), 400));

		$this->expectException(TokenRequestException::class);
		$this->expectExceptionMessage('invalid_grant');

		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config());
	}

	public function testThrowsOnInvalidJson(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse('not json', 200));

		$this->expectException(TokenRequestException::class);

		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config());
	}

	public function testPublicClientOmitsAuthorizationHeader(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));

		$config = new OpenIDConnectClientConfig(
			clientId: 'the-client-id',
			clientSecret: '',
			redirectUrl: 'https://example.com/callback',
			endpointOverrides: [ ProviderMetadataResolver::TOKEN_ENDPOINT => self::TOKEN_ENDPOINT ],
		);

		$this->makeClient($fetcher)->exchangeAuthorizationCode($config, 'the-code');

		$this->assertArrayNotHasKey('Authorization', $fetcher->requests[0]['headers']);
		$this->assertStringContainsString('client_id=the-client-id', $fetcher->requests[0]['body']);
	}

}
