<?php

namespace Oidc;

use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\TokenRequestException;
use Oidc\Fakes\ArrayLogger;
use Oidc\Fakes\FakeHttpFetcher;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

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

	private function makeClient( FakeHttpFetcher $fetcher, ?ArrayLogger $logger = null ): TokenEndpointClient {
		return new TokenEndpointClient($fetcher, new ProviderMetadataResolver($fetcher), $logger ?? new ArrayLogger);
	}

	/**
	 * Mirrors how OpenIDConnectClient scopes a client: one ProviderMetadataResolver, scoped
	 * once, shared between the resolver's own use and the client built on top of it.
	 */
	private function makeScopedClient( FakeHttpFetcher $fetcher, ArrayLogger $logger, string $state ): TokenEndpointClient {
		$providerMetadataResolver = (new ProviderMetadataResolver($fetcher, $logger))->withState($state);

		return (new TokenEndpointClient($fetcher, $providerMetadataResolver, $logger))->withState($state, $providerMetadataResolver);
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
		$logger  = new ArrayLogger;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'error' => 'invalid_grant' ], JSON_THROW_ON_ERROR), 400));

		try {
			$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config());
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException $e ) {
			$this->assertStringContainsString('invalid_grant', $e->getMessage());
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame(self::TOKEN_ENDPOINT, $records[0]['context']['endpoint']);
		$this->assertSame(400, $records[0]['context']['http_status']);
		$this->assertSame('invalid_grant', $records[0]['context']['provider_error']);
		$this->assertNull($records[0]['context']['state'], 'client credentials is non-interactive - there is no flow to correlate with');
	}

	public function testExchangeAuthorizationCodeLogsTheGivenStateOnFailure(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'error' => 'invalid_grant' ], JSON_THROW_ON_ERROR), 400));

		try {
			$this->makeScopedClient($fetcher, $logger, 'the-state')->exchangeAuthorizationCode($this->config(), 'the-code');
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testLogsTransportFailureDetailsWithoutRequestParameters(): void {
		$fetcher   = new FakeHttpFetcher;
		$logger    = new ArrayLogger;
		$transport = new HttpTransportException('timed out');
		$fetcher->failWith(self::TOKEN_ENDPOINT, $transport);

		try {
			$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config());
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame(self::TOKEN_ENDPOINT, $records[0]['context']['endpoint']);
		$this->assertNull($records[0]['context']['http_status']);
		$this->assertSame($transport, $records[0]['context']['exception']);
		$this->assertArrayNotHasKey('params', $records[0]['context']);
		$this->assertNull($records[0]['context']['state']);
	}

	public function testLogsResponseContentTypeOnFailure(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse('invalid_client', 401, 'text/plain'));

		try {
			$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config());
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertSame('text/plain', $records[0]['context']['content_type']);
	}

	public function testThrowsOnNonSuccessStatusWithNonJsonBodyStillReportsTheStatusAndBody(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse('invalid_client', 400));

		try {
			$this->makeClient($fetcher)->requestClientCredentialsToken($this->config());
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException $e ) {
			$this->assertStringContainsString('400', $e->getMessage());
			$this->assertSame(400, $e->getHttpStatus());
			$this->assertSame('invalid_client', $e->getRawBody());
		}
	}

	public function testThrowsOnInvalidJson(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse('not json', 200));

		try {
			$this->makeClient($fetcher)->requestClientCredentialsToken($this->config());
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException $e ) {
			$this->assertSame(200, $e->getHttpStatus());
			$this->assertSame('not json', $e->getRawBody());
		}
	}

	public function testWithStateDoesNotAffectTheOriginalInstance(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'error' => 'invalid_grant' ], JSON_THROW_ON_ERROR), 400));
		$client = $this->makeClient($fetcher, $logger);

		$providerMetadataResolver = new ProviderMetadataResolver($fetcher, $logger);
		$client->withState('the-state', $providerMetadataResolver->withState('the-state'));

		try {
			$client->requestClientCredentialsToken($this->config());
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException ) {
		}

		$this->assertNull($logger->recordsAt(LogLevel::ERROR)[0]['context']['state']);
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
