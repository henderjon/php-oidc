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
		return new TokenEndpointClient($fetcher, new ProviderMetadataResolver($fetcher, new UrlPolicy), $logger ?? new ArrayLogger);
	}

	/**
	 * Mirrors how OpenIDConnectClient scopes a client: one ProviderMetadataResolver, scoped
	 * once, shared between the resolver's own use and the client built on top of it.
	 */
	private function makeScopedClient( FakeHttpFetcher $fetcher, ArrayLogger $logger, string $state ): TokenEndpointClient {
		$providerMetadataResolver = (new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger))->withState($state);

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

	public function testRefreshToken(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'the-new-access-token' ], JSON_THROW_ON_ERROR), 200));

		$result = $this->makeClient($fetcher)->refreshToken($this->config(), 'the-refresh-token');

		$this->assertSame('the-new-access-token', $result->accessToken);

		$request = $fetcher->requests[0];
		$this->assertStringContainsString('grant_type=refresh_token', $request['body']);
		$this->assertStringContainsString('refresh_token=the-refresh-token', $request['body']);
		$this->assertSame('Basic ' . base64_encode('the-client-id:the-client-secret'), $request['headers']['Authorization']);
	}

	/**
	 * A rejected refresh token (revoked, expired, or already rotated out from under the
	 * caller) is a routine, terminal outcome, not a claims problem - it must surface as
	 * TokenRequestException, not AuthenticationFailedException, so a caller can tell "this
	 * session is over, re-authenticate" apart from "a validated claim did not match".
	 * request() already covers this generically (see
	 * testThrowsOnNonSuccessStatusWithErrorField(), exercised via a different grant) - this
	 * proves it holds for refreshToken() specifically too, not just by construction.
	 */
	public function testRefreshTokenThrowsOnARejectedRefreshToken(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'error' => 'invalid_grant' ], JSON_THROW_ON_ERROR), 400));

		$this->expectException(TokenRequestException::class);
		$this->expectExceptionMessage('invalid_grant');

		$this->makeClient($fetcher)->refreshToken($this->config(), 'the-refresh-token');
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

	public function testRequestClientCredentialsTokenSendsExtraParams(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));

		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config(), extraParams: [ 'audience' => 'https://api.example.com' ]);

		parse_str((string)$fetcher->requests[0]['body'], $body);
		$this->assertSame('https://api.example.com', $body['audience']);
	}

	public function testRequestClientCredentialsTokenExtraParamsCannotOverrideGrantType(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));

		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config(), extraParams: [ 'grant_type' => 'authorization_code' ]);

		parse_str((string)$fetcher->requests[0]['body'], $body);
		$this->assertSame('client_credentials', $body['grant_type']);
	}

	public function testRequestClientCredentialsTokenExtraParamsCannotOverrideScope(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));

		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config(), [ 'read' ], [ 'scope' => 'forged' ]);

		parse_str((string)$fetcher->requests[0]['body'], $body);
		$this->assertSame('read', $body['scope']);
	}

	public function testRequestClientCredentialsTokenExtraParamsScopeIsReservedEvenWithNoScopesRequested(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));

		// No scopes requested at all - a sneaky "scope" in extraParams must not leak through
		// just because there is no real scope list to compare it against.
		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config(), [], [ 'scope' => 'forged' ]);

		$this->assertStringNotContainsString('scope=', $fetcher->requests[0]['body']);
	}

	public function testRequestClientCredentialsTokenSendsARepeatedExtraParamAsBareKeysNotBrackets(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));

		// RFC 8707 allows repeating `resource` to request a token for multiple resources -
		// as the bare key repeated (resource=a&resource=b), not http_build_query()'s default
		// bracket encoding (resource[0]=a&resource[1]=b), which most authorization servers
		// will not parse as a repeated parameter.
		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config(), [], [
			'resource' => [ 'https://api-a.example.com', 'https://api-b.example.com' ],
		]);

		$body = (string)$fetcher->requests[0]['body'];
		$this->assertStringNotContainsString('resource%5B', $body, 'must not bracket-encode a repeated parameter');
		$this->assertStringContainsString('resource=' . urlencode('https://api-a.example.com'), $body);
		$this->assertStringContainsString('resource=' . urlencode('https://api-b.example.com'), $body);
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
		// A wrong-but-JSON-labelled content type, so this exercises the unsuccessful-status
		// path specifically - not the separate unexpected-content-type rejection, which a
		// non-JSON content type like text/plain would hit first instead (see
		// testThrowsOnUnexpectedContentType below).
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse('invalid_client', 401, 'application/json'));

		try {
			$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config());
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertSame('OIDC: token endpoint returned an unsuccessful response', $records[0]['message']);
		$this->assertSame('application/json', $records[0]['context']['content_type']);
	}

	public function testThrowsOnUnexpectedContentType(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse('<html>not a token response</html>', 200, 'text/html'));

		try {
			$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config());
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertSame('OIDC: token endpoint returned an unexpected content type', $records[0]['message']);
		$this->assertSame('text/html', $records[0]['context']['content_type']);
	}

	public function testANonSuccessStatusTakesPrecedenceOverAnUnexpectedContentType(): void {
		// A proxy/gateway failure (a 502 from something in front of the real token endpoint)
		// commonly carries both an error status and an HTML content type at once - the status
		// is the more fundamental signal, so it must win rather than being masked by a
		// content-type rejection.
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse('<html>Bad Gateway</html>', 502, 'text/html'));

		try {
			$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config());
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException $e ) {
			$this->assertStringContainsString('502', $e->getMessage());
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: token endpoint returned an unsuccessful response', $records[0]['message']);
		$this->assertSame(502, $records[0]['context']['http_status']);
		$this->assertSame('text/html', $records[0]['context']['content_type']);
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

		$providerMetadataResolver = new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger);
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
