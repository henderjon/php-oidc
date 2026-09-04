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

	public function testRequestClientCredentialsTokenLogsWhenExtraParamsOverridesGrantType(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));
		$logger = new ArrayLogger;

		$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config(), extraParams: [ 'grant_type' => 'authorization_code' ]);

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$collision = $records[0];
		$this->assertSame('OIDC: extraParams collided with a reserved param and was overridden', $collision['message']);
		$this->assertSame([ 'grant_type' ], $collision['context']['overridden_keys']);
	}

	public function testRequestClientCredentialsTokenExtraParamsCannotOverrideScope(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));

		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config(), [ 'read' ], [ 'scope' => 'forged' ]);

		parse_str((string)$fetcher->requests[0]['body'], $body);
		$this->assertSame('read', $body['scope']);
	}

	public function testRequestClientCredentialsTokenLogsWhenExtraParamsOverridesScope(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));
		$logger = new ArrayLogger;

		$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config(), [ 'read' ], [ 'scope' => 'forged' ]);

		$this->assertSame(
			[ 'scope' ],
			$logger->recordsAt(LogLevel::DEBUG)[0]['context']['overridden_keys'],
		);
	}

	public function testRequestClientCredentialsTokenDoesNotLogAnythingWhenExtraParamsHasNoCollision(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));
		$logger = new ArrayLogger;

		$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config(), [ 'read' ], [ 'audience' => 'https://api.example.com' ]);

		$this->assertSame(
			[],
			array_values(array_filter(
				$logger->recordsAt(LogLevel::DEBUG),
				static fn ( array $record ): bool => $record['message'] === 'OIDC: extraParams collided with a reserved param and was overridden',
			)),
		);
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
		} catch( TokenRequestException $e ) {
			$this->assertSame('the-state', $e->getState());
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
		$logger = new ArrayLogger;

		try {
			$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config());
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException $e ) {
			$this->assertSame(200, $e->getHttpStatus());
			$this->assertSame('not json', $e->getRawBody());
			$this->assertInstanceOf(\JsonException::class, $e->getPrevious());
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertInstanceOf(\JsonException::class, $records[0]['context']['exception']);
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

	public function testExchangeAuthorizationCodeLogsTheRequestWithTheCodePartiallyRedacted(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));
		$logger = new ArrayLogger;

		$this->makeClient($fetcher, $logger)->exchangeAuthorizationCode($this->config(), 'the-authorization-code');

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$request = $records[0];

		$this->assertSame('OIDC: requesting a token', $request['message']);
		$this->assertSame(self::TOKEN_ENDPOINT, $request['context']['endpoint']);
		$this->assertSame('authorization_code', $request['context']['params']['grant_type']);
		$this->assertSame(Redact::partial('the-authorization-code'), $request['context']['params']['code']);
		$this->assertStringNotContainsString('the-authorization-code', json_encode($records));
	}

	public function testWhenScopedTheStateReachesBothItsOwnLogsAndClientAuthenticatorsThroughTheSameLogger(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));
		$logger = new ArrayLogger;

		$this->makeScopedClient($fetcher, $logger, 'the-flow-state')->exchangeAuthorizationCode($this->config(), 'the-code');

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$this->assertGreaterThanOrEqual(2, count($records));

		foreach( $records as $record ) {
			$this->assertSame('the-flow-state', $record['context']['state'], "every debug record for a scoped call must carry the same state - got: {$record['message']}");
		}
	}

	public function testRefreshTokenLogsTheRequestWithTheRefreshTokenPartiallyRedacted(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));
		$logger = new ArrayLogger;

		$this->makeClient($fetcher, $logger)->refreshToken($this->config(), 'the-original-refresh-token');

		$request = $logger->recordsAt(LogLevel::DEBUG)[0];

		$this->assertSame(Redact::partial('the-original-refresh-token'), $request['context']['params']['refresh_token']);
	}

	public function testRequestNeverLogsTheClientSecretEvenRedacted(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));
		$logger = new ArrayLogger;

		$config = $this->config()->withClientAuthMethod(ClientAuthMethod::Post);
		$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($config);

		// Not even Redact::partial('the-client-secret') should appear - client_secret is
		// excluded from every debug record this class and ClientAuthenticator produce, unlike
		// the short-lived values above. See ClientAuthenticator's docblock for why.
		$this->assertStringNotContainsString('the-client-secret', json_encode($logger->records));
	}

	public function testSuccessfulResponseLogsThePartiallyRedactedTokens(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token'  => 'the-returned-access-token',
			'id_token'       => 'the-returned-id-token-value',
			'refresh_token'  => 'the-returned-refresh-token',
			'expires_in'     => 3600,
		], JSON_THROW_ON_ERROR), 200));
		$logger = new ArrayLogger;

		$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config());

		$records  = $logger->recordsAt(LogLevel::DEBUG);
		$response = $records[array_key_last($records)];

		$this->assertSame('OIDC: token endpoint returned a token', $response['message']);
		$this->assertSame(Redact::partial('the-returned-access-token'), $response['context']['access_token']);
		$this->assertSame(Redact::partial('the-returned-id-token-value'), $response['context']['id_token']);
		$this->assertSame(Redact::partial('the-returned-refresh-token'), $response['context']['refresh_token']);
		$this->assertSame(3600, $response['context']['expires_in']);
		$this->assertStringNotContainsString('the-returned-access-token', json_encode($records));
		$this->assertStringNotContainsString('the-returned-id-token-value', json_encode($records));
		$this->assertStringNotContainsString('the-returned-refresh-token', json_encode($records));
	}

	public function testSuccessfulResponseLogsScopeAndTokenTypeInFullSinceNeitherIsSecret(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'x',
			'scope'        => 'read write',
			'token_type'   => 'Bearer',
		], JSON_THROW_ON_ERROR), 200));
		$logger = new ArrayLogger;

		$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config(), [ 'read', 'write' ]);

		$records  = $logger->recordsAt(LogLevel::DEBUG);
		$response = $records[array_key_last($records)];

		$this->assertSame('read write', $response['context']['scope']);
		$this->assertSame('Bearer', $response['context']['token_type']);
	}

	public function testSuccessfulResponseLogsNullForAnAbsentToken(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'x' ], JSON_THROW_ON_ERROR), 200));
		$logger = new ArrayLogger;

		$this->makeClient($fetcher, $logger)->requestClientCredentialsToken($this->config());

		$records  = $logger->recordsAt(LogLevel::DEBUG);
		$response = $records[array_key_last($records)];

		$this->assertNull($response['context']['id_token']);
		$this->assertNull($response['context']['refresh_token']);
		$this->assertNull($response['context']['scope']);
		$this->assertNull($response['context']['token_type']);
	}

}
