<?php

namespace Oidc;

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\UserInfoRequestException;
use Oidc\Fakes\ArrayLogger;
use Oidc\Fakes\FakeHttpFetcher;
use Oidc\Fakes\InMemoryCache;
use Oidc\Fakes\RsaKeyFixture;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use Psr\SimpleCache\CacheInterface;

class OpenIDConnectClientTest extends TestCase {

	private const ISSUER                 = 'https://issuer.example.com';
	private const CLIENT_ID              = 'the-client-id';
	private const CLIENT_SECRET          = 'the-client-secret';
	private const REDIRECT_URL           = 'https://example.com/callback';
	private const AUTHORIZATION_ENDPOINT = 'https://issuer.example.com/authorize';
	private const TOKEN_ENDPOINT         = 'https://issuer.example.com/token';
	private const JWKS_URI               = 'https://issuer.example.com/jwks';
	private const USERINFO_ENDPOINT      = 'https://issuer.example.com/userinfo';

	private function config(): OpenIDConnectClientConfig {
		return new OpenIDConnectClientConfig(
			clientId: self::CLIENT_ID,
			clientSecret: self::CLIENT_SECRET,
			redirectUrl: self::REDIRECT_URL,
			issuer: self::ISSUER,
			endpointOverrides: [
				ProviderMetadataResolver::AUTHORIZATION_ENDPOINT => self::AUTHORIZATION_ENDPOINT,
				ProviderMetadataResolver::TOKEN_ENDPOINT         => self::TOKEN_ENDPOINT,
				ProviderMetadataResolver::JWKS_URI               => self::JWKS_URI,
				ProviderMetadataResolver::USERINFO_ENDPOINT      => self::USERINFO_ENDPOINT,
			],
		);
	}

	private function makeClient( FakeHttpFetcher $fetcher, ?CacheInterface $cache = null, ?ArrayLogger $logger = null ): OpenIDConnectClient {
		return (new OpenIDConnectClientFactory($fetcher, logger: $logger ?? new ArrayLogger))->make($cache ?? new InMemoryCache, 'the-cache-key');
	}

	/**
	 * @return array<array-key,mixed>
	 */
	private function queryParams( string $url ): array {
		parse_str((string)parse_url($url, PHP_URL_QUERY), $params);

		return $params;
	}

	public function testBuildAuthorizationCodeRedirect(): void {
		$fetcher = new FakeHttpFetcher;
		$client  = $this->makeClient($fetcher);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config()->withScopes([ 'email' ]));
		$params   = $this->queryParams($redirect->url);

		$this->assertStringStartsWith(self::AUTHORIZATION_ENDPOINT, $redirect->url);
		$this->assertSame('code', $params['response_type']);
		$this->assertSame(self::CLIENT_ID, $params['client_id']);
		$this->assertSame(self::REDIRECT_URL, $params['redirect_uri']);
		$this->assertSame('openid email', $params['scope']);
		$this->assertNotEmpty($params['state']);
		$this->assertNotEmpty($params['nonce']);
	}

	public function testExtraAuthParamsCannotOverrideProtocolParams(): void {
		$fetcher  = new FakeHttpFetcher;
		$client   = $this->makeClient($fetcher);
		$config   = $this->config()->withExtraAuthParams([ 'client_id' => 'a-forged-client-id', 'prompt' => 'none' ]);
		$redirect = $client->buildAuthorizationCodeRedirect($config);
		$params   = $this->queryParams($redirect->url);

		$this->assertSame(self::CLIENT_ID, $params['client_id']);
		$this->assertSame('none', $params['prompt']);
	}

	public function testCompleteAuthorizationCodeFlowFullCycle(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => self::CLIENT_ID,
			'sub'   => 'user-1',
			'nonce' => $params['nonce'],
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
			'id_token'     => $idToken,
		], JSON_THROW_ON_ERROR), 200));

		$response = new IncomingAuthorizationResponse([ 'code' => 'the-code', 'state' => $params['state'] ]);
		$result   = $client->completeAuthorizationCodeFlow($this->config(), $response);

		$this->assertSame('user-1', $result->claims->get('sub'));
		$this->assertSame('the-access-token', $result->accessToken);
		$this->assertSame($idToken, $result->idToken);
	}

	public function testRequiredPkceCompletesAuthorizationCodeFlow(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);
		$config = $this->config()->withPkce(PkceMode::Required);

		$redirect = $client->buildAuthorizationCodeRedirect($config);
		$params   = $this->queryParams($redirect->url);

		$this->assertSame('S256', $params['code_challenge_method']);
		$this->assertSame(43, strlen($params['code_challenge']));

		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => self::CLIENT_ID,
			'sub'   => 'user-1',
			'nonce' => $params['nonce'],
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
			'id_token'     => $idToken,
		], JSON_THROW_ON_ERROR), 200));

		$result = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
			'code'  => 'the-code',
			'state' => $params['state'],
		]));

		parse_str((string)$fetcher->requests[0]['body'], $tokenParams);
		$this->assertSame($params['code_challenge'], Pkce::challengeFor($tokenParams['code_verifier']));
		$this->assertSame('user-1', $result->claims->get('sub'));
	}

	public function testDisabledPkceOmitsCodeChallengeFromRedirect(): void {
		$fetcher = new FakeHttpFetcher;
		$client  = $this->makeClient($fetcher);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		$this->assertArrayNotHasKey('code_challenge', $params);
		$this->assertArrayNotHasKey('code_challenge_method', $params);
	}

	public function testRequiredPkceFailsClosedWhenTheVerifierIsMissingAtCompletion(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$client  = $this->makeClient($fetcher, logger: $logger);

		// Built without PKCE, so no verifier was ever stored - simulates the verifier
		// having been evicted from the cache by the time the callback comes back.
		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		try {
			$client->completeAuthorizationCodeFlow($this->config()->withPkce(PkceMode::Required), new IncomingAuthorizationResponse([
				'code'  => 'the-code',
				'state' => $params['state'],
			]));
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertSame('Unable to verify PKCE code verifier', $e->getMessage());
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: PKCE code verifier missing for a Required flow', $records[0]['message']);
		$this->assertSame($params['state'], $records[0]['context']['state']);
	}

	public function testOptionalPkceProceedsWithoutAVerifierWhenNoneWasStored(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);

		// Same simulated eviction as the Required case above, but Optional must fail open.
		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => self::CLIENT_ID,
			'sub'   => 'user-1',
			'nonce' => $params['nonce'],
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
			'id_token'     => $idToken,
		], JSON_THROW_ON_ERROR), 200));

		$result = $client->completeAuthorizationCodeFlow($this->config()->withPkce(PkceMode::Optional), new IncomingAuthorizationResponse([
			'code'  => 'the-code',
			'state' => $params['state'],
		]));

		parse_str((string)$fetcher->requests[0]['body'], $tokenParams);
		$this->assertArrayNotHasKey('code_verifier', $tokenParams);
		$this->assertSame('user-1', $result->claims->get('sub'));
	}

	public function testCompleteAuthorizationCodeFlowWithWrongAudienceFailsEvenWithNoAudienceOverrideConfigured(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => 'someone-elses-client-id',
			'sub'   => 'user-1',
			'nonce' => $params['nonce'],
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
			'id_token'     => $idToken,
		], JSON_THROW_ON_ERROR), 200));

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('audience');

		$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([ 'code' => 'the-code', 'state' => $params['state'] ]));
	}

	public function testCompleteAuthorizationCodeFlowFailsClosedWhenTheStoredFlowIsCorrupted(): void {
		$fetcher = new FakeHttpFetcher;
		$cache   = new InMemoryCache;
		$client  = $this->makeClient($fetcher, $cache);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		// Simulate a malformed cache entry (e.g. written by an incompatible version, or a
		// key collision) rather than a clean miss - consume() must still fail closed instead
		// of trusting a value that is not the shape it wrote.
		$cache->set("henderjon.oidc.flow.the-cache-key.{$params['state']}", 'not-an-array', 600);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('Unable to verify state');

		$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([ 'code' => 'the-code', 'state' => $params['state'] ]));
	}

	public function testTwoConcurrentAuthorizationAttemptsOnTheSameSessionDoNotCollide(): void {
		$fetcher = new FakeHttpFetcher;
		$client  = $this->makeClient($fetcher);

		$firstParams  = $this->queryParams($client->buildAuthorizationCodeRedirect($this->config())->url);
		$secondParams = $this->queryParams($client->buildAuthorizationCodeRedirect($this->config())->url);

		$this->assertNotSame($firstParams['state'], $secondParams['state']);

		// No id_token in the response, so completion always fails past this point for both
		// calls - that failure (not "Unable to verify state") is what proves each call made
		// it through its own state/nonce lookup.
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
		], JSON_THROW_ON_ERROR), 200));

		// Complete the second tab first. If the two attempts shared one slot, this would
		// have already consumed (or overwritten) the first tab's entry.
		try {
			$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
				'code'  => 'the-code',
				'state' => $secondParams['state'],
			]));
		} catch( AuthenticationFailedException $e ) {
			$this->assertNotSame('Unable to verify state', $e->getMessage());
		}

		// The first tab's attempt must still be there and independently completable.
		try {
			$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
				'code'  => 'the-code',
				'state' => $firstParams['state'],
			]));
		} catch( AuthenticationFailedException $e ) {
			$this->assertNotSame('Unable to verify state', $e->getMessage());
		}
	}

	public function testCompleteAuthorizationCodeFlowWithWrongStateFails(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$client  = $this->makeClient($fetcher, logger: $logger);

		$client->buildAuthorizationCodeRedirect($this->config());

		try {
			$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
				'code'  => 'the-code',
				'state' => 'a-forged-state',
			]));
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			// The exception itself stays generic - the detail lives in the log instead.
			$this->assertSame('Unable to verify state', $e->getMessage());
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: no pending authorization flow found for the given state', $records[0]['message']);
		$this->assertSame('a-forged-state', $records[0]['context']['state']);
	}

	public function testCompleteAuthorizationCodeFlowWithNoStateAtAllLogsDistinctlyFromAWrongState(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$client  = $this->makeClient($fetcher, logger: $logger);

		$client->buildAuthorizationCodeRedirect($this->config());

		try {
			$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
				'code' => 'the-code',
			]));
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertSame('Unable to verify state', $e->getMessage());
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: callback is missing the state parameter', $records[0]['message']);
	}

	public function testCompleteAuthorizationCodeFlowWithProviderErrorFails(): void {
		$fetcher = new FakeHttpFetcher;
		$client  = $this->makeClient($fetcher);

		$client->buildAuthorizationCodeRedirect($this->config());

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('access_denied');

		$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
			'error' => 'access_denied',
		]));
	}

	public function testCompleteAuthorizationCodeFlowWithoutBuildingARedirectFirstFails(): void {
		$fetcher = new FakeHttpFetcher;
		$client  = $this->makeClient($fetcher);

		$this->expectException(AuthenticationFailedException::class);

		$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
			'code'  => 'the-code',
			'state' => 'anything',
		]));
	}

	public function testTokenResponseMissingIdTokenLogsAWarning(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$client  = $this->makeClient($fetcher, logger: $logger);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		// No id_token in this response at all - as opposed to one present but malformed,
		// which TokenResult itself already logs.
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
		], JSON_THROW_ON_ERROR), 200));

		try {
			$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
				'code'  => 'the-code',
				'state' => $params['state'],
			]));
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertSame('Token response is missing id_token', $e->getMessage());
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: token endpoint response is missing id_token', $records[0]['message']);
	}

	public function testImplicitFlowFullCycle(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);

		$redirect = $client->buildImplicitFlowRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		$this->assertSame('id_token', $params['response_type']);

		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => self::CLIENT_ID,
			'sub'   => 'user-1',
			'nonce' => $params['nonce'],
		]);

		$response = new IncomingAuthorizationResponse([ 'id_token' => $idToken, 'state' => $params['state'] ]);
		$result   = $client->completeImplicitFlow($this->config(), $response);

		$this->assertSame('user-1', $result->claims->get('sub'));
	}

	public function testImplicitFlowCallbackMissingIdTokenLogsAWarning(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$client  = $this->makeClient($fetcher, logger: $logger);

		$redirect = $client->buildImplicitFlowRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		try {
			$client->completeImplicitFlow($this->config(), new IncomingAuthorizationResponse([ 'state' => $params['state'] ]));
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertSame('Callback is missing the id_token', $e->getMessage());
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: callback is missing the id_token', $records[0]['message']);
	}

	public function testRequestClientCredentialsToken(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'the-access-token' ], JSON_THROW_ON_ERROR), 200));

		$result = $this->makeClient($fetcher)->requestClientCredentialsToken($this->config(), [ 'read' ]);

		$this->assertSame('the-access-token', $result->accessToken);
	}

	public function testFetchUserInfoJson(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse(json_encode([ 'sub' => 'user-1', 'email' => 'user@example.com' ], JSON_THROW_ON_ERROR), 200, 'application/json'));

		$claims = $this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token');

		$this->assertSame('user-1', $claims->get('sub'));
		$this->assertSame('user@example.com', $claims->get('email'));
		$this->assertSame('Bearer the-access-token', $fetcher->requests[0]['headers']['Authorization']);
	}

	public function testFetchUserInfoSignedResponse(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$idToken = $fixture->sign([ 'sub' => 'user-1' ]);
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse($idToken, 200, 'application/jwt'));

		$claims = $this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token');

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testFetchUserInfoThrowsOnNonSuccessStatus(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse('unauthorized', 401));

		$this->expectException(UserInfoRequestException::class);

		$this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token');
	}

}
