<?php

namespace Oidc;

use Firebase\JWT\JWT;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\ProviderDiscoveryException;
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
			'expires_in'   => 3600,
		], JSON_THROW_ON_ERROR), 200));

		$response = new IncomingAuthorizationResponse([ 'code' => 'the-code', 'state' => $params['state'] ]);
		$result   = $client->completeAuthorizationCodeFlow($this->config(), $response);

		$this->assertSame('user-1', $result->claims->get('sub'));
		$this->assertSame('the-access-token', $result->accessToken);
		$this->assertSame($idToken, $result->idToken);
		$this->assertSame(3600, $result->expiresIn);
	}

	public function testCompleteAuthorizationCodeFlowRejectsAnIdTokenMissingSub(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		// RsaKeyFixture::sign() fills in a default sub unless overridden - explicitly clear it
		// to prove a token omitting the required claim entirely is rejected, not just a wrong one.
		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => self::CLIENT_ID,
			'sub'   => null,
			'nonce' => $params['nonce'],
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
			'id_token'     => $idToken,
		], JSON_THROW_ON_ERROR), 200));

		try {
			$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
				'code'  => 'the-code',
				'state' => $params['state'],
			]));
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			// A claims failure happens after the token is already in hand - getIdToken()
			// surfaces it so the whole claim set can be inspected at once, not just the one
			// claim (sub, here) that happened to be the first check to fail.
			$this->assertSame($idToken, $e->getIdToken());
		}
	}

	public function testCompleteAuthorizationCodeFlowRejectsAnIdTokenWithAnUntrustedExtraAudience(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		// aud lists this client alongside an audience nobody configured this client to trust -
		// OpenID Connect Core 1.0 §3.1.3.7 step 3 requires rejecting that, not just confirming
		// the client's own id is somewhere in the list.
		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => [ self::CLIENT_ID, 'an-untrusted-audience' ],
			'nonce' => $params['nonce'],
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
			'id_token'     => $idToken,
		], JSON_THROW_ON_ERROR), 200));

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('not trusted');

		$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
			'code'  => 'the-code',
			'state' => $params['state'],
		]));
	}

	public function testCompleteAuthorizationCodeFlowAcceptsAnUntrustedExtraAudienceWhenOptedOut(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);
		$config = $this->config()->withAllowUntrustedAudiences(true);

		$redirect = $client->buildAuthorizationCodeRedirect($config);
		$params   = $this->queryParams($redirect->url);

		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => [ self::CLIENT_ID, 'an-untrusted-audience' ],
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

		$this->assertSame([ self::CLIENT_ID, 'an-untrusted-audience' ], $result->claims->get('aud'));
	}

	public function testCompleteAuthorizationCodeFlowLogsAnAlertWhenAllowUntrustedAudiencesLetsSomethingThrough(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$logger = new ArrayLogger;
		$client = $this->makeClient($fetcher, logger: $logger);
		$config = $this->config()->withAllowUntrustedAudiences(true);

		$redirect = $client->buildAuthorizationCodeRedirect($config);
		$params   = $this->queryParams($redirect->url);

		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => [ self::CLIENT_ID, 'an-untrusted-audience' ],
			'nonce' => $params['nonce'],
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
			'id_token'     => $idToken,
		], JSON_THROW_ON_ERROR), 200));

		$client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
			'code'  => 'the-code',
			'state' => $params['state'],
		]));

		$records = $logger->recordsAt(LogLevel::ALERT);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: ID token audience contains untrusted values, allowed through by configuration', $records[0]['message']);
		$this->assertSame([ 'an-untrusted-audience' ], $records[0]['context']['untrusted']);
	}

	public function testCompleteAuthorizationCodeFlowRejectsAnIdTokenExceedingTheConfiguredMaxLifetime(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);
		$config = $this->config()->withMaxTokenLifetimeSeconds(300);

		$redirect = $client->buildAuthorizationCodeRedirect($config);
		$params   = $this->queryParams($redirect->url);

		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => self::CLIENT_ID,
			'nonce' => $params['nonce'],
			'iat'   => time(),
			'exp'   => time() + 3600,
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
			'id_token'     => $idToken,
		], JSON_THROW_ON_ERROR), 200));

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('lifetime');

		$client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
			'code'  => 'the-code',
			'state' => $params['state'],
		]));
	}

	public function testCompletionResolvesTokenEndpointAndJwksUriFromOneDiscoveryFetch(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::ISSUER . '/.well-known/openid-configuration', new FetchResponse(json_encode([
			'issuer'         => self::ISSUER,
			'token_endpoint' => self::TOKEN_ENDPOINT,
			'jwks_uri'       => self::JWKS_URI,
		], JSON_THROW_ON_ERROR), 200));
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		$config = new OpenIDConnectClientConfig(
			clientId: self::CLIENT_ID,
			clientSecret: self::CLIENT_SECRET,
			redirectUrl: self::REDIRECT_URL,
			providerUrl: self::ISSUER,
			issuer: self::ISSUER,
		);

		// Seed a pending flow directly, bypassing buildAuthorizationCodeRedirect() entirely -
		// that method would resolve authorization_endpoint too, muddying the fetch count this
		// test exists to check: that completion resolves token_endpoint (inside
		// TokenEndpointClient) and jwks_uri (back in OpenIDConnectClient) from a single scoped
		// ProviderMetadataResolver, not two independently-scoped copies each fetching discovery
		// themselves. See TokenEndpointClient::withState().
		$cache = new InMemoryCache;
		$flow  = (new AuthorizationStateStore($cache, 'the-cache-key'))->start();

		$client = $this->makeClient($fetcher, $cache);

		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => self::CLIENT_ID,
			'sub'   => 'user-1',
			'nonce' => $flow->nonce,
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
			'id_token'     => $idToken,
		], JSON_THROW_ON_ERROR), 200));

		$result = $client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
			'code'  => 'the-code',
			'state' => $flow->state,
		]));

		$this->assertSame('user-1', $result->claims->get('sub'));
		$discoveryRequests = array_filter($fetcher->requests, static fn ( array $r ): bool => str_ends_with($r['url'], '/.well-known/openid-configuration'));
		$this->assertCount(1, $discoveryRequests);
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
		$logger  = new ArrayLogger;
		$client  = $this->makeClient($fetcher, logger: $logger);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		$this->assertArrayNotHasKey('code_challenge', $params);
		$this->assertArrayNotHasKey('code_challenge_method', $params);
		// A confidential client (has a client secret) isn't the case PKCE exists to guard -
		// no nudge warning expected here, unlike the public-client case below.
		$this->assertSame([], $logger->records);
	}

	public function testPublicClientWithPkceDisabledLogsAWarning(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$client  = $this->makeClient($fetcher, logger: $logger);

		$client->buildAuthorizationCodeRedirect($this->config()->withClientSecret(''));

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: public client is building an authorization redirect with PKCE disabled', $records[0]['message']);
		$this->assertSame(self::CLIENT_ID, $records[0]['context']['client_id']);
	}

	public function testPublicClientWithPkceEnabledDoesNotLogTheDisabledWarning(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$client  = $this->makeClient($fetcher, logger: $logger);

		$client->buildAuthorizationCodeRedirect($this->config()->withClientSecret('')->withPkce(PkceMode::Required));

		$this->assertSame([], $logger->records);
	}

	public function testPublicClientBuildingAnImplicitFlowRedirectDoesNotLogThePkceWarning(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$client  = $this->makeClient($fetcher, logger: $logger);

		$redirect = $client->buildImplicitFlowRedirect($this->config()->withClientSecret(''));
		$params   = $this->queryParams($redirect->url);

		// PKCE only applies to the authorization code flow - no code to intercept in the
		// implicit flow, so no code_challenge and no nudge about it being disabled.
		$this->assertArrayNotHasKey('code_challenge', $params);
		$this->assertSame([], $logger->records);
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

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: PKCE code verifier missing for a Required flow', $records[0]['message']);
		$this->assertSame($params['state'], $records[0]['context']['state']);
	}

	public function testOptionalPkceProceedsWithoutAVerifierWhenNoneWasStored(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$logger = new ArrayLogger;
		$client = $this->makeClient($fetcher, logger: $logger);

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

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: PKCE code verifier missing for an Optional flow - proceeding without one', $records[0]['message']);
		$this->assertSame($params['state'], $records[0]['context']['state']);
	}

	public function testCompleteAuthorizationCodeFlowWithWrongAudienceFailsEvenWithNoAudienceOverrideConfigured(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$logger = new ArrayLogger;
		$client = $this->makeClient($fetcher, logger: $logger);

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

		try {
			$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([ 'code' => 'the-code', 'state' => $params['state'] ]));
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertStringContainsString('audience', $e->getMessage());
		}

		// Proves the correlation id set by buildAuthorizationCodeRedirect() survives the
		// whole trip through token exchange and out to ClaimsValidator's own log call -
		// not just that each collaborator accepts a $state parameter in isolation.
		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame($params['state'], $records[0]['context']['state']);
	}

	public function testJwksFetchFailureDuringCompletionLogsTheOriginatingState(): void {
		$fixture   = new RsaKeyFixture;
		$fetcher   = new FakeHttpFetcher;
		$transport = new HttpTransportException('connection refused');
		$fetcher->failWith(self::JWKS_URI, $transport);
		$logger = new ArrayLogger;
		$client = $this->makeClient($fetcher, logger: $logger);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		// A well-formed, real RS256 token - it must get past decodeHeader() so the failure
		// actually happens at the JWKS fetch, not earlier at header parsing.
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

		try {
			$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
				'code'  => 'the-code',
				'state' => $params['state'],
			]));
			$this->fail('Expected a ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		// Proves the correlation id reaches all the way down into IdTokenVerifier's own
		// collaborator (fetchJwks), not just the layers OpenIDConnectClient calls directly.
		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: unable to fetch JWKS', $records[0]['message']);
		$this->assertSame($params['state'], $records[0]['context']['state']);
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
			// The exception's message stays generic - the detail lives in the log - but
			// getState() still surfaces the raw callback state, since $flow is null here and
			// there is no FlowState to read it from instead.
			$this->assertSame('Unable to verify state', $e->getMessage());
			$this->assertSame('a-forged-state', $e->getState());
			$this->assertNull($e->getIdToken(), 'no token was ever fetched before this failure');
		}

		$records = $logger->recordsAt(LogLevel::ALERT);
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
			$this->assertNull($e->getState(), 'no state was ever in the callback to surface');
			$this->assertNull($e->getIdToken(), 'no token was ever fetched before this failure');
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
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

	public function testCompleteAuthorizationCodeFlowWithProviderErrorLogsTheErrorAndDescription(): void {
		$fetcher = new FakeHttpFetcher;
		$logger  = new ArrayLogger;
		$client  = $this->makeClient($fetcher, logger: $logger);

		try {
			$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
				'error'             => 'access_denied',
				'error_description' => 'The user denied access',
				'state'             => 'the-callback-state',
			]));
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$providerErrorRecords = array_values(array_filter(
			$records,
			static fn ( array $record ): bool => $record['message'] === 'OIDC: provider returned an error on the callback',
		));

		$this->assertCount(1, $providerErrorRecords);
		$this->assertSame('access_denied', $providerErrorRecords[0]['context']['error']);
		$this->assertSame('The user denied access', $providerErrorRecords[0]['context']['error_description']);
		$this->assertSame('the-callback-state', $providerErrorRecords[0]['context']['state']);
	}

	public function testCompletionNeverSendsCredentialsToATokenEndpointThatViolatesTheUrlPolicy(): void {
		$fetcher = new FakeHttpFetcher;
		$config  = $this->config()->withEndpointOverrides([
			ProviderMetadataResolver::TOKEN_ENDPOINT => 'http://attacker.example.net/token',
		]);
		$client = $this->makeClient($fetcher);

		$redirect = $client->buildAuthorizationCodeRedirect($config);
		$params   = $this->queryParams($redirect->url);

		try {
			$client->completeAuthorizationCodeFlow($config, new IncomingAuthorizationResponse([
				'code'  => 'the-code',
				'state' => $params['state'],
			]));
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		// resolve() rejects the endpoint before TokenEndpointClient ever builds a request, so
		// the client secret this config carries never went anywhere near that host.
		$this->assertSame([], $fetcher->requests);
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

	public function testTokenResponseMissingIdTokenLogsAnError(): void {
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
			$this->assertNull($e->getIdToken(), 'the missing id_token IS the failure - there is nothing to attach');
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: token endpoint response is missing id_token', $records[0]['message']);
		$this->assertSame($params['state'], $records[0]['context']['state']);
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

	public function testBuildImplicitFlowRedirectWithAccessTokenRequestsIdTokenToken(): void {
		$client = $this->makeClient(new FakeHttpFetcher);

		$redirect = $client->buildImplicitFlowRedirectWithAccessToken($this->config());
		$params   = $this->queryParams($redirect->url);

		$this->assertSame('id_token token', $params['response_type']);
	}

	/**
	 * OpenID Connect Core 1.0 §3.2.2.10 makes at_hash REQUIRED when an access token is issued
	 * from the authorization endpoint alongside the ID token - unlike the Authorization Code
	 * Flow, where §3.1.3.6 leaves it OPTIONAL even with an access token present too.
	 */
	public function testImplicitFlowWithAccessTokenRequiresAtHash(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);

		$redirect = $client->buildImplicitFlowRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		$idToken = $fixture->sign([
			'iss'   => self::ISSUER,
			'aud'   => self::CLIENT_ID,
			'sub'   => 'user-1',
			'nonce' => $params['nonce'],
		]);

		$response = new IncomingAuthorizationResponse([
			'id_token'     => $idToken,
			'access_token' => 'the-access-token',
			'state'        => $params['state'],
		]);

		try {
			$client->completeImplicitFlow($this->config(), $response);
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertStringContainsString('missing the required at_hash claim', $e->getMessage());
			$this->assertSame($idToken, $e->getIdToken());
		}
	}

	public function testImplicitFlowWithAccessTokenAndValidAtHashSucceeds(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$client = $this->makeClient($fetcher);

		$redirect = $client->buildImplicitFlowRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		$accessToken = 'the-access-token';
		$digest      = hash('sha256', $accessToken, true);
		$atHash      = JWT::urlsafeB64Encode(substr($digest, 0, 16));

		$idToken = $fixture->sign([
			'iss'     => self::ISSUER,
			'aud'     => self::CLIENT_ID,
			'sub'     => 'user-1',
			'nonce'   => $params['nonce'],
			'at_hash' => $atHash,
		]);

		$response = new IncomingAuthorizationResponse([
			'id_token'     => $idToken,
			'access_token' => $accessToken,
			'state'        => $params['state'],
		]);

		$result = $client->completeImplicitFlow($this->config(), $response);

		$this->assertSame('user-1', $result->claims->get('sub'));
	}

	public function testImplicitFlowCallbackMissingIdTokenLogsAnError(): void {
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
			$this->assertNull($e->getIdToken(), 'the missing id_token IS the failure - there is nothing to attach');
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: callback is missing the id_token', $records[0]['message']);
		$this->assertSame($params['state'], $records[0]['context']['state']);
	}

	public function testRefreshWithNoNewIdTokenReturnsTheOriginalIdTokenAndClaims(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-new-access-token',
			'expires_in'   => 3600,
		], JSON_THROW_ON_ERROR), 200));

		$originalClaims = new Claims([ 'iss' => self::ISSUER, 'sub' => 'user-1', 'aud' => self::CLIENT_ID ]);

		$result = $this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $originalClaims);

		$this->assertSame('the-original-id-token', $result->idToken);
		$this->assertSame($originalClaims, $result->claims);
		$this->assertSame('the-new-access-token', $result->accessToken);
		$this->assertSame(3600, $result->expiresIn);
	}

	public function testRefreshWithAMatchingNewIdTokenSucceeds(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		$newIdToken = $fixture->sign([ 'iss' => self::ISSUER, 'sub' => 'user-1', 'aud' => self::CLIENT_ID ]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-new-access-token',
			'id_token'     => $newIdToken,
		], JSON_THROW_ON_ERROR), 200));

		$originalClaims = new Claims([ 'iss' => self::ISSUER, 'sub' => 'user-1', 'aud' => self::CLIENT_ID ]);

		$result = $this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $originalClaims);

		$this->assertSame($newIdToken, $result->idToken);
		$this->assertSame('user-1', $result->claims->get('sub'));
	}

	public function testRequestClientCredentialsToken(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'the-access-token' ], JSON_THROW_ON_ERROR), 200));

		$result = $this->makeClient($fetcher)->requestClientCredentialsToken($this->config(), [ 'read' ]);

		$this->assertSame('the-access-token', $result->accessToken);
	}

	public function testRequestClientCredentialsTokenPassesExtraParamsThrough(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'the-access-token' ], JSON_THROW_ON_ERROR), 200));

		$this->makeClient($fetcher)->requestClientCredentialsToken($this->config(), extraParams: [ 'audience' => 'https://api.example.com' ]);

		parse_str((string)$fetcher->requests[0]['body'], $body);
		$this->assertSame('https://api.example.com', $body['audience']);
	}

	public function testFetchUserInfoJson(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse(json_encode([ 'sub' => 'user-1', 'email' => 'user@example.com' ], JSON_THROW_ON_ERROR), 200, 'application/json'));

		$claims = $this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-1');

		$this->assertSame('user-1', $claims->get('sub'));
		$this->assertSame('user@example.com', $claims->get('email'));
		$this->assertSame('Bearer the-access-token', $fetcher->requests[0]['headers']['Authorization']);
	}

	/**
	 * OpenID Connect Core 1.0 §5.3.2: iss/aud are only REQUIRED "if signed" - a plain JSON
	 * UserInfo response carrying neither must still pass once its sub matches.
	 */
	public function testFetchUserInfoJsonDoesNotRequireIssuerOrAudience(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse(json_encode([ 'sub' => 'user-1' ], JSON_THROW_ON_ERROR), 200, 'application/json'));

		$claims = $this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-1');

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testFetchUserInfoJsonRejectsASubjectMismatch(): void {
		$fetcher = new FakeHttpFetcher;
		$body    = json_encode([ 'sub' => 'user-1' ], JSON_THROW_ON_ERROR);
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse($body, 200, 'application/json'));

		try {
			$this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-2');
			$this->fail('Expected UserInfoRequestException to be thrown');
		} catch( UserInfoRequestException $e ) {
			// The subject check applies to both the signed and plain JSON response shapes -
			// getHttpStatus()/getRawBody() surface the response either way, not just on the
			// direct HTTP-level failures below.
			$this->assertSame(200, $e->getHttpStatus());
			$this->assertSame($body, $e->getRawBody());
		}
	}

	public function testFetchUserInfoJsonRejectsAMissingSubject(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse(json_encode([ 'email' => 'user@example.com' ], JSON_THROW_ON_ERROR), 200, 'application/json'));

		$this->expectException(UserInfoRequestException::class);

		$this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-1');
	}

	public function testFetchUserInfoSignedResponse(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$idToken = $fixture->sign([ 'sub' => 'user-1', 'iss' => self::ISSUER, 'aud' => self::CLIENT_ID ]);
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse($idToken, 200, 'application/jwt'));

		$claims = $this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-1');

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testFetchUserInfoSignedResponseRejectsAWrongIssuer(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$idToken = $fixture->sign([ 'sub' => 'user-1', 'iss' => 'https://other.example.com', 'aud' => self::CLIENT_ID ]);
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse($idToken, 200, 'application/jwt'));

		try {
			$this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-1');
			$this->fail('Expected UserInfoRequestException to be thrown');
		} catch( UserInfoRequestException $e ) {
			// getRawBody() is the signed JWT itself here, not a JSON body - decoding it shows
			// every claim it carried, not just the issuer this particular check rejected.
			$this->assertSame(200, $e->getHttpStatus());
			$this->assertSame($idToken, $e->getRawBody());
		}
	}

	public function testFetchUserInfoSignedResponseRejectsAWrongAudience(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$idToken = $fixture->sign([ 'sub' => 'user-1', 'iss' => self::ISSUER, 'aud' => 'someone-elses-client-id' ]);
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse($idToken, 200, 'application/jwt'));

		$this->expectException(UserInfoRequestException::class);

		$this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-1');
	}

	public function testFetchUserInfoSignedResponseRejectsAWrongSubject(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$idToken = $fixture->sign([ 'sub' => 'user-1', 'iss' => self::ISSUER, 'aud' => self::CLIENT_ID ]);
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse($idToken, 200, 'application/jwt'));

		$this->expectException(UserInfoRequestException::class);

		$this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-2');
	}

	public function testFetchUserInfoSignedResponseRejectsAMissingSubject(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$idToken = $fixture->sign([ 'sub' => null, 'iss' => self::ISSUER, 'aud' => self::CLIENT_ID ]);
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse($idToken, 200, 'application/jwt'));

		$this->expectException(UserInfoRequestException::class);

		$this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-1');
	}

	public function testFetchUserInfoThrowsOnNonSuccessStatus(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse('unauthorized', 401));

		try {
			$this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-1');
			$this->fail('Expected UserInfoRequestException to be thrown');
		} catch( UserInfoRequestException $e ) {
			$this->assertSame(401, $e->getHttpStatus());
			$this->assertSame('unauthorized', $e->getRawBody());
		}
	}

	public function testFetchUserInfoThrowsOnUnexpectedContentType(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse('<html>not userinfo</html>', 200, 'text/html'));

		try {
			$this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-1');
			$this->fail('Expected UserInfoRequestException to be thrown');
		} catch( UserInfoRequestException $e ) {
			$this->assertSame(200, $e->getHttpStatus());
			$this->assertSame('<html>not userinfo</html>', $e->getRawBody());
		}
	}

	public function testFetchUserInfoThrowsOnInvalidJson(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::USERINFO_ENDPOINT, new FetchResponse('not json', 200));

		try {
			$this->makeClient($fetcher)->fetchUserInfo($this->config(), 'the-access-token', 'user-1');
			$this->fail('Expected UserInfoRequestException to be thrown');
		} catch( UserInfoRequestException $e ) {
			$this->assertSame(200, $e->getHttpStatus());
			$this->assertSame('not json', $e->getRawBody());
			$this->assertInstanceOf(\JsonException::class, $e->getPrevious());
		}
	}

}
