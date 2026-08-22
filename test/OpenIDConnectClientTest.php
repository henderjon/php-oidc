<?php

namespace Henderjon\Oidc;

use Henderjon\Oidc\Exceptions\AuthenticationFailedException;
use Henderjon\Oidc\Exceptions\UserInfoRequestException;
use Henderjon\Oidc\Fakes\FakeHttpFetcher;
use Henderjon\Oidc\Fakes\InMemoryCache;
use Henderjon\Oidc\Fakes\RsaKeyFixture;
use PHPUnit\Framework\TestCase;
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

	private function makeClient( FakeHttpFetcher $fetcher, ?CacheInterface $cache = null ): OpenIDConnectClient {
		return new OpenIDConnectClient($cache ?? new InMemoryCache, 'the-cache-key', $fetcher);
	}

	/**
	 * @return array<array-key,mixed>
	 */
	private function queryParams( string $url ): array {
		parse_str((string)parse_url($url, PHP_URL_QUERY), $params);

		return $params;
	}

	public function testConstructorDefaultsCreateAWorkingClient(): void {
		$client = new OpenIDConnectClient(new InMemoryCache);

		$this->assertInstanceOf(Interfaces\AuthorizationFlowClientInterface::class, $client);
		$this->assertInstanceOf(Interfaces\TokenGrantClientInterface::class, $client);
		$this->assertInstanceOf(Interfaces\UserInfoClientInterface::class, $client);
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

	public function testCompleteAuthorizationCodeFlowFailsClosedWhenTheStateStoreLostTheNonce(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$cache  = new InMemoryCache;
		$client = $this->makeClient($fetcher, $cache);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		$params   = $this->queryParams($redirect->url);

		// Simulate the state store losing just the nonce entry (e.g. an eviction under a
		// non-session-scoped cache) while the state entry survives.
		$cache->delete('henderjon.oidc.nonce.the-cache-key');

		$idToken = $fixture->sign([
			'iss' => self::ISSUER,
			'aud' => self::CLIENT_ID,
			'sub' => 'user-1',
			// No nonce claim needed here - the check must fail before this claim is even read,
			// since $expectedNonce itself came back null.
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-access-token',
			'id_token'     => $idToken,
		], JSON_THROW_ON_ERROR), 200));

		$this->expectException(AuthenticationFailedException::class);

		$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([ 'code' => 'the-code', 'state' => $params['state'] ]));
	}

	public function testCompleteAuthorizationCodeFlowWithWrongStateFails(): void {
		$fetcher = new FakeHttpFetcher;
		$client  = $this->makeClient($fetcher);

		$client->buildAuthorizationCodeRedirect($this->config());

		$this->expectException(AuthenticationFailedException::class);

		$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([
			'code'  => 'the-code',
			'state' => 'a-forged-state',
		]));
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
