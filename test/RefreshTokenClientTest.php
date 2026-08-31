<?php

namespace Oidc;

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\TokenRequestException;
use Oidc\Fakes\ArrayLogger;
use Oidc\Fakes\FakeHttpFetcher;
use Oidc\Fakes\RsaKeyFixture;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

class RefreshTokenClientTest extends TestCase {

	private const ISSUER         = 'https://issuer.example.com';
	private const CLIENT_ID      = 'the-client-id';
	private const TOKEN_ENDPOINT = 'https://issuer.example.com/token';
	private const JWKS_URI       = 'https://issuer.example.com/jwks';

	private function config(): OpenIDConnectClientConfig {
		return new OpenIDConnectClientConfig(
			clientId: self::CLIENT_ID,
			clientSecret: 'the-client-secret',
			redirectUrl: 'https://example.com/callback',
			issuer: self::ISSUER,
			endpointOverrides: [
				ProviderMetadataResolver::TOKEN_ENDPOINT => self::TOKEN_ENDPOINT,
				ProviderMetadataResolver::JWKS_URI       => self::JWKS_URI,
			],
		);
	}

	/**
	 * @param array<string,mixed> $overrides
	 */
	private function originalClaims( array $overrides = [] ): Claims {
		return new Claims([
			'iss' => self::ISSUER,
			'sub' => 'user-1',
			'aud' => self::CLIENT_ID,
			'iat' => 1_700_000_000,
			'exp' => 1_700_003_600,
			...$overrides,
		]);
	}

	private function makeClient( FakeHttpFetcher $fetcher, ?ArrayLogger $logger = null ): RefreshTokenClient {
		$logger                   = $logger ?? new ArrayLogger;
		$providerMetadataResolver = new ProviderMetadataResolver($fetcher, new UrlPolicy, $logger);

		return new RefreshTokenClient(
			$providerMetadataResolver,
			new IdTokenVerifier($fetcher, logger: $logger),
			new ClaimsValidator($logger),
			new TokenEndpointClient($fetcher, $providerMetadataResolver, $logger),
		);
	}

	public function testRefreshWithNoNewIdTokenReturnsTheOriginalIdTokenAndClaims(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token'  => 'the-new-access-token',
			'refresh_token' => 'the-new-refresh-token',
			'expires_in'    => 3600,
		], JSON_THROW_ON_ERROR), 200));

		$originalClaims = $this->originalClaims();

		$result = $this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $originalClaims);

		$this->assertSame('the-original-id-token', $result->idToken);
		$this->assertSame($originalClaims, $result->claims);
		$this->assertSame('the-new-access-token', $result->accessToken);
		$this->assertSame('the-new-refresh-token', $result->refreshToken);
		$this->assertSame(3600, $result->expiresIn);
	}

	public function testRefreshWithAMatchingNewIdTokenSucceeds(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		$newIdToken = $fixture->sign([
			'iss'       => self::ISSUER,
			'sub'       => 'user-1',
			'aud'       => self::CLIENT_ID,
			'auth_time' => 1_699_999_000,
			'nonce'     => 'the-nonce',
		]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-new-access-token',
			'id_token'     => $newIdToken,
		], JSON_THROW_ON_ERROR), 200));

		$originalClaims = $this->originalClaims([ 'auth_time' => 1_699_999_000, 'nonce' => 'the-nonce' ]);

		$result = $this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $originalClaims);

		$this->assertSame($newIdToken, $result->idToken);
		$this->assertSame('user-1', $result->claims->get('sub'));
		$this->assertSame('the-new-access-token', $result->accessToken);
	}

	public function testRefreshAllowsANewIdTokenWithNoNonceEvenWhenTheOriginalHadOne(): void {
		// OpenID Connect Core 1.0 §12.2: a refreshed ID token "SHOULD NOT have a nonce Claim,
		// even when the ID Token issued at the time of the original authentication contained
		// nonce" - dropping it entirely must not be rejected.
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		$newIdToken = $fixture->sign([ 'iss' => self::ISSUER, 'sub' => 'user-1', 'aud' => self::CLIENT_ID ]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-new-access-token',
			'id_token'     => $newIdToken,
		], JSON_THROW_ON_ERROR), 200));

		$originalClaims = $this->originalClaims([ 'nonce' => 'the-nonce' ]);

		$result = $this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $originalClaims);

		$this->assertSame('user-1', $result->claims->get('sub'));
	}

	public function testRefreshRejectsANewIdTokenWithAMismatchedIssuer(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		$newIdToken = $fixture->sign([ 'iss' => 'https://attacker.example.net', 'sub' => 'user-1', 'aud' => self::CLIENT_ID ]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-new-access-token',
			'id_token'     => $newIdToken,
		], JSON_THROW_ON_ERROR), 200));

		try {
			$this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $this->originalClaims());
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			// getIdToken() surfaces the NEW refreshed token this failure happened against,
			// not the original one passed into refresh().
			$this->assertSame($newIdToken, $e->getIdToken());
		}
	}

	public function testRefreshRejectsANewIdTokenWithAMismatchedSubject(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		$newIdToken = $fixture->sign([ 'iss' => self::ISSUER, 'sub' => 'someone-elses-subject', 'aud' => self::CLIENT_ID ]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-new-access-token',
			'id_token'     => $newIdToken,
		], JSON_THROW_ON_ERROR), 200));

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('does not match the original ID token');

		$this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $this->originalClaims());
	}

	public function testRefreshRejectsANewIdTokenWithAMismatchedAudience(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		$newIdToken = $fixture->sign([ 'iss' => self::ISSUER, 'sub' => 'user-1', 'aud' => 'someone-elses-client-id' ]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-new-access-token',
			'id_token'     => $newIdToken,
		], JSON_THROW_ON_ERROR), 200));

		$this->expectException(AuthenticationFailedException::class);

		$this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $this->originalClaims());
	}

	public function testRefreshRejectsANewIdTokenWithAMismatchedAuthTime(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		$newIdToken = $fixture->sign([ 'iss' => self::ISSUER, 'sub' => 'user-1', 'aud' => self::CLIENT_ID, 'auth_time' => 1_700_000_300 ]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-new-access-token',
			'id_token'     => $newIdToken,
		], JSON_THROW_ON_ERROR), 200));

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('does not match the original authentication time');

		$this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $this->originalClaims([ 'auth_time' => 1_699_999_000 ]));
	}

	public function testRefreshRejectsANewIdTokenWithANonceMismatch(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		$newIdToken = $fixture->sign([ 'iss' => self::ISSUER, 'sub' => 'user-1', 'aud' => self::CLIENT_ID, 'nonce' => 'a-different-nonce' ]);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([
			'access_token' => 'the-new-access-token',
			'id_token'     => $newIdToken,
		], JSON_THROW_ON_ERROR), 200));

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('does not match the original ID token');

		$this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $this->originalClaims([ 'nonce' => 'the-nonce' ]));
	}

	public function testRefreshSendsTheRefreshTokenToTheTokenEndpoint(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'access_token' => 'the-new-access-token' ], JSON_THROW_ON_ERROR), 200));

		$this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $this->originalClaims());

		$this->assertStringContainsString('grant_type=refresh_token', $fetcher->requests[0]['body']);
		$this->assertStringContainsString('refresh_token=the-refresh-token', $fetcher->requests[0]['body']);
	}

	/**
	 * A rejected refresh token is a routine, terminal outcome (revoked, expired, already
	 * rotated out from under the caller) - not a claims problem. It must surface as
	 * TokenRequestException here, distinct from every AuthenticationFailedException test
	 * above, so a caller can tell "this session is over, re-authenticate" apart from
	 * "a validated claim did not match". This never reaches claims validation at all - the
	 * token endpoint rejects the request before any new ID token exists to inspect.
	 */
	public function testRefreshThrowsTokenRequestExceptionOnARejectedRefreshToken(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode([ 'error' => 'invalid_grant' ], JSON_THROW_ON_ERROR), 400));

		$this->expectException(TokenRequestException::class);

		$this->makeClient($fetcher)->refresh($this->config(), 'the-refresh-token', 'the-original-id-token', $this->originalClaims());
	}

}
