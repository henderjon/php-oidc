<?php

namespace Oidc\Stateless;

use Firebase\JWT\JWT;
use Oidc\AuthenticationResult;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\ConfigurationException;
use Oidc\Exceptions\TokenRequestException;
use Oidc\Fakes\ArrayLogger;
use Oidc\Fakes\FakeHttpFetcher;
use Oidc\Fakes\InMemoryCache;
use Oidc\Fakes\RsaKeyFixture;
use Oidc\FetchResponse;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClient;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;
use Oidc\PkceMode;
use Oidc\ProviderMetadataResolver;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

class StatelessCodeIdTokenClientTest extends TestCase {

	private const ISSUER         = 'https://issuer.example.com';
	private const CLIENT_ID      = 'the-client-id';
	private const CLIENT_SECRET  = 'the-client-secret';
	private const REDIRECT_URI   = 'https://example.com/callback';
	private const TOKEN_ENDPOINT = 'https://issuer.example.com/token';
	private const JWKS_URI       = 'https://issuer.example.com/jwks';
	private const MAX_AGE        = 300;

	private function config(): OpenIDConnectClientConfig {
		return new OpenIDConnectClientConfig(
			clientId: self::CLIENT_ID,
			clientSecret: self::CLIENT_SECRET,
			redirectUri: self::REDIRECT_URI,
			issuer: self::ISSUER,
			endpointOverrides: [
				ProviderMetadataResolver::AUTHORIZATION_ENDPOINT => 'https://issuer.example.com/authorize',
				ProviderMetadataResolver::TOKEN_ENDPOINT         => self::TOKEN_ENDPOINT,
				ProviderMetadataResolver::JWKS_URI               => self::JWKS_URI,
			],
		);
	}

	private function makeClient( FakeHttpFetcher $fetcher, ?ArrayLogger $logger = null ): StatelessCodeIdTokenClient {
		return (new OpenIDConnectClientFactory($fetcher, logger: $logger ?? new ArrayLogger))->makeStateless();
	}

	/**
	 * A fetcher that serves the fixture's JWKS and answers the token endpoint with $idToken.
	 */
	private function fetcherReturning( RsaKeyFixture $fixture, ?string $idToken, string $accessToken = 'the-access-token' ): FakeHttpFetcher {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		$body = [ 'access_token' => $accessToken, 'expires_in' => 3600, 'refresh_token' => 'the-refresh-token' ];

		if( $idToken !== null ) {
			$body['id_token'] = $idToken;
		}

		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse(json_encode($body, JSON_THROW_ON_ERROR), 200));

		return $fetcher;
	}

	/**
	 * @param array<string,mixed> $overrides
	 * @return array<string,mixed>
	 */
	private function claims( array $overrides = [] ): array {
		return [
			'iss' => self::ISSUER,
			'aud' => self::CLIENT_ID,
			'sub' => 'user-1',
			'iat' => time() - 10,
			'exp' => time() + 3600,
			...$overrides,
		];
	}

	private function codeOnly(): IncomingAuthorizationResponse {
		return new IncomingAuthorizationResponse([ 'code' => 'the-code' ]);
	}

	private function complete( FakeHttpFetcher $fetcher, ?IncomingAuthorizationResponse $response = null, ?OpenIDConnectClientConfig $config = null, int $maxAge = self::MAX_AGE, ?string $redirectUriOverride = null, ?ArrayLogger $logger = null ): AuthenticationResult {
		return $this->makeClient($fetcher, $logger)->completeStatelessCodeFlow($config ?? $this->config(), $response ?? $this->codeOnly(), $maxAge, $redirectUriOverride);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function lastTokenRequestParams( FakeHttpFetcher $fetcher ): array {
		$requests = array_values(array_filter($fetcher->requests, static fn ( array $r ): bool => $r['url'] === self::TOKEN_ENDPOINT));
		$this->assertNotEmpty($requests, 'expected a request to the token endpoint');
		parse_str((string)end($requests)['body'], $params);

		return $params;
	}

	private function assertRejected( callable $attempt, string $messageFragment ): void {
		try {
			$attempt();
			$this->fail('Expected an AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertStringContainsString($messageFragment, $e->getMessage());
		}
	}

	public function testHappyPathReturnsTheSameResultShapeAsTheNormalFlow(): void {
		$fixture = new RsaKeyFixture;
		$idToken = $fixture->sign($this->claims());
		$fetcher = $this->fetcherReturning($fixture, $idToken);

		$result = $this->complete($fetcher);

		$this->assertSame($idToken, $result->idToken);
		$this->assertSame('user-1', $result->claims->get('sub'));
		$this->assertSame('the-access-token', $result->accessToken);
		$this->assertSame('the-refresh-token', $result->refreshToken);
		$this->assertSame(3600, $result->expiresIn);
	}

	public function testTheTokenRequestCarriesTheCodeAndNoCodeVerifier(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims()));

		$this->complete($fetcher);

		$params = $this->lastTokenRequestParams($fetcher);
		$this->assertSame('authorization_code', $params['grant_type']);
		$this->assertSame('the-code', $params['code']);
		$this->assertArrayNotHasKey('code_verifier', $params);
	}

	public function testATokenWithNoNonceClaimPasses(): void {
		$fixture = new RsaKeyFixture;
		$claims  = $this->claims();

		$this->assertArrayNotHasKey('nonce', $claims);

		$result = $this->complete($this->fetcherReturning($fixture, $fixture->sign($claims)));

		$this->assertSame('user-1', $result->claims->get('sub'));
	}

	public function testATokenCarryingAnUnrelatedNonceStillPasses(): void {
		$fixture = new RsaKeyFixture;

		$result = $this->complete($this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'nonce' => 'whatever-the-provider-sent' ]))));

		$this->assertSame('user-1', $result->claims->get('sub'));
	}

	public function testRedirectUriOverrideIsSentToTheTokenEndpointWhenSet(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims()));

		$this->complete($fetcher, redirectUriOverride: 'https://example.com/other-callback');

		$this->assertSame('https://example.com/other-callback', $this->lastTokenRequestParams($fetcher)['redirect_uri']);
	}

	public function testConfiguredRedirectUriIsSentWhenThereIsNoOverride(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims()));

		$this->complete($fetcher);

		$this->assertSame(self::REDIRECT_URI, $this->lastTokenRequestParams($fetcher)['redirect_uri']);
	}

	public function testCompletionLogsAWarningSayingStateNonceAndPkceWereNotVerified(): void {
		$fixture = new RsaKeyFixture;
		$logger  = new ArrayLogger;

		$this->complete($this->fetcherReturning($fixture, $fixture->sign($this->claims())), logger: $logger);

		$warnings = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $warnings);
		$this->assertSame('OIDC: stateless code flow completed without verifying state, nonce, or PKCE', array_values($warnings)[0]['message']);
		$this->assertSame('user-1', array_values($warnings)[0]['context']['sub']);
	}

	public function testAFailureLogsNoCompletionWarning(): void {
		$fixture = new RsaKeyFixture;
		$logger  = new ArrayLogger;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'iss' => 'https://evil.example.com' ])));

		try {
			$this->complete($fetcher, logger: $logger);
			$this->fail('Expected an AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$this->assertSame([], $logger->recordsAt(LogLevel::WARNING));
	}

	public function testRejectsABadSignature(): void {
		$signer = new RsaKeyFixture;
		$other  = new RsaKeyFixture;

		// JWKS from one key, token signed by another, same key id.
		$fetcher = $this->fetcherReturning($other, $signer->sign($this->claims()));

		$this->expectException(AuthenticationFailedException::class);

		$this->complete($fetcher);
	}

	public function testRejectsTheWrongIssuer(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'iss' => 'https://evil.example.com' ])));

		$this->assertRejected(fn () => $this->complete($fetcher), 'issuer');
	}

	public function testRejectsTheWrongAudience(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'aud' => 'some-other-client' ])));

		$this->assertRejected(fn () => $this->complete($fetcher), 'audience');
	}

	public function testRejectsAnAudienceWithAnUntrustedExtraValue(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'aud' => [ self::CLIENT_ID, 'untrusted-party' ], 'azp' => self::CLIENT_ID ])));

		$this->assertRejected(fn () => $this->complete($fetcher), 'not trusted');
	}

	public function testAllowUntrustedAudiencesIsHonored(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'aud' => [ self::CLIENT_ID, 'untrusted-party' ], 'azp' => self::CLIENT_ID ])));

		$result = $this->complete($fetcher, config: $this->config()->withAllowUntrustedAudiences(true));

		$this->assertSame('user-1', $result->claims->get('sub'));
	}

	public function testRejectsTheWrongAuthorizedParty(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'azp' => 'some-other-client' ])));

		$this->assertRejected(fn () => $this->complete($fetcher), 'azp');
	}

	public function testRejectsAnExpiredToken(): void {
		$fixture = new RsaKeyFixture;
		// A generous age limit, so only exp can be what rejects it.
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'iat' => time() - 2000, 'exp' => time() - 1000 ])));

		$this->expectException(AuthenticationFailedException::class);

		$this->complete($fetcher, maxAge: 86_400);
	}

	public function testRejectsAStaleIat(): void {
		$fixture = new RsaKeyFixture;
		// 1000 seconds old against a 300 second maximum plus the 300 second default leeway.
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'iat' => time() - 1000 ])));

		$this->assertRejected(fn () => $this->complete($fetcher), 'issued longer ago than the configured maximum age');
	}

	public function testAnIatInsideTheWindowPasses(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'iat' => time() - 200 ])));

		$result = $this->complete($fetcher);

		$this->assertSame('user-1', $result->claims->get('sub'));
	}

	public function testRejectsAMissingIat(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'iat' => null ])));

		$this->assertRejected(fn () => $this->complete($fetcher), 'iat');
	}

	public function testRejectsAnUnsignedAlgNoneToken(): void {
		$fixture = new RsaKeyFixture;
		$header  = JWT::urlsafeB64Encode(json_encode([ 'alg' => 'none', 'typ' => 'JWT' ], JSON_THROW_ON_ERROR));
		$payload = JWT::urlsafeB64Encode(json_encode($this->claims(), JSON_THROW_ON_ERROR));
		$fetcher = $this->fetcherReturning($fixture, "{$header}.{$payload}.");

		$this->expectException(AuthenticationFailedException::class);

		$this->complete($fetcher);
	}

	public function testRejectsAMaxTokenLifetimeViolation(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims([ 'exp' => time() + 7200 ])));

		$this->assertRejected(fn () => $this->complete($fetcher, config: $this->config()->withMaxTokenLifetimeSeconds(600)), 'lifetime');
	}

	public function testHonorsMaxAgeSecondsAndRequiresAuthTime(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims()));

		$this->assertRejected(fn () => $this->complete($fetcher, config: $this->config()->withMaxAgeSeconds(600)), 'auth_time');
	}

	public function testATokenEndpointFailureThrowsATokenRequestException(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, null);
		$fetcher->respondTo(self::TOKEN_ENDPOINT, new FetchResponse('{"error":"invalid_grant"}', 400));

		$this->expectException(TokenRequestException::class);

		$this->complete($fetcher);
	}

	public function testATokenResponseWithNoIdTokenThrows(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, null);

		$this->assertRejected(fn () => $this->complete($fetcher), 'missing id_token');
	}

	public function testAResponseCarryingAStateThrowsBeforeAnyRequest(): void {
		$fetcher = new FakeHttpFetcher;

		$this->assertRejected(fn () => $this->complete($fetcher, new IncomingAuthorizationResponse([ 'code' => 'the-code', 'state' => 'a-state' ])), 'belongs to the stateful flow');
		$this->assertSame([], $fetcher->requests);
	}

	public function testAResponseCarryingAnErrorThrowsWithTheProviderErrorAttached(): void {
		$fetcher  = new FakeHttpFetcher;
		$response = new IncomingAuthorizationResponse([ 'error' => 'access_denied', 'error_description' => 'user said no' ]);

		try {
			$this->complete($fetcher, $response);
			$this->fail('Expected an AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertSame('Provider returned an error: access_denied: user said no', $e->getMessage());
			$this->assertSame('access_denied', $e->getProviderError()?->error);
		}

		$this->assertSame([], $fetcher->requests);
	}

	public function testAnErrorTakesPrecedenceOverAStateInTheResponse(): void {
		$response = new IncomingAuthorizationResponse([ 'error' => 'access_denied', 'state' => 'a-state' ]);

		$this->assertRejected(fn () => $this->complete(new FakeHttpFetcher, $response), 'Provider returned an error');
	}

	public function testAResponseWithNoCodeThrows(): void {
		$fetcher = new FakeHttpFetcher;

		$this->assertRejected(fn () => $this->complete($fetcher, new IncomingAuthorizationResponse([])), 'missing the authorization code');
		$this->assertSame([], $fetcher->requests);
	}

	public function testAnIdTokenDeliveredDirectlyThrows(): void {
		$fetcher = new FakeHttpFetcher;

		$this->assertRejected(fn () => $this->complete($fetcher, new IncomingAuthorizationResponse([ 'code' => 'the-code', 'id_token' => 'a.b.c' ])), 'carries a token directly');
		$this->assertSame([], $fetcher->requests);
	}

	public function testAnAccessTokenDeliveredDirectlyThrows(): void {
		$fetcher = new FakeHttpFetcher;

		$this->assertRejected(fn () => $this->complete($fetcher, new IncomingAuthorizationResponse([ 'code' => 'the-code', 'access_token' => 'a-token' ])), 'carries a token directly');
		$this->assertSame([], $fetcher->requests);
	}

	public function testNoIssuerConfiguredThrowsBeforeTheCodeIsRedeemed(): void {
		$fetcher = new FakeHttpFetcher;

		$this->assertRejected(fn () => $this->complete($fetcher, config: $this->config()->withIssuer(null)), 'No issuer configured');
		$this->assertSame([], $fetcher->requests);
	}

	public function testANonPositiveMaximumAgeThrowsAConfigurationExceptionBeforeAnyRequest(): void {
		$fetcher = new FakeHttpFetcher;

		try {
			$this->complete($fetcher, maxAge: 0);
			$this->fail('Expected a ConfigurationException to be thrown');
		} catch( ConfigurationException $e ) {
			$this->assertStringContainsString('must be positive', $e->getMessage());
		}

		$this->assertSame([], $fetcher->requests);
	}

	public function testTheExceptionCarriesNoStateAndTheRawIdToken(): void {
		$fixture = new RsaKeyFixture;
		$idToken = $fixture->sign($this->claims([ 'iss' => 'https://evil.example.com' ]));

		try {
			$this->complete($this->fetcherReturning($fixture, $idToken));
			$this->fail('Expected an AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertNull($e->getState());
			$this->assertSame($idToken, $e->getIdToken());
		}
	}

	/**
	 * Every ClaimsValidator call the main flow's verifyAndValidateIdToken() makes, other than the
	 * nonce check, must be made here too, so a check added to the main path cannot be silently
	 * missing from this one. Compares the source of the two methods, since ClaimsValidator is
	 * final and cannot be subclassed to record calls. Only a call written as
	 * `$claimsValidator->validateSomething(` is seen, which is how both methods write them.
	 */
	public function testEveryMainFlowValidatorCallExceptNonceIsAlsoMadeHere(): void {
		$main      = $this->validatorCallsIn(OpenIDConnectClient::class);
		$stateless = $this->validatorCallsIn(StatelessCodeIdTokenClient::class);

		$this->assertContains('validateNonce', $main, 'the main flow should still check the nonce');
		$this->assertNotContains('validateNonce', $stateless, 'the stateless flow has no nonce to check');
		$this->assertContains('validateIssuedAtAge', $stateless, 'the stateless flow needs its own replay defense');

		$this->assertSame(
			array_values(array_diff($main, [ 'validateNonce' ])),
			array_values(array_diff($stateless, [ 'validateIssuedAtAge' ])),
			'the stateless flow and the main flow validate different claims',
		);
	}

	public function testBothFlowsVerifyTheSignatureThroughTheSameVerifierCall(): void {
		foreach( [ OpenIDConnectClient::class, StatelessCodeIdTokenClient::class ] as $class ) {
			$this->assertStringContainsString('->verify(', $this->sourceOfValidationMethod($class), "{$class} must verify the ID token signature");
		}
	}

	/**
	 * @return list<string>
	 */
	private function validatorCallsIn( string $class ): array {
		preg_match_all('/\$claimsValidator->(validate\w+)\(/', $this->sourceOfValidationMethod($class), $matches);

		$calls = array_values(array_unique($matches[1]));
		sort($calls);

		return $calls;
	}

	private function sourceOfValidationMethod( string $class ): string {
		$method = new \ReflectionMethod($class, 'verifyAndValidateIdToken');
		$lines  = file((string)$method->getFileName());

		$this->assertIsArray($lines);

		return implode('', array_slice($lines, $method->getStartLine() - 1, $method->getEndLine() - $method->getStartLine() + 1));
	}

	private function mainClient( FakeHttpFetcher $fetcher ): OpenIDConnectClient {
		return (new OpenIDConnectClientFactory($fetcher, logger: new ArrayLogger))->make(new InMemoryCache);
	}

	public function testTheMainFlowStillRejectsAResponseWithNoState(): void {
		$fetcher = new FakeHttpFetcher;

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('Unable to verify state');

		$this->mainClient($fetcher)->completeAuthorizationCodeFlow($this->config(), $this->codeOnly());
	}

	public function testTheMainFlowStillRejectsATokenWithNoNonce(): void {
		$fixture = new RsaKeyFixture;
		$fetcher = $this->fetcherReturning($fixture, $fixture->sign($this->claims()));
		$client  = $this->mainClient($fetcher);

		$redirect = $client->buildAuthorizationCodeRedirect($this->config());
		parse_str((string)parse_url($redirect->url, PHP_URL_QUERY), $query);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('nonce');

		$client->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([ 'code' => 'the-code', 'state' => $query['state'] ]));
	}

	public function testTheMainFlowStillRejectsAMissingPkceVerifierWhenRequired(): void {
		$fetcher = new FakeHttpFetcher;
		$client  = $this->mainClient($fetcher);

		// Redirect built with PKCE off, so no verifier is stored, then completed with it required.
		$redirect = $client->buildAuthorizationCodeRedirect($this->config()->withPkce(PkceMode::Disabled));
		parse_str((string)parse_url($redirect->url, PHP_URL_QUERY), $query);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('Unable to verify PKCE code verifier');

		$client->completeAuthorizationCodeFlow($this->config()->withPkce(PkceMode::Required), new IncomingAuthorizationResponse([ 'code' => 'the-code', 'state' => $query['state'] ]));
	}

}
