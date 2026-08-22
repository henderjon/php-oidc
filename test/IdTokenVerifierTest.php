<?php

namespace Henderjon\Oidc;

use Firebase\JWT\JWT;
use Henderjon\Oidc\Exceptions\AuthenticationFailedException;
use Henderjon\Oidc\Exceptions\HttpTransportException;
use Henderjon\Oidc\Exceptions\ProviderDiscoveryException;
use Henderjon\Oidc\Fakes\FakeHttpFetcher;
use Henderjon\Oidc\Fakes\FixedClock;
use Henderjon\Oidc\Fakes\RsaKeyFixture;
use PHPUnit\Framework\TestCase;

class IdTokenVerifierTest extends TestCase {

	private const JWKS_URI = 'https://issuer.example.com/jwks';
	private const CLIENT_SECRET       = 'test-client-secret-0123456789abcdef';
	private const WRONG_CLIENT_SECRET = 'wrong-client-secret-0123456789abcdef';

	private function fetcherWithJwks( RsaKeyFixture $fixture ): FakeHttpFetcher {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));

		return $fetcher;
	}

	public function testVerifyRs256TokenAgainstJwks(): void {
		$fixture  = new RsaKeyFixture;
		$idToken  = $fixture->sign([ 'iss' => 'https://issuer.example.com', 'sub' => 'user-1' ]);
		$verifier = new IdTokenVerifier($this->fetcherWithJwks($fixture));

		$claims = $verifier->verify($idToken, self::JWKS_URI, 'unused-client-secret');

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testVerifyRs256TokenWithNoKidFallsBackToTheSoleKey(): void {
		$fixture  = new RsaKeyFixture;
		$idToken  = $fixture->sign([ 'sub' => 'user-1' ], keyId: null);
		$verifier = new IdTokenVerifier($this->fetcherWithJwks($fixture));

		$claims = $verifier->verify($idToken, self::JWKS_URI, 'unused-client-secret');

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testVerifyHs256TokenAgainstClientSecret(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1' ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$claims = $verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET);

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testVerifyHs256TokenWithWrongSecretFails(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1' ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify($idToken, self::JWKS_URI, self::WRONG_CLIENT_SECRET);
	}

	public function testVerifyExpiredTokenFails(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1', 'exp' => 1000 ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher, new FixedClock(new \DateTimeImmutable('@2000')), leewaySeconds: 0);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET);
	}

	public function testInjectedClockControlsExpiryEvaluationInsteadOfWallClock(): void {
		// exp is 1000, real wall-clock time() is far past that - but the injected clock says "now" is 999,
		// which is still before exp. If the injected clock were not actually used, this would throw.
		$idToken  = JWT::encode([ 'sub' => 'user-1', 'exp' => 1000 ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher, new FixedClock(new \DateTimeImmutable('@999')), leewaySeconds: 0);

		$claims = $verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET);

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testVerifyMalformedTokenFails(): void {
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify('not-a-jwt', self::JWKS_URI, 'the-client-secret');
	}

	public function testVerifyTokenMissingAlgHeaderFails(): void {
		$header   = JWT::urlsafeB64Encode(json_encode([ 'typ' => 'JWT' ], JSON_THROW_ON_ERROR));
		$payload  = JWT::urlsafeB64Encode(json_encode([ 'sub' => 'user-1' ], JSON_THROW_ON_ERROR));
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify("{$header}.{$payload}.sig", self::JWKS_URI, 'the-client-secret');
	}

	public function testVerifyEncryptedTokenIsRejected(): void {
		$header   = JWT::urlsafeB64Encode(json_encode([ 'alg' => 'RSA-OAEP', 'enc' => 'A256GCM' ], JSON_THROW_ON_ERROR));
		$payload  = JWT::urlsafeB64Encode('encrypted-payload');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('not supported');

		$verifier->verify("{$header}.{$payload}.sig", self::JWKS_URI, 'the-client-secret');
	}

	public function testVerifyThrowsWhenNoJwksKeyMatchesAndMultipleKeysExist(): void {
		$fixture      = new RsaKeyFixture;
		$otherFixture = new RsaKeyFixture;

		// A JWKS with two keys, neither carrying the kid this token was signed with.
		$mergedJwks = [ 'keys' => [ ...$fixture->jwks()['keys'], ...$this->reKeyed($otherFixture) ] ];
		$fetcher    = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse(json_encode($mergedJwks, JSON_THROW_ON_ERROR), 200));

		$idTokenWithUnknownKid = $fixture->sign([ 'sub' => 'user-1' ], keyId: 'unknown-kid');

		$verifier = new IdTokenVerifier($fetcher);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify($idTokenWithUnknownKid, self::JWKS_URI, 'unused');
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function reKeyed( RsaKeyFixture $fixture ): array {
		$keys       = $fixture->jwks()['keys'];
		$keys[0]['kid'] = 'other-key';

		return $keys;
	}

	public function testVerifyWrapsJwksFetchFailure(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->failWith(self::JWKS_URI, new HttpTransportException('connection refused'));
		$verifier = new IdTokenVerifier($fetcher);

		$idToken = (new RsaKeyFixture)->sign([ 'sub' => 'user-1' ]);

		$this->expectException(ProviderDiscoveryException::class);

		$verifier->verify($idToken, self::JWKS_URI, 'unused');
	}

	public function testVerifyWithMatchingAccessTokenHashPasses(): void {
		$accessToken  = 'the-access-token';
		$digest       = hash('sha256', $accessToken, true);
		$expectedHash = JWT::urlsafeB64Encode(substr($digest, 0, 16));

		$idToken  = JWT::encode([ 'sub' => 'user-1', 'at_hash' => $expectedHash ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$claims = $verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET, accessToken: $accessToken);

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testVerifyWithMismatchedAccessTokenHashFails(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1', 'at_hash' => 'not-the-right-hash' ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET, accessToken: 'the-access-token');
	}

	public function testVerifyWithAtHashButNoAccessTokenSkipsTheCheck(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1', 'at_hash' => 'irrelevant' ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$claims = $verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET);

		$this->assertSame('user-1', $claims->get('sub'));
	}

}
