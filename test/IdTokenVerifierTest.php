<?php

namespace Oidc;

use Firebase\JWT\JWT;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\Fakes\ArrayLogger;
use Oidc\Fakes\FakeHttpFetcher;
use Oidc\Fakes\FixedClock;
use Oidc\Fakes\RsaKeyFixture;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

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
		$fetcher   = new FakeHttpFetcher;
		$transport = new HttpTransportException('connection refused');
		$fetcher->failWith(self::JWKS_URI, $transport);
		$logger   = new ArrayLogger;
		$verifier = new IdTokenVerifier($fetcher, logger: $logger);

		$idToken = (new RsaKeyFixture)->sign([ 'sub' => 'user-1' ]);

		try {
			$verifier->verify($idToken, self::JWKS_URI, 'unused', state: 'the-state');
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: unable to fetch JWKS', $records[0]['message']);
		$this->assertSame(self::JWKS_URI, $records[0]['context']['jwks_uri']);
		$this->assertSame($transport, $records[0]['context']['exception']);
		$this->assertSame('the-state', $records[0]['context']['state']);
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

	public function testVerifyEncryptedTokenLogsTheHeader(): void {
		$header   = JWT::urlsafeB64Encode(json_encode([ 'alg' => 'RSA-OAEP', 'enc' => 'A256GCM' ], JSON_THROW_ON_ERROR));
		$payload  = JWT::urlsafeB64Encode('encrypted-payload');
		$logger   = new ArrayLogger;
		$verifier = new IdTokenVerifier(new FakeHttpFetcher, logger: $logger);

		try {
			$verifier->verify("{$header}.{$payload}.sig", self::JWKS_URI, 'the-client-secret', state: 'the-state');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('A256GCM', $records[0]['context']['header']['enc']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyTokenMissingAlgHeaderLogsTheHeader(): void {
		$header   = JWT::urlsafeB64Encode(json_encode([ 'typ' => 'JWT' ], JSON_THROW_ON_ERROR));
		$payload  = JWT::urlsafeB64Encode(json_encode([ 'sub' => 'user-1' ], JSON_THROW_ON_ERROR));
		$logger   = new ArrayLogger;
		$verifier = new IdTokenVerifier(new FakeHttpFetcher, logger: $logger);

		try {
			$verifier->verify("{$header}.{$payload}.sig", self::JWKS_URI, 'the-client-secret', state: 'the-state');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame([ 'typ' => 'JWT' ], $records[0]['context']['header']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyThrowsWhenNoJwksKeyMatchesLogsTheAvailableKids(): void {
		$fixture      = new RsaKeyFixture;
		$otherFixture = new RsaKeyFixture;

		$mergedJwks = [ 'keys' => [ ...$fixture->jwks()['keys'], ...$this->reKeyed($otherFixture) ] ];
		$fetcher    = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse(json_encode($mergedJwks, JSON_THROW_ON_ERROR), 200));

		$idTokenWithUnknownKid = $fixture->sign([ 'sub' => 'user-1' ], keyId: 'unknown-kid');

		$logger   = new ArrayLogger;
		$verifier = new IdTokenVerifier($fetcher, logger: $logger);

		try {
			$verifier->verify($idTokenWithUnknownKid, self::JWKS_URI, 'unused', state: 'the-state');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('unknown-kid', $records[0]['context']['kid']);
		$this->assertSame([ RsaKeyFixture::KEY_ID, 'other-key' ], $records[0]['context']['available_kids']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyHs256TokenWithWrongSecretLogsTheExceptionButStaysGeneric(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1' ], self::CLIENT_SECRET, 'HS256');
		$logger   = new ArrayLogger;
		$verifier = new IdTokenVerifier(new FakeHttpFetcher, logger: $logger);

		try {
			$verifier->verify($idToken, self::JWKS_URI, self::WRONG_CLIENT_SECRET, state: 'the-state');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			// firebase/php-jwt's own message lives only in the log (and in ->getPrevious(),
			// for anything inspecting the chain directly) - not folded into the message text.
			$this->assertSame('ID token verification failed', $e->getMessage());
			$this->assertNotNull($e->getPrevious());
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertInstanceOf(\Exception::class, $records[0]['context']['exception']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyWithMismatchedAccessTokenHashLogsTheAlg(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1', 'at_hash' => 'not-the-right-hash' ], self::CLIENT_SECRET, 'HS256');
		$logger   = new ArrayLogger;
		$verifier = new IdTokenVerifier(new FakeHttpFetcher, logger: $logger);

		try {
			$verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET, accessToken: 'the-access-token', state: 'the-state');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('HS256', $records[0]['context']['alg']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testSuccessfulVerifyDoesNotLogAnything(): void {
		$fixture  = new RsaKeyFixture;
		$idToken  = $fixture->sign([ 'iss' => 'https://issuer.example.com', 'sub' => 'user-1' ]);
		$logger   = new ArrayLogger;
		$verifier = new IdTokenVerifier($this->fetcherWithJwks($fixture), logger: $logger);

		$verifier->verify($idToken, self::JWKS_URI, 'unused-client-secret');

		$this->assertSame([], $logger->records);
	}

}
