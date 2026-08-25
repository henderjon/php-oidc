<?php

namespace Oidc;

use Firebase\JWT\JWT;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\Fakes\ArrayLogger;
use Oidc\Fakes\EcKeyFixture;
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

		$claims = $verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET, allowedAlgorithms: [ 'HS256' ]);

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testVerifyHs256TokenWithWrongSecretFails(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1' ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify($idToken, self::JWKS_URI, self::WRONG_CLIENT_SECRET, allowedAlgorithms: [ 'HS256' ]);
	}

	public function testVerifyExpiredTokenFails(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1', 'exp' => 1000 ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher, new FixedClock(new \DateTimeImmutable('@2000')), leewaySeconds: 0);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET, allowedAlgorithms: [ 'HS256' ]);
	}

	public function testInjectedClockControlsExpiryEvaluationInsteadOfWallClock(): void {
		// exp is 1000, real wall-clock time() is far past that - but the injected clock says "now" is 999,
		// which is still before exp. If the injected clock were not actually used, this would throw.
		$idToken  = JWT::encode([ 'sub' => 'user-1', 'exp' => 1000 ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher, new FixedClock(new \DateTimeImmutable('@999')), leewaySeconds: 0);

		$claims = $verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET, allowedAlgorithms: [ 'HS256' ]);

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

	public function testVerifyRejectsAlgorithmNotInTheAllowlist(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1' ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('"HS256" is not allowed');

		// Default allowlist is RS256 only - HS256 must be rejected without it.
		$verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET);
	}

	public function testVerifyRejectsDisallowedAlgorithmBeforeEverFetchingJwks(): void {
		$fixture = new RsaKeyFixture;
		$idToken = $fixture->sign([ 'sub' => 'user-1' ]);

		// No response configured for JWKS_URI - FakeHttpFetcher throws a bare RuntimeException
		// for any URL it was not told to answer. Getting AuthenticationFailedException instead
		// proves the allowlist was checked before the JWKS fetch was ever attempted.
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify($idToken, self::JWKS_URI, 'unused', allowedAlgorithms: [ 'HS256' ]);
	}

	public function testVerifyRejectsNoneAlgorithmEvenWhenExplicitlyAllowlisted(): void {
		$header   = JWT::urlsafeB64Encode(json_encode([ 'alg' => 'none', 'typ' => 'JWT' ], JSON_THROW_ON_ERROR));
		$payload  = JWT::urlsafeB64Encode(json_encode([ 'sub' => 'user-1' ], JSON_THROW_ON_ERROR));
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('"none" is not allowed');

		$verifier->verify("{$header}.{$payload}.", self::JWKS_URI, 'unused', allowedAlgorithms: [ 'none', 'RS256' ]);
	}

	public function testVerifyRejectsHmacAlgorithmForAPublicClient(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1' ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('requires a client secret');

		// clientSecret is empty - a public client - even though HS256 is on the allowlist.
		$verifier->verify($idToken, self::JWKS_URI, '', allowedAlgorithms: [ 'HS256' ]);
	}

	public function testVerifyRejectsDisallowedAlgorithmLogsTheAllowlist(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1' ], self::CLIENT_SECRET, 'HS256');
		$logger   = new ArrayLogger;
		$verifier = (new IdTokenVerifier(new FakeHttpFetcher, logger: $logger))->withState('the-state');

		try {
			$verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET);
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('HS256', $records[0]['context']['alg']);
		$this->assertSame([ 'RS256' ], $records[0]['context']['allowed_algorithms']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyEs256TokenAgainstMatchingEcJwks(): void {
		$fixture = new EcKeyFixture;
		$idToken = $fixture->sign([ 'sub' => 'user-1' ]);
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200));
		$verifier = new IdTokenVerifier($fetcher);

		$claims = $verifier->verify($idToken, self::JWKS_URI, 'unused', allowedAlgorithms: [ 'ES256' ]);

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testVerifyRejectsJwksKeyTypeMismatchedWithTokenAlgorithm(): void {
		$ecFixture = new EcKeyFixture;

		// The JWKS entry is a real EC key with no "alg" of its own (RFC 7517 §4.4 makes it
		// optional) - it is only selected because its kid matches. The header claims RS256,
		// which this class would otherwise take at face value when labelling the resolved
		// Key. The signature is garbage - it must never be reached, since this should be
		// rejected before decodeAndVerifySignature() runs at all.
		$header  = JWT::urlsafeB64Encode(json_encode([ 'alg' => 'RS256', 'kid' => EcKeyFixture::KEY_ID, 'typ' => 'JWT' ], JSON_THROW_ON_ERROR));
		$payload = JWT::urlsafeB64Encode(json_encode([ 'sub' => 'user-1' ], JSON_THROW_ON_ERROR));
		$idToken = "{$header}.{$payload}." . JWT::urlsafeB64Encode('forged-signature');

		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($ecFixture->jwksJson(), 200));
		$verifier = new IdTokenVerifier($fetcher);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('key type does not match');

		$verifier->verify($idToken, self::JWKS_URI, 'unused');
	}

	public function testVerifyRejectsJwksKeyTypeMismatchLogsTheMismatch(): void {
		$ecFixture = new EcKeyFixture;
		$header    = JWT::urlsafeB64Encode(json_encode([ 'alg' => 'RS256', 'kid' => EcKeyFixture::KEY_ID, 'typ' => 'JWT' ], JSON_THROW_ON_ERROR));
		$payload   = JWT::urlsafeB64Encode(json_encode([ 'sub' => 'user-1' ], JSON_THROW_ON_ERROR));
		$idToken   = "{$header}.{$payload}." . JWT::urlsafeB64Encode('forged-signature');

		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($ecFixture->jwksJson(), 200));
		$logger   = new ArrayLogger;
		$verifier = (new IdTokenVerifier($fetcher, logger: $logger))->withState('the-state');

		try {
			$verifier->verify($idToken, self::JWKS_URI, 'unused');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('RS256', $records[0]['context']['alg']);
		$this->assertSame('RSA', $records[0]['context']['expected_kty']);
		$this->assertSame('EC', $records[0]['context']['actual_kty']);
		$this->assertSame('the-state', $records[0]['context']['state']);
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
		$verifier = (new IdTokenVerifier($fetcher, logger: $logger))->withState('the-state');

		$idToken = (new RsaKeyFixture)->sign([ 'sub' => 'user-1' ]);

		try {
			$verifier->verify($idToken, self::JWKS_URI, 'unused');
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

	public function testVerifyThrowsOnUnexpectedJwksContentType(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse('<html>not a jwks document</html>', 200, 'text/html'));
		$logger   = new ArrayLogger;
		$verifier = (new IdTokenVerifier($fetcher, logger: $logger))->withState('the-state');

		$idToken = (new RsaKeyFixture)->sign([ 'sub' => 'user-1' ]);

		try {
			$verifier->verify($idToken, self::JWKS_URI, 'unused');
			$this->fail('Expected ProviderDiscoveryException to be thrown');
		} catch( ProviderDiscoveryException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: JWKS endpoint returned an unexpected content type', $records[0]['message']);
		$this->assertSame('text/html', $records[0]['context']['content_type']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyAcceptsJwkSetJsonContentTypeForJwks(): void {
		$fixture = new RsaKeyFixture;
		$idToken = $fixture->sign([ 'sub' => 'user-1' ]);
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse($fixture->jwksJson(), 200, 'application/jwk-set+json'));
		$verifier = new IdTokenVerifier($fetcher);

		$claims = $verifier->verify($idToken, self::JWKS_URI, 'unused');

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testVerifyRejectsJwksExceedingTheMaximumKeyCount(): void {
		$keys = [];

		for( $i = 0; $i < 51; $i++ ) {
			$keys[] = [ 'kty' => 'RSA', 'kid' => "key-{$i}", 'n' => 'unused', 'e' => 'unused' ];
		}

		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse(json_encode([ 'keys' => $keys ], JSON_THROW_ON_ERROR), 200));
		$logger   = new ArrayLogger;
		$verifier = (new IdTokenVerifier($fetcher, logger: $logger))->withState('the-state');

		$idToken = (new RsaKeyFixture)->sign([ 'sub' => 'user-1' ]);

		try {
			$verifier->verify($idToken, self::JWKS_URI, 'unused');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: JWKS document exceeds the maximum number of keys', $records[0]['message']);
		$this->assertSame(51, $records[0]['context']['key_count']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	/**
	 * firebase/php-jwt's JWK::parseKeySet() throws its own exception (UnexpectedValueException,
	 * InvalidArgumentException, ...) for a "keys" value that is present but not an array,
	 * before this class's own key-type check ever runs. Confirmed this directly against
	 * JWK::parseKeySet() while investigating this fix - it is not merely theoretical.
	 */
	public function testVerifyWrapsAStringJwksKeysValue(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse(json_encode([ 'keys' => 'not-an-array' ], JSON_THROW_ON_ERROR), 200));
		$verifier = new IdTokenVerifier($fetcher);

		$idToken = (new RsaKeyFixture)->sign([ 'sub' => 'user-1' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('Unable to parse the JWKS document');

		$verifier->verify($idToken, self::JWKS_URI, 'unused');
	}

	public function testVerifyWrapsANullJwksKeysValue(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse(json_encode([ 'keys' => null ], JSON_THROW_ON_ERROR), 200));
		$verifier = new IdTokenVerifier($fetcher);

		$idToken = (new RsaKeyFixture)->sign([ 'sub' => 'user-1' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('Unable to parse the JWKS document');

		$verifier->verify($idToken, self::JWKS_URI, 'unused');
	}

	public function testVerifyMissingJwksKeysMemberIsWrapped(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse(json_encode([], JSON_THROW_ON_ERROR), 200));
		$verifier = new IdTokenVerifier($fetcher);

		$idToken = (new RsaKeyFixture)->sign([ 'sub' => 'user-1' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('Unable to parse the JWKS document');

		$verifier->verify($idToken, self::JWKS_URI, 'unused');
	}

	public function testVerifyEmptyJwksKeysArrayIsWrapped(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse(json_encode([ 'keys' => [] ], JSON_THROW_ON_ERROR), 200));
		$verifier = new IdTokenVerifier($fetcher);

		$idToken = (new RsaKeyFixture)->sign([ 'sub' => 'user-1' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('Unable to parse the JWKS document');

		$verifier->verify($idToken, self::JWKS_URI, 'unused');
	}

	public function testVerifyLogsAMalformedJwksKeysValueBeforeThrowing(): void {
		$fetcher = new FakeHttpFetcher;
		$fetcher->respondTo(self::JWKS_URI, new FetchResponse(json_encode([ 'keys' => 'not-an-array' ], JSON_THROW_ON_ERROR), 200));
		$logger   = new ArrayLogger;
		$verifier = (new IdTokenVerifier($fetcher, logger: $logger))->withState('the-state');

		$idToken = (new RsaKeyFixture)->sign([ 'sub' => 'user-1' ]);

		try {
			$verifier->verify($idToken, self::JWKS_URI, 'unused');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: unable to parse the JWKS document', $records[0]['message']);
		$this->assertSame(self::JWKS_URI, $records[0]['context']['jwks_uri']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyRejectsAnOversizedIdToken(): void {
		// No response configured for JWKS_URI - FakeHttpFetcher throws a bare RuntimeException
		// for any URL it was not told to answer. Getting AuthenticationFailedException instead
		// proves the length check runs before anything about the token is even looked at.
		$verifier      = new IdTokenVerifier(new FakeHttpFetcher);
		$oversizedToken = str_repeat('a', 16 * 1024 + 1);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify($oversizedToken, self::JWKS_URI, 'unused');
	}

	public function testVerifyRejectsAnOversizedIdTokenLogsTheLength(): void {
		$logger        = new ArrayLogger;
		$verifier      = (new IdTokenVerifier(new FakeHttpFetcher, logger: $logger))->withState('the-state');
		$oversizedToken = str_repeat('a', 16 * 1024 + 1);

		try {
			$verifier->verify($oversizedToken, self::JWKS_URI, 'unused');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: ID token exceeds the maximum allowed length', $records[0]['message']);
		$this->assertSame(16 * 1024 + 1, $records[0]['context']['length']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyWithMatchingAccessTokenHashPasses(): void {
		$accessToken  = 'the-access-token';
		$digest       = hash('sha256', $accessToken, true);
		$expectedHash = JWT::urlsafeB64Encode(substr($digest, 0, 16));

		$idToken  = JWT::encode([ 'sub' => 'user-1', 'at_hash' => $expectedHash ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$claims = $verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET, allowedAlgorithms: [ 'HS256' ], accessToken: $accessToken);

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testVerifyWithMismatchedAccessTokenHashFails(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1', 'at_hash' => 'not-the-right-hash' ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$this->expectException(AuthenticationFailedException::class);

		$verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET, allowedAlgorithms: [ 'HS256' ], accessToken: 'the-access-token');
	}

	public function testVerifyWithAtHashButNoAccessTokenSkipsTheCheck(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1', 'at_hash' => 'irrelevant' ], self::CLIENT_SECRET, 'HS256');
		$verifier = new IdTokenVerifier(new FakeHttpFetcher);

		$claims = $verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET, allowedAlgorithms: [ 'HS256' ]);

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testVerifyEncryptedTokenLogsTheHeader(): void {
		$header   = JWT::urlsafeB64Encode(json_encode([ 'alg' => 'RSA-OAEP', 'enc' => 'A256GCM' ], JSON_THROW_ON_ERROR));
		$payload  = JWT::urlsafeB64Encode('encrypted-payload');
		$logger   = new ArrayLogger;
		$verifier = (new IdTokenVerifier(new FakeHttpFetcher, logger: $logger))->withState('the-state');

		try {
			$verifier->verify("{$header}.{$payload}.sig", self::JWKS_URI, 'the-client-secret');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('A256GCM', $records[0]['context']['header']['enc']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyTokenMissingAlgHeaderLogsTheHeader(): void {
		$header   = JWT::urlsafeB64Encode(json_encode([ 'typ' => 'JWT' ], JSON_THROW_ON_ERROR));
		$payload  = JWT::urlsafeB64Encode(json_encode([ 'sub' => 'user-1' ], JSON_THROW_ON_ERROR));
		$logger   = new ArrayLogger;
		$verifier = (new IdTokenVerifier(new FakeHttpFetcher, logger: $logger))->withState('the-state');

		try {
			$verifier->verify("{$header}.{$payload}.sig", self::JWKS_URI, 'the-client-secret');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
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
		$verifier = (new IdTokenVerifier($fetcher, logger: $logger))->withState('the-state');

		try {
			$verifier->verify($idTokenWithUnknownKid, self::JWKS_URI, 'unused');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('unknown-kid', $records[0]['context']['kid']);
		$this->assertSame([ RsaKeyFixture::KEY_ID, 'other-key' ], $records[0]['context']['available_kids']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyHs256TokenWithWrongSecretLogsTheExceptionButStaysGeneric(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1' ], self::CLIENT_SECRET, 'HS256');
		$logger   = new ArrayLogger;
		$verifier = (new IdTokenVerifier(new FakeHttpFetcher, logger: $logger))->withState('the-state');

		try {
			$verifier->verify($idToken, self::JWKS_URI, self::WRONG_CLIENT_SECRET, allowedAlgorithms: [ 'HS256' ]);
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			// firebase/php-jwt's own message lives only in the log (and in ->getPrevious(),
			// for anything inspecting the chain directly) - not folded into the message text.
			$this->assertSame('ID token verification failed', $e->getMessage());
			$this->assertNotNull($e->getPrevious());
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertInstanceOf(\Exception::class, $records[0]['context']['exception']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testVerifyWithMismatchedAccessTokenHashLogsTheAlg(): void {
		$idToken  = JWT::encode([ 'sub' => 'user-1', 'at_hash' => 'not-the-right-hash' ], self::CLIENT_SECRET, 'HS256');
		$logger   = new ArrayLogger;
		$verifier = (new IdTokenVerifier(new FakeHttpFetcher, logger: $logger))->withState('the-state');

		try {
			$verifier->verify($idToken, self::JWKS_URI, self::CLIENT_SECRET, allowedAlgorithms: [ 'HS256' ], accessToken: 'the-access-token');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
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

	public function testWithStateDoesNotAffectTheOriginalInstance(): void {
		$header   = JWT::urlsafeB64Encode(json_encode([ 'typ' => 'JWT' ], JSON_THROW_ON_ERROR));
		$payload  = JWT::urlsafeB64Encode(json_encode([ 'sub' => 'user-1' ], JSON_THROW_ON_ERROR));
		$logger   = new ArrayLogger;
		$verifier = new IdTokenVerifier(new FakeHttpFetcher, logger: $logger);

		$verifier->withState('the-state');

		try {
			$verifier->verify("{$header}.{$payload}.sig", self::JWKS_URI, 'the-client-secret');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$this->assertNull($logger->recordsAt(LogLevel::ERROR)[0]['context']['state']);
	}

}
