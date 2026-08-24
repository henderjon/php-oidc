<?php

namespace Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Verifies an ID token's signature (asymmetric via JWKS, or HMAC via the
 * client secret) using `firebase/php-jwt`, and - since the token itself is
 * authentic once the signature checks out - its `at_hash` binding to an
 * access token, if both are present.
 *
 * The token's own `alg` header never gets to pick its own verification
 * strategy: `$allowedAlgorithms` (see OpenIDConnectClientConfig::$allowedAlgorithms)
 * is checked, `none` is unconditionally rejected, and HS* is rejected outright for a
 * public client (empty client secret) - all before any key material, cached or fetched,
 * is touched. This is deliberate, not redundant with firebase/php-jwt's own internal
 * `Key`-vs-header algorithm check: this class builds the `Key` object FROM the header's
 * own `alg` (there is no other source for it - every JWT verifier has to know what the
 * token claims before it can verify it), so that internal check alone would be
 * tautological here without a policy decided independently of the token first.
 *
 * `JWT::decode()` already enforces `exp`/`nbf`/`iat`; the injected clock
 * only exists to make that deterministic in tests instead of racing
 * against `time()`. Encrypted (JWE) tokens are explicitly unsupported -
 * detected and rejected before any key material is touched.
 *
 * Issuer/audience/nonce are not this class's concern - see ClaimsValidator.
 *
 * Every failure here is a stronger signal than a mismatched `state` or
 * `nonce` - it means the token itself is malformed, unsigned by a key we
 * trust, or otherwise not what it claims to be. Each one is logged (the
 * JOSE header, which carries no secret material, or the specific mismatch)
 * before the generic AuthenticationFailedException is thrown, so that
 * signal survives even if the caller never logs the exception itself.
 */
final class IdTokenVerifier {

	public function __construct(
		private readonly HttpFetcherInterface $httpFetcher,
		private readonly ClockInterface $clock = new CurrentClock,
		private readonly int $leewaySeconds = 300,
		private readonly LoggerInterface $logger = new NullLogger,
		private readonly ?string $state = null,
	) {
	}

	/**
	 * Returns a copy of this verifier carrying one flow's correlation id - see
	 * ClaimsValidator::withState() for why this returns a new instance instead of
	 * mutating the shared one.
	 */
	public function withState( ?string $state ): self {
		return new self($this->httpFetcher, $this->clock, $this->leewaySeconds, $this->logger, $state);
	}

	/**
	 * @throws AuthenticationFailedException
	 * @throws ProviderDiscoveryException
	 */
	/**
	 * @param list<string> $allowedAlgorithms See OpenIDConnectClientConfig::$allowedAlgorithms.
	 */
	public function verify(
		string $idToken,
		string $jwksUri,
		string $clientSecret,
		array $allowedAlgorithms = [ 'RS256' ],
		?string $accessToken = null,
	): Claims {
		$header = $this->decodeHeader($idToken);

		if( isset($header['enc']) ) {
			$this->logger->warning('OIDC: ID token is encrypted (JWE), which is not supported', [ 'header' => $header, 'state' => $this->state ]);

			throw new AuthenticationFailedException('Encrypted ID tokens (JWE) are not supported');
		}

		$alg = $header['alg'] ?? null;

		if( !is_string($alg) || $alg === '' ) {
			$this->logger->warning('OIDC: ID token is missing its alg header', [ 'header' => $header, 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token is missing its alg header');
		}

		$this->assertAlgorithmAllowed($alg, $allowedAlgorithms, $clientSecret);

		$key = str_starts_with($alg, 'HS')
			? new Key($clientSecret, $alg)
			: $this->resolveAsymmetricKey($jwksUri, $alg, is_string($header['kid'] ?? null) ? $header['kid'] : null);

		$claims = $this->decodeAndVerifySignature($idToken, $key);

		$this->verifyAccessTokenHash($claims, $alg, $accessToken);

		return $claims;
	}

	/**
	 * `none` is rejected unconditionally, even if a caller's own $allowedAlgorithms
	 * mistakenly includes it - firebase/php-jwt already refuses to decode it too, but this
	 * class does not rely solely on that. HS* is rejected outright for a public client
	 * (empty $clientSecret), also regardless of $allowedAlgorithms: a confidential client's
	 * secret is presumed genuinely unknown to an attacker, but nothing stands behind an
	 * empty one, so there is no configuration where HMAC-with-no-secret is sound.
	 *
	 * @param list<string> $allowedAlgorithms
	 * @throws AuthenticationFailedException
	 */
	private function assertAlgorithmAllowed( string $alg, array $allowedAlgorithms, string $clientSecret ): void {
		if( $alg === 'none' ) {
			$this->logger->warning('OIDC: ID token declares the "none" algorithm', [ 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token algorithm "none" is not allowed');
		}

		if( !in_array($alg, $allowedAlgorithms, true) ) {
			$this->logger->warning('OIDC: ID token algorithm is not in the configured allowlist', [
				'alg'                => $alg,
				'allowed_algorithms' => $allowedAlgorithms,
				'state'              => $this->state,
			]);

			throw new AuthenticationFailedException("ID token algorithm \"{$alg}\" is not allowed");
		}

		if( str_starts_with($alg, 'HS') && $clientSecret === '' ) {
			$this->logger->warning('OIDC: ID token uses an HMAC algorithm but no client secret is configured', [ 'alg' => $alg, 'state' => $this->state ]);

			throw new AuthenticationFailedException("ID token algorithm \"{$alg}\" requires a client secret");
		}
	}

	/**
	 * @throws AuthenticationFailedException
	 */
	private function decodeAndVerifySignature( string $idToken, Key $key ): Claims {
		$originalTimestamp = JWT::$timestamp;
		$originalLeeway    = JWT::$leeway;

		JWT::$timestamp = $this->clock->now()->getTimestamp();
		JWT::$leeway    = $this->leewaySeconds;

		try {
			$payload = JWT::decode($idToken, $key);
		} catch( \Exception $e ) {
			// The exception stays generic - firebase/php-jwt's own message (and whatever it
			// happens to reveal about why decoding failed) lives only in the log, matching
			// every other failure in this class and in ClaimsValidator. `previous` still
			// carries the original exception for anything inspecting the chain directly.
			$this->logger->warning('OIDC: ID token signature verification failed', [ 'exception' => $e, 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token verification failed', previous: $e);
		} finally {
			JWT::$timestamp = $originalTimestamp;
			JWT::$leeway    = $originalLeeway;
		}

		return new Claims($payload);
	}

	/**
	 * @throws AuthenticationFailedException
	 */
	private function verifyAccessTokenHash( Claims $claims, string $alg, ?string $accessToken ): void {
		$atHash = $claims->get('at_hash');

		if( $atHash === null || $accessToken === null ) {
			return;
		}

		$bitLength = match( true ) {
			str_ends_with($alg, '384') => 384,
			str_ends_with($alg, '512') => 512,
			default                    => 256,
		};

		$digest   = hash('sha' . $bitLength, $accessToken, true);
		$expected = JWT::urlsafeB64Encode(substr($digest, 0, intdiv($bitLength, 16)));

		if( !hash_equals($expected, (string)$atHash) ) {
			$this->logger->warning('OIDC: ID token at_hash does not match the access token', [ 'alg' => $alg, 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token at_hash does not match the access token');
		}
	}

	/**
	 * @throws AuthenticationFailedException
	 * @throws ProviderDiscoveryException
	 */
	private function resolveAsymmetricKey( string $jwksUri, string $alg, ?string $kid ): Key {
		$jwks   = $this->fetchJwks($jwksUri);
		$keySet = JWK::parseKeySet($jwks, $alg);

		$selectedKid = match( true ) {
			$kid !== null && isset($keySet[$kid]) => $kid,
			count($keySet) === 1                  => array_key_first($keySet),
			default                                => null,
		};

		if( $selectedKid === null ) {
			$this->logger->warning('OIDC: unable to find a matching JWKS key for this ID token', [
				'kid'            => $kid,
				'available_kids' => array_keys($keySet),
				'state'          => $this->state,
			]);

			throw new AuthenticationFailedException('Unable to find a matching JWKS key for this ID token');
		}

		$this->assertKeyTypeMatchesAlgorithm($jwks, $selectedKid, $alg);

		return $keySet[$selectedKid];
	}

	/**
	 * A JWKS entry's own "alg" is optional (RFC 7517 §4.4) - when it is absent,
	 * JWK::parseKeySet() labels the resulting Key with whatever algorithm this class asked
	 * for, which is the token's own (already allowlist-checked) `alg`. That means
	 * firebase/php-jwt's internal "does the Key's algorithm match the token header"
	 * check - the one this class's own class docblock explains is otherwise tautological
	 * here - would trivially pass even if the JWKS entry it resolved to is structurally the
	 * wrong kind of key for that algorithm (an EC key selected for an RS256 token, say).
	 * This checks the selected entry's own declared "kty" against the algorithm family
	 * independently of that internal check, using the raw JWKS document rather than the
	 * already-parsed Key objects, since a Key exposes only its (possibly tautological)
	 * algorithm label, not the JWK's original "kty".
	 *
	 * @param array<string,mixed> $jwks
	 * @throws AuthenticationFailedException
	 */
	private function assertKeyTypeMatchesAlgorithm( array $jwks, string $selectedKid, string $alg ): void {
		$expectedKty = match( true ) {
			str_starts_with($alg, 'RS'), str_starts_with($alg, 'PS') => 'RSA',
			str_starts_with($alg, 'ES')                              => 'EC',
			$alg === 'EdDSA'                                         => 'OKP',
			// Anything else is outside firebase/php-jwt's own supported algorithm list and
			// will already be rejected by JWT::decode() itself - nothing to check here.
			default                                                  => null,
		};

		if( $expectedKty === null ) {
			return;
		}

		foreach( $jwks['keys'] as $index => $entry ) {
			if( ( $entry['kid'] ?? (string)$index ) !== $selectedKid ) {
				continue;
			}

			$actualKty = $entry['kty'] ?? null;

			if( $actualKty !== $expectedKty ) {
				$this->logger->warning('OIDC: JWKS key type does not match the ID token algorithm', [
					'alg'          => $alg,
					'expected_kty' => $expectedKty,
					'actual_kty'   => $actualKty,
					'kid'          => $selectedKid,
					'state'        => $this->state,
				]);

				throw new AuthenticationFailedException('JWKS key type does not match the ID token algorithm');
			}

			return;
		}
	}

	/**
	 * @throws ProviderDiscoveryException
	 * @return array<string,mixed>
	 */
	private function fetchJwks( string $jwksUri ): array {
		try {
			$response = $this->httpFetcher->fetch($jwksUri, null);
		} catch( HttpTransportException $e ) {
			$this->logger->error('OIDC: unable to fetch JWKS', [ 'jwks_uri' => $jwksUri, 'exception' => $e, 'state' => $this->state ]);

			throw new ProviderDiscoveryException("Unable to fetch JWKS from {$jwksUri}", previous: $e);
		}

		if( $response->status !== 200 ) {
			$this->logger->error('OIDC: JWKS endpoint returned an unsuccessful response', [
				'jwks_uri'    => $jwksUri,
				'http_status' => $response->status,
				'state'       => $this->state,
			]);

			throw new ProviderDiscoveryException("JWKS endpoint {$jwksUri} returned HTTP {$response->status}");
		}

		$decoded = json_decode($response->body, true);

		if( !is_array($decoded) ) {
			$this->logger->error('OIDC: JWKS endpoint returned invalid JSON', [
				'jwks_uri'    => $jwksUri,
				'http_status' => $response->status,
				'state'       => $this->state,
			]);

			throw new ProviderDiscoveryException("JWKS endpoint {$jwksUri} returned invalid JSON");
		}

		return $decoded;
	}

	/**
	 * @throws AuthenticationFailedException
	 * @return array<string,mixed>
	 */
	private function decodeHeader( string $idToken ): array {
		$segments = explode('.', $idToken);

		if( count($segments) !== 3 ) {
			$this->logger->warning('OIDC: ID token is not a well-formed JWT', [ 'segment_count' => count($segments), 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token is not a well-formed JWT');
		}

		$decoded = json_decode(JWT::urlsafeB64Decode($segments[0]), true);

		if( !is_array($decoded) ) {
			$this->logger->warning('OIDC: ID token header is not valid JSON', [ 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token header is not valid JSON');
		}

		return $decoded;
	}

}
