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
 * Verifies an ID token's signature (RS256 via JWKS, or HS256 via the
 * client secret) using `firebase/php-jwt`, and - since the token itself is
 * authentic once the signature checks out - its `at_hash` binding to an
 * access token, if both are present.
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
	) {
	}

	/**
	 * @throws AuthenticationFailedException
	 * @throws ProviderDiscoveryException
	 */
	public function verify(
		string $idToken,
		string $jwksUri,
		string $clientSecret,
		?string $accessToken = null,
		bool $verifyTls = true,
		?string $state = null,
	): Claims {
		$header = $this->decodeHeader($idToken, $state);

		if( isset($header['enc']) ) {
			$this->logger->warning('OIDC: ID token is encrypted (JWE), which is not supported', [ 'header' => $header, 'state' => $state ]);

			throw new AuthenticationFailedException('Encrypted ID tokens (JWE) are not supported');
		}

		$alg = $header['alg'] ?? null;

		if( !is_string($alg) || $alg === '' ) {
			$this->logger->warning('OIDC: ID token is missing its alg header', [ 'header' => $header, 'state' => $state ]);

			throw new AuthenticationFailedException('ID token is missing its alg header');
		}

		$key = str_starts_with($alg, 'HS')
			? new Key($clientSecret, $alg)
			: $this->resolveAsymmetricKey($jwksUri, $alg, is_string($header['kid'] ?? null) ? $header['kid'] : null, $verifyTls, $state);

		$claims = $this->decodeAndVerifySignature($idToken, $key, $state);

		$this->verifyAccessTokenHash($claims, $alg, $accessToken, $state);

		return $claims;
	}

	/**
	 * @throws AuthenticationFailedException
	 */
	private function decodeAndVerifySignature( string $idToken, Key $key, ?string $state ): Claims {
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
			$this->logger->warning('OIDC: ID token signature verification failed', [ 'exception' => $e, 'state' => $state ]);

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
	private function verifyAccessTokenHash( Claims $claims, string $alg, ?string $accessToken, ?string $state ): void {
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
			$this->logger->warning('OIDC: ID token at_hash does not match the access token', [ 'alg' => $alg, 'state' => $state ]);

			throw new AuthenticationFailedException('ID token at_hash does not match the access token');
		}
	}

	/**
	 * @throws AuthenticationFailedException
	 * @throws ProviderDiscoveryException
	 */
	private function resolveAsymmetricKey( string $jwksUri, string $alg, ?string $kid, bool $verifyTls, ?string $state ): Key {
		$keySet = JWK::parseKeySet($this->fetchJwks($jwksUri, $verifyTls, $state), $alg);

		if( $kid !== null && isset($keySet[$kid]) ) {
			return $keySet[$kid];
		}

		if( count($keySet) === 1 ) {
			return array_values($keySet)[0];
		}

		$this->logger->warning('OIDC: unable to find a matching JWKS key for this ID token', [
			'kid'            => $kid,
			'available_kids' => array_keys($keySet),
			'state'          => $state,
		]);

		throw new AuthenticationFailedException('Unable to find a matching JWKS key for this ID token');
	}

	/**
	 * @throws ProviderDiscoveryException
	 * @return array<string,mixed>
	 */
	private function fetchJwks( string $jwksUri, bool $verifyTls, ?string $state ): array {
		try {
			$response = $this->httpFetcher->fetch($jwksUri, null, verifyTls: $verifyTls);
		} catch( HttpTransportException $e ) {
			$this->logger->error('OIDC: unable to fetch JWKS', [ 'jwks_uri' => $jwksUri, 'exception' => $e, 'state' => $state ]);

			throw new ProviderDiscoveryException("Unable to fetch JWKS from {$jwksUri}", previous: $e);
		}

		if( $response->status !== 200 ) {
			$this->logger->error('OIDC: JWKS endpoint returned an unsuccessful response', [
				'jwks_uri'    => $jwksUri,
				'http_status' => $response->status,
				'state'       => $state,
			]);

			throw new ProviderDiscoveryException("JWKS endpoint {$jwksUri} returned HTTP {$response->status}");
		}

		$decoded = json_decode($response->body, true);

		if( !is_array($decoded) ) {
			$this->logger->error('OIDC: JWKS endpoint returned invalid JSON', [
				'jwks_uri'    => $jwksUri,
				'http_status' => $response->status,
				'state'       => $state,
			]);

			throw new ProviderDiscoveryException("JWKS endpoint {$jwksUri} returned invalid JSON");
		}

		return $decoded;
	}

	/**
	 * @throws AuthenticationFailedException
	 * @return array<string,mixed>
	 */
	private function decodeHeader( string $idToken, ?string $state ): array {
		$segments = explode('.', $idToken);

		if( count($segments) !== 3 ) {
			$this->logger->warning('OIDC: ID token is not a well-formed JWT', [ 'segment_count' => count($segments), 'state' => $state ]);

			throw new AuthenticationFailedException('ID token is not a well-formed JWT');
		}

		$decoded = json_decode(JWT::urlsafeB64Decode($segments[0]), true);

		if( !is_array($decoded) ) {
			$this->logger->warning('OIDC: ID token header is not valid JSON', [ 'state' => $state ]);

			throw new AuthenticationFailedException('ID token header is not valid JSON');
		}

		return $decoded;
	}

}
