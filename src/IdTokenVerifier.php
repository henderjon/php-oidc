<?php

namespace Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Psr\Clock\ClockInterface;

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
 */
final class IdTokenVerifier {

	public function __construct(
		private readonly HttpFetcherInterface $httpFetcher,
		private readonly ClockInterface $clock = new CurrentClock,
		private readonly int $leewaySeconds = 300,
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
	): Claims {
		$header = $this->decodeHeader($idToken);

		if( isset($header['enc']) ) {
			throw new AuthenticationFailedException('Encrypted ID tokens (JWE) are not supported');
		}

		$alg = $header['alg'] ?? null;

		if( !is_string($alg) || $alg === '' ) {
			throw new AuthenticationFailedException('ID token is missing its alg header');
		}

		$key = str_starts_with($alg, 'HS')
			? new Key($clientSecret, $alg)
			: $this->resolveAsymmetricKey($jwksUri, $alg, is_string($header['kid'] ?? null) ? $header['kid'] : null, $verifyTls);

		$claims = $this->decodeAndVerifySignature($idToken, $key);

		$this->verifyAccessTokenHash($claims, $alg, $accessToken);

		return $claims;
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
			throw new AuthenticationFailedException('ID token verification failed: ' . $e->getMessage(), previous: $e);
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
			throw new AuthenticationFailedException('ID token at_hash does not match the access token');
		}
	}

	/**
	 * @throws AuthenticationFailedException
	 * @throws ProviderDiscoveryException
	 */
	private function resolveAsymmetricKey( string $jwksUri, string $alg, ?string $kid, bool $verifyTls ): Key {
		$keySet = JWK::parseKeySet($this->fetchJwks($jwksUri, $verifyTls), $alg);

		if( $kid !== null && isset($keySet[$kid]) ) {
			return $keySet[$kid];
		}

		if( count($keySet) === 1 ) {
			return array_values($keySet)[0];
		}

		throw new AuthenticationFailedException('Unable to find a matching JWKS key for this ID token');
	}

	/**
	 * @throws ProviderDiscoveryException
	 * @return array<string,mixed>
	 */
	private function fetchJwks( string $jwksUri, bool $verifyTls ): array {
		try {
			$response = $this->httpFetcher->fetch($jwksUri, null, verifyTls: $verifyTls);
		} catch( HttpTransportException $e ) {
			throw new ProviderDiscoveryException("Unable to fetch JWKS from {$jwksUri}", previous: $e);
		}

		if( $response->status !== 200 ) {
			throw new ProviderDiscoveryException("JWKS endpoint {$jwksUri} returned HTTP {$response->status}");
		}

		$decoded = json_decode($response->body, true);

		if( !is_array($decoded) ) {
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
			throw new AuthenticationFailedException('ID token is not a well-formed JWT');
		}

		$decoded = json_decode(JWT::urlsafeB64Decode($segments[0]), true);

		if( !is_array($decoded) ) {
			throw new AuthenticationFailedException('ID token header is not valid JSON');
		}

		return $decoded;
	}

}
