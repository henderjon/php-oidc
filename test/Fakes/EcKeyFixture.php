<?php

namespace Oidc\Fakes;

use Firebase\JWT\JWT;

/**
 * A throwaway EC (P-256) key pair plus its JWKS document, generated fresh per instance.
 * Unlike RsaKeyFixture, its JWKS entry deliberately omits "alg" - JWKS entries commonly do
 * not declare one (RFC 7517 §4.4 makes it optional), which is exactly the case
 * IdTokenVerifier's own JWK-type check exists to cover.
 *
 * `openssl_pkey_get_details()`'s `ec.x`/`ec.y` are minimal-length big-endian integers, not
 * fixed-width - roughly 1 in 256 keys generated has a coordinate one byte shorter than
 * P-256's fixed 32-byte width, because its leading byte happens to be zero and PHP's OpenSSL
 * binding does not restore it. Encoding that shorter value directly into the JWK produces a
 * document `firebase/php-jwt`'s own `JWK::parseKeySet()` cannot reassemble into a valid EC
 * public key, surfacing as an intermittent `DomainException: OpenSSL unable to validate key`
 * - confirmed by generating 2,000 keys, finding this in ~0.85% of them, and reproducing the
 * exact failure from an unpadded coordinate. Zero-padding both coordinates to the curve's
 * fixed width before encoding is the fix RFC 7518 §6.2.1.2/6.2.1.3 already specify for `x`/`y`.
 */
final class EcKeyFixture {

	public const KEY_ID = 'test-ec-key-1';

	// P-256's fixed coordinate width in bytes (256 bits) - see the class docblock.
	private const COORDINATE_LENGTH_BYTES = 32;

	private string $privateKeyPem;

	/** @var array<string,mixed> */
	private array $jwks;

	public function __construct() {
		$resource = openssl_pkey_new([
			'curve_name'       => 'prime256v1',
			'private_key_type' => OPENSSL_KEYTYPE_EC,
		]);

		if( $resource === false ) {
			throw new \RuntimeException('Unable to generate an EC key pair for tests');
		}

		openssl_pkey_export($resource, $privateKeyPem);
		$this->privateKeyPem = $privateKeyPem;
		$details             = openssl_pkey_get_details($resource);

		if( $details === false ) {
			throw new \RuntimeException('Unable to read the generated EC key pair for tests');
		}

		$this->jwks = [
			'keys' => [
				[
					'kty' => 'EC',
					'kid' => self::KEY_ID,
					'use' => 'sig',
					'crv' => 'P-256',
					'x'   => JWT::urlsafeB64Encode(self::fixedWidthCoordinate($details['ec']['x'])),
					'y'   => JWT::urlsafeB64Encode(self::fixedWidthCoordinate($details['ec']['y'])),
				],
			],
		];
	}

	/**
	 * Public (not private) so EcKeyFixtureTest can assert its behavior directly against a
	 * deliberately short input, rather than relying on the ~1-in-256 chance of a real
	 * generated key happening to need it.
	 */
	public static function fixedWidthCoordinate( string $coordinate ): string {
		return str_pad($coordinate, self::COORDINATE_LENGTH_BYTES, "\x00", STR_PAD_LEFT);
	}

	/**
	 * @return array<string,mixed>
	 */
	public function jwks(): array {
		return $this->jwks;
	}

	public function jwksJson(): string {
		return json_encode($this->jwks, JSON_THROW_ON_ERROR);
	}

	/**
	 * @param array<string,mixed> $claims
	 */
	public function sign( array $claims, ?string $keyId = self::KEY_ID ): string {
		return JWT::encode($claims, $this->privateKeyPem, 'ES256', $keyId);
	}

}
