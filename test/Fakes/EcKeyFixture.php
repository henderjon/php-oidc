<?php

namespace Oidc\Fakes;

use Firebase\JWT\JWT;

/**
 * A throwaway EC (P-256) key pair plus its JWKS document, generated fresh per instance.
 * Unlike RsaKeyFixture, its JWKS entry deliberately omits "alg" - JWKS entries commonly do
 * not declare one (RFC 7517 §4.4 makes it optional), which is exactly the case
 * IdTokenVerifier's own JWK-type check exists to cover.
 */
final class EcKeyFixture {

	public const KEY_ID = 'test-ec-key-1';

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
					'x'   => JWT::urlsafeB64Encode($details['ec']['x']),
					'y'   => JWT::urlsafeB64Encode($details['ec']['y']),
				],
			],
		];
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
