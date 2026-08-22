<?php

namespace Henderjon\Oidc\Fakes;

use Firebase\JWT\JWT;

/**
 * A throwaway RSA key pair plus its JWKS document, generated fresh per
 * instance, for signing and verifying test ID tokens without any live IdP.
 */
final class RsaKeyFixture {

	public const KEY_ID = 'test-key-1';

	private string $privateKeyPem;

	/** @var array<string,mixed> */
	private array $jwks;

	public function __construct() {
		$resource = openssl_pkey_new([
			'private_key_bits' => 2048,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		]);

		if( $resource === false ) {
			throw new \RuntimeException('Unable to generate an RSA key pair for tests');
		}

		openssl_pkey_export($resource, $privateKeyPem);
		$this->privateKeyPem = $privateKeyPem;
		$details             = openssl_pkey_get_details($resource);

		if( $details === false ) {
			throw new \RuntimeException('Unable to read the generated RSA key pair for tests');
		}

		$this->jwks = [
			'keys' => [
				[
					'kty' => 'RSA',
					'kid' => self::KEY_ID,
					'use' => 'sig',
					'alg' => 'RS256',
					'n'   => JWT::urlsafeB64Encode($details['rsa']['n']),
					'e'   => JWT::urlsafeB64Encode($details['rsa']['e']),
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
		return JWT::encode($claims, $this->privateKeyPem, 'RS256', $keyId);
	}

}
