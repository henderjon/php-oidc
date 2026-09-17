<?php

namespace Oidc\Fakes;

use Firebase\JWT\JWT;

/**
 * A throwaway Ed25519 (RFC 8037 OKP) key pair plus its JWKS document, generated fresh per
 * instance. `sodium_crypto_sign_keypair()`'s 64-byte "secret key" half is the seed plus the
 * public key concatenated - `firebase/php-jwt`'s own EdDSA signing path expects exactly that,
 * base64url-encoded, as a single-line string (see `JWT::sign()`'s `validateEdDSAKey()`, which
 * reads "the last non-empty line" of whatever string it is given).
 */
final class EdDsaKeyFixture {

	public const KEY_ID = 'test-eddsa-key-1';

	private string $secretKey;

	/** @var array<string,mixed> */
	private array $jwks;

	public function __construct() {
		$keyPair   = sodium_crypto_sign_keypair();
		$this->secretKey = sodium_crypto_sign_secretkey($keyPair);
		$publicKey = sodium_crypto_sign_publickey($keyPair);

		$this->jwks = [
			'keys' => [
				[
					'kty' => 'OKP',
					'kid' => self::KEY_ID,
					'use' => 'sig',
					'crv' => 'Ed25519',
					'x'   => JWT::urlsafeB64Encode($publicKey),
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
		$claims = [ 'sub' => 'default-test-subject', 'iat' => time(), 'exp' => time() + 3600, ...$claims ];

		return JWT::encode($claims, JWT::urlsafeB64Encode($this->secretKey), 'EdDSA', $keyId);
	}

}
