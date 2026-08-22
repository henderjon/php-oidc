<?php

namespace Oidc;

/**
 * A bag of decoded claims - from a verified ID token or a userinfo
 * response. One shape for both.
 */
final class Claims {

	/**
	 * @var array<string,mixed>
	 */
	private readonly array $claims;

	/**
	 * @param array<string,mixed>|\stdClass $claims
	 */
	public function __construct( \stdClass|array $claims ) {
		$this->claims = (array)$claims;
	}

	public function get( string $key, mixed $default = null ): mixed {
		return $this->claims[$key] ?? $default;
	}

	public function has( string $key ): bool {
		return array_key_exists($key, $this->claims);
	}

	/**
	 * @return array<string,mixed>
	 */
	public function all(): array {
		return $this->claims;
	}

}
