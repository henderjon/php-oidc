<?php

namespace Oidc\Fakes;

use Psr\SimpleCache\CacheInterface;

/**
 * A minimal PSR-16 cache backed by a plain array, for tests that need a
 * real CacheInterface without a real caching backend. TTLs are accepted
 * but not enforced - nothing in this test suite waits for an expiry.
 */
final class InMemoryCache implements CacheInterface {

	/** @var array<string,mixed> */
	private array $values = [];

	public function get( string $key, mixed $default = null ): mixed {
		return $this->values[$key] ?? $default;
	}

	public function set( string $key, mixed $value, \DateInterval|int|null $ttl = null ): bool {
		$this->values[$key] = $value;

		return true;
	}

	public function delete( string $key ): bool {
		unset($this->values[$key]);

		return true;
	}

	public function clear(): bool {
		$this->values = [];

		return true;
	}

	public function getMultiple( iterable $keys, mixed $default = null ): iterable {
		$result = [];
		foreach( $keys as $key ) {
			$result[$key] = $this->get($key, $default);
		}

		return $result;
	}

	public function setMultiple( iterable $values, \DateInterval|int|null $ttl = null ): bool {
		foreach( $values as $key => $value ) {
			$this->set($key, $value, $ttl);
		}

		return true;
	}

	public function deleteMultiple( iterable $keys ): bool {
		foreach( $keys as $key ) {
			$this->delete($key);
		}

		return true;
	}

	public function has( string $key ): bool {
		return array_key_exists($key, $this->values);
	}

}
