<?php

namespace Oidc\Fakes;

use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache whose writes always report failure, for testing how
 * callers react to a cache write that never lands - without needing a
 * real cache backend to actually go down.
 */
final class FailingCache implements CacheInterface {

	public function get( string $key, mixed $default = null ): mixed {
		return $default;
	}

	public function set( string $key, mixed $value, \DateInterval|int|null $ttl = null ): bool {
		return false;
	}

	public function delete( string $key ): bool {
		return false;
	}

	public function clear(): bool {
		return false;
	}

	public function getMultiple( iterable $keys, mixed $default = null ): iterable {
		$result = [];
		foreach( $keys as $key ) {
			$result[$key] = $default;
		}

		return $result;
	}

	public function setMultiple( iterable $values, \DateInterval|int|null $ttl = null ): bool {
		return false;
	}

	public function deleteMultiple( iterable $keys ): bool {
		return false;
	}

	public function has( string $key ): bool {
		return false;
	}

}
