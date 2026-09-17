<?php

namespace Oidc\Fakes;

use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache whose every method throws, for testing how a caller reacts to a cache backend
 * that raises `Psr\SimpleCache\CacheException` (or its `InvalidArgumentException` sub-interface)
 * instead of returning normally. A conformant backend can legitimately do this for a key
 * containing a reserved character or exceeding its supported length - see PSR-16's own key
 * requirements - so a caller that only ever checks a boolean return or a null miss is not
 * actually handling every outcome PSR-16 allows.
 */
final class ThrowingCache implements CacheInterface {

	public function get( string $key, mixed $default = null ): mixed {
		throw new SimpleCacheInvalidArgumentException("Invalid key: {$key}");
	}

	public function set( string $key, mixed $value, \DateInterval|int|null $ttl = null ): bool {
		throw new SimpleCacheInvalidArgumentException("Invalid key: {$key}");
	}

	public function delete( string $key ): bool {
		throw new SimpleCacheInvalidArgumentException("Invalid key: {$key}");
	}

	public function clear(): bool {
		throw new SimpleCacheInvalidArgumentException('clear() should never be called by this library');
	}

	public function getMultiple( iterable $keys, mixed $default = null ): iterable {
		throw new SimpleCacheInvalidArgumentException('getMultiple() should never be called by this library');
	}

	public function setMultiple( iterable $values, \DateInterval|int|null $ttl = null ): bool {
		throw new SimpleCacheInvalidArgumentException('setMultiple() should never be called by this library');
	}

	public function deleteMultiple( iterable $keys ): bool {
		throw new SimpleCacheInvalidArgumentException('deleteMultiple() should never be called by this library');
	}

	public function has( string $key ): bool {
		throw new SimpleCacheInvalidArgumentException("Invalid key: {$key}");
	}

}
