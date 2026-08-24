<?php

namespace Oidc\Fakes;

use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache that behaves normally except delete() always reports
 * failure, for testing how callers react when a cache backend cannot
 * confirm a key was actually removed.
 */
final class DeleteFailingCache implements CacheInterface {

	public function __construct(
		private readonly CacheInterface $inner = new InMemoryCache,
	) {
	}

	public function get( string $key, mixed $default = null ): mixed {
		return $this->inner->get($key, $default);
	}

	public function set( string $key, mixed $value, \DateInterval|int|null $ttl = null ): bool {
		return $this->inner->set($key, $value, $ttl);
	}

	public function delete( string $key ): bool {
		$this->inner->delete($key);

		return false;
	}

	public function clear(): bool {
		return $this->inner->clear();
	}

	public function getMultiple( iterable $keys, mixed $default = null ): iterable {
		return $this->inner->getMultiple($keys, $default);
	}

	public function setMultiple( iterable $values, \DateInterval|int|null $ttl = null ): bool {
		return $this->inner->setMultiple($values, $ttl);
	}

	public function deleteMultiple( iterable $keys ): bool {
		return $this->inner->deleteMultiple($keys);
	}

	public function has( string $key ): bool {
		return $this->inner->has($key);
	}

}
