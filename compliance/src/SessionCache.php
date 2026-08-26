<?php

namespace Compliance;

use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache backed by $_SESSION - the only thing this harness needs to survive the
 * redirect out to the conformance suite and back. php's built-in dev server does not keep
 * any in-memory state between requests, so state/nonce/PKCE verifier (written by
 * AuthorizationStateStore before the redirect, read by it after the callback) has to live
 * somewhere that does. The session cookie is what makes that round trip work.
 */
final class SessionCache implements CacheInterface {

	/**
	 * @param mixed $default
	 */
	public function get(string $key, mixed $default = null): mixed {
		$entry = $_SESSION['cache'][$key] ?? null;

		if( !is_array($entry) || !array_key_exists('value', $entry) ) {
			return $default;
		}

		if( $entry['expires_at'] !== null && $entry['expires_at'] < time() ) {
			unset($_SESSION['cache'][$key]);

			return $default;
		}

		return $entry['value'];
	}

	public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool {
		$_SESSION['cache'][$key] = [
			'value'      => $value,
			'expires_at' => $this->expiresAt($ttl),
		];

		return true;
	}

	public function delete(string $key): bool {
		unset($_SESSION['cache'][$key]);

		return true;
	}

	public function clear(): bool {
		$_SESSION['cache'] = [];

		return true;
	}

	/**
	 * @param iterable<string> $keys
	 * @param mixed $default
	 * @return iterable<string,mixed>
	 */
	public function getMultiple(iterable $keys, mixed $default = null): iterable {
		$result = [];

		foreach( $keys as $key ) {
			$result[$key] = $this->get($key, $default);
		}

		return $result;
	}

	/**
	 * @param iterable<string,mixed> $values
	 */
	public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool {
		foreach( $values as $key => $value ) {
			$this->set((string)$key, $value, $ttl);
		}

		return true;
	}

	/**
	 * @param iterable<string> $keys
	 */
	public function deleteMultiple(iterable $keys): bool {
		foreach( $keys as $key ) {
			$this->delete($key);
		}

		return true;
	}

	public function has(string $key): bool {
		$miss = new \stdClass;

		return $this->get($key, $miss) !== $miss;
	}

	private function expiresAt(\DateInterval|int|null $ttl): ?int {
		if( $ttl === null ) {
			return null;
		}

		if( is_int($ttl) ) {
			return time() + $ttl;
		}

		return (new \DateTimeImmutable())->add($ttl)->getTimestamp();
	}

}
