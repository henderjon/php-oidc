<?php

namespace Henderjon\Oidc;

use Psr\SimpleCache\CacheInterface;

/**
 * Generates and persists the state/nonce for one in-flight authorization
 * attempt via an injected PSR-16 cache, and reads + clears them on
 * completion.
 *
 * Replaces jumbojett's `protected getSessionKey/setSessionKey/unsetSessionKey`
 * subclass hook - callers inject whatever `Psr\SimpleCache\CacheInterface`
 * they want (a real cache, or a plain in-memory one in tests) instead of
 * subclassing anything.
 *
 * One store tracks exactly one in-flight attempt at a time - scope a
 * separate cache instance (or cacheKeySuffix) per SSO integration if you
 * need more than one in flight concurrently.
 */
final class AuthorizationStateStore {

	private const STATE_KEY = 'henderjon.oidc.state';
	private const NONCE_KEY = 'henderjon.oidc.nonce';

	public function __construct(
		private readonly CacheInterface $cache,
		private readonly string $cacheKeySuffix = "", // optional; use if using a global cache where name collisions are possible (READ: not session based)
		private readonly int $ttlSeconds = 600,
	) {
	}

	/**
	 * @param int<1,max> $length
	 */
	public function start(int $length = 16): FlowState {
		$state = $this->randomToken($length);
		$nonce = $this->randomToken($length);

		$this->cache->set($this->stateKey(), $state, $this->ttlSeconds);
		$this->cache->set($this->nonceKey(), $nonce, $this->ttlSeconds);

		return new FlowState($state, $nonce);
	}

	/**
	 * Reads and clears the persisted state/nonce. Any field that was never
	 * stored, or was already consumed, comes back null.
	 */
	public function consume(): FlowState {
		$state = $this->cache->get($this->stateKey());
		$nonce = $this->cache->get($this->nonceKey());

		$this->cache->delete($this->stateKey());
		$this->cache->delete($this->nonceKey());

		return new FlowState(
			is_string($state) ? $state : null,
			is_string($nonce) ? $nonce : null,
		);
	}

	/**
	 * @param int<1,max> $length
	 */
	private function randomToken(int $length): string {
		return bin2hex(random_bytes($length));
	}

	private function stateKey(): string {
		return self::STATE_KEY . ".{$this->cacheKeySuffix}";
	}

	private function nonceKey(): string {
		return self::NONCE_KEY . ".{$this->cacheKeySuffix}";
	}

}
