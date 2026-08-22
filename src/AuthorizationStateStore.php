<?php

namespace Oidc;

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
	private const CODE_VERIFIER_KEY = 'henderjon.oidc.code_verifier';

	public function __construct(
		private readonly CacheInterface $cache,
		private readonly string $cacheKeySuffix = "", // optional; use if using a global cache where name collisions are possible (READ: not session based)
		private readonly int $ttlSeconds = 600,
	) {
	}

	/**
	 * @param int<1,max> $length
	 */
	public function start(int $length = 16, ?string $codeVerifier = null): FlowState {
		$state = $this->randomToken($length);
		$nonce = $this->randomToken($length);

		$this->cache->set($this->stateKey(), $state, $this->ttlSeconds);
		$this->cache->set($this->nonceKey(), $nonce, $this->ttlSeconds);

		if( $codeVerifier !== null ) {
			$this->cache->set($this->codeVerifierKey(), $codeVerifier, $this->ttlSeconds);
		}

		return new FlowState($state, $nonce, $codeVerifier);
	}

	/**
	 * Reads and clears the persisted state/nonce. Any field that was never
	 * stored, or was already consumed, comes back null.
	 */
	public function consume(): FlowState {
		$state = $this->cache->get($this->stateKey());
		$nonce = $this->cache->get($this->nonceKey());
		$codeVerifier = $this->cache->get($this->codeVerifierKey());

		$this->cache->delete($this->stateKey());
		$this->cache->delete($this->nonceKey());
		$this->cache->delete($this->codeVerifierKey());

		return new FlowState(
			is_string($state) ? $state : null,
			is_string($nonce) ? $nonce : null,
			is_string($codeVerifier) ? $codeVerifier : null,
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

	private function codeVerifierKey(): string {
		return self::CODE_VERIFIER_KEY . ".{$this->cacheKeySuffix}";
	}

}
