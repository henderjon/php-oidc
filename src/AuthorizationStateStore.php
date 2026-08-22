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
 * One store tracks exactly one in-flight attempt at a time. When the
 * injected cache is shared across users - the common case for a load
 * balanced application backed by something like memcache - pass a
 * `cacheKeySuffix` derived from the current user's session, not a static
 * value, or two users authenticating at the same time will overwrite each
 * other's state, nonce, and code_verifier. A static suffix only separates
 * one SSO integration from another; it does nothing to separate concurrent
 * users of the same integration.
 */
final class AuthorizationStateStore {

	private const STATE_KEY = 'henderjon.oidc.state';
	private const NONCE_KEY = 'henderjon.oidc.nonce';
	private const CODE_VERIFIER_KEY = 'henderjon.oidc.code_verifier';

	public function __construct(
		private readonly CacheInterface $cache,
		private readonly string $cacheKeySuffix = "", // scope this to the current user's session when the cache is shared across users
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
