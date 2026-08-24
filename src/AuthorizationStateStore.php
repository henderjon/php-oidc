<?php

namespace Oidc;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
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
 * Each attempt gets its own cache entry, keyed by the random `state` that
 * attempt generated - not a shared slot. `start()` returns that state as
 * part of the FlowState, and the caller sends it out with the redirect;
 * `consume()` takes the state the provider echoed back and looks up that
 * exact entry. This is what lets any number of attempts - concurrent users
 * sharing one cache, or one user with two tabs open - run at once without
 * overwriting each other, and it is why `consume()` needs the state handed
 * back to it rather than reading a fixed key.
 *
 * `cacheKeySuffix` is now just a namespace, for keeping one integration's
 * keys visually distinct from another's when they share a cache (or cache
 * dump) - not a correctness requirement. Two stores with the same suffix,
 * or no suffix at all, will not collide with each other; the state itself
 * already guarantees that.
 */
final class AuthorizationStateStore {

	private const FLOW_KEY_PREFIX = 'henderjon.oidc.flow';

	/**
	 * `state` reaches consume() straight from the callback, before it is known to
	 * match anything - so it is still attacker-controlled at the point it gets
	 * logged. Cap what actually lands in a log record so a crafted callback cannot
	 * pad every warning this class emits with an arbitrarily large value.
	 */
	private const MAX_LOGGED_STATE_LENGTH = 64;

	public function __construct(
		private readonly CacheInterface $cache,
		private readonly string $cacheKeySuffix = "",
		private readonly int $ttlSeconds = 600,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @param int<1,max> $length
	 */
	public function start(int $length = 16, ?string $codeVerifier = null): FlowState {
		$state = $this->randomToken($length);
		$nonce = $this->randomToken($length);

		$this->cache->set($this->flowKey($state), [
			'nonce'         => $nonce,
			'code_verifier' => $codeVerifier,
		], $this->ttlSeconds);

		return new FlowState($state, $nonce, $codeVerifier);
	}

	/**
	 * Looks up and clears the attempt started under the given state. Returns
	 * null if no such attempt exists - the caller must treat every reason the
	 * same way: reject the callback. The logger gets more detail than the
	 * caller does, but PSR-16's `get()` only ever reports a hit or a miss -
	 * it cannot say why a miss happened, so a forged/wrong state, an expired
	 * entry, and one evicted early by the cache backend all log identically
	 * as "not found". Only a hit that is not the shape this class wrote
	 * (`corrupted`) is actually distinguishable from that.
	 */
	public function consume(string $state): ?FlowState {
		$key  = $this->flowKey($state);
		$flow = $this->cache->get($key);

		$this->cache->delete($key);

		if( $flow === null ) {
			$this->logger->warning('OIDC: no pending authorization flow found for the given state', [ 'state' => $this->loggableState($state) ]);

			return null;
		}

		if( !is_array($flow) || !is_string($flow['nonce'] ?? null) ) {
			$this->logger->warning('OIDC: cached authorization flow entry is not the expected shape', [
				'state' => $this->loggableState($state),
				'type'  => get_debug_type($flow),
				'keys'  => is_array($flow) ? array_keys($flow) : null,
			]);

			return null;
		}

		$codeVerifier = $flow['code_verifier'] ?? null;

		return new FlowState($state, $flow['nonce'], is_string($codeVerifier) ? $codeVerifier : null);
	}

	/**
	 * @param int<1,max> $length
	 */
	private function randomToken(int $length): string {
		return bin2hex(random_bytes($length));
	}

	private function flowKey(string $state): string {
		return self::FLOW_KEY_PREFIX . ".{$this->cacheKeySuffix}.{$state}";
	}

	private function loggableState(string $state): string {
		return strlen($state) > self::MAX_LOGGED_STATE_LENGTH
			? substr($state, 0, self::MAX_LOGGED_STATE_LENGTH) . '...(truncated)'
			: $state;
	}

}
