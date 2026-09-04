<?php

namespace Oidc;

use Oidc\Exceptions\AuthorizationStateException;
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
 * already guarantees that. Scope it to something session- or user-bound
 * (see the example applications) if you want a browser session to only
 * ever be able to consume its own attempt - this class does not enforce
 * that binding itself, since what "session" means is entirely up to the
 * host application.
 *
 * `consume()` is not atomic: it is a `get()` followed by a `delete()`, and
 * PSR-16 (`Psr\SimpleCache\CacheInterface`) has no compare-and-delete or
 * get-and-delete primitive to make that one operation. Two requests racing
 * to consume the exact same `state` could therefore both read the entry
 * before either deletes it. This is deliberately not solved here with a
 * lock or a backend-specific atomic op - both would mean either a new
 * dependency or code that only works against specific cache backends,
 * against this library's own dependency-light premise, for a race with a
 * bounded impact: both racing attempts still have to redeem the same
 * authorization `code` at the token endpoint, and every OAuth authorization
 * server enforces that a code is redeemable only once (RFC 6749 §4.1.2).
 * The race can cause a confusing double local attempt; it cannot itself
 * produce two valid sessions from one code.
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
	 * @throws AuthorizationStateException When the cache write itself fails - fail closed
	 *         rather than hand back a FlowState pointing at an attempt that was never
	 *         actually persisted, which `consume()` could never find later no matter what
	 *         the provider echoes back.
	 */
	public function start(int $length = 16, ?string $codeVerifier = null): FlowState {
		$state = $this->randomToken($length);
		$nonce = $this->randomToken($length);

		$stored = $this->cache->set($this->flowKey($state), [
			'nonce'         => $nonce,
			'code_verifier' => $codeVerifier,
		], $this->ttlSeconds);

		if( !$stored ) {
			$this->logger->error('OIDC: failed to persist a new authorization attempt', [ 'state' => $this->loggableState($state) ]);

			throw new AuthorizationStateException('Unable to persist authorization state', state: $this->loggableState($state));
		}

		$this->logger->debug('OIDC: persisted a new authorization attempt', [
			'state'             => $this->loggableState($state),
			'ttl_seconds'       => $this->ttlSeconds,
			'has_code_verifier' => $codeVerifier !== null,
		]);

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
		$key     = $this->flowKey($state);
		$flow    = $this->cache->get($key);
		$deleted = $this->cache->delete($key);

		if( $flow === null ) {
			// warning, not alert: alert is reserved for a configuration choice worth a
			// developer's own review (CurlHttpFetcher's TLS-disabled flag,
			// ClaimsValidator's allowUntrustedAudiences opt-out) - a state that matches
			// nothing is a runtime event, not something anyone configured, even though it
			// is still worth a human's attention. See this method's own docblock for the
			// several distinct things a miss here could mean.
			$this->logger->warning('OIDC: no pending authorization flow found for the given state', [ 'state' => $this->loggableState($state) ]);

			return null;
		}

		if( !is_array($flow) || !is_string($flow['nonce'] ?? null) ) {
			$this->logger->error('OIDC: cached authorization flow entry is not the expected shape', [
				'state' => $this->loggableState($state),
				'type'  => get_debug_type($flow),
				'keys'  => is_array($flow) ? array_keys($flow) : null,
			]);

			return null;
		}

		if( !$deleted ) {
			// PSR-16 delete() is as ambiguous as get() about why it failed - "may not have
			// been cleared" rather than a firm claim, since some backends report false for
			// a key that was already gone, not only for a real error.
			$this->logger->notice('OIDC: consumed authorization flow entry may not have been cleared from the cache', [
				'state' => $this->loggableState($state),
			]);
		}

		$codeVerifier = $flow['code_verifier'] ?? null;
		$codeVerifier = is_string($codeVerifier) ? $codeVerifier : null;

		$this->logger->debug('OIDC: consumed an authorization attempt', [
			'state'             => $this->loggableState($state),
			'has_code_verifier' => $codeVerifier !== null,
		]);

		return new FlowState($state, $flow['nonce'], $codeVerifier);
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
