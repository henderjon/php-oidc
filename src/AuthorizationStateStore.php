<?php

namespace Oidc;

use Oidc\Exceptions\AuthorizationStateException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheException;
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
 *
 * Every method here assumes the injected `LoggerInterface` does not throw. Nothing in this
 * class, or anywhere else in this library, catches an exception a logger raises - it propagates
 * exactly like any other exception, interrupting whichever method was logging at the time. That
 * is worth knowing because `consume()` calls `delete()` before it logs anything: if the injected
 * logger throws on that final debug call, the cache entry has already been cleared, so the
 * interrupted attempt cannot be completed by retrying the same callback - the state now matches
 * nothing, indistinguishable from an expired or forged one, and the caller has to restart the
 * whole authorization flow. `start()` has a milder version of the same risk: a throwing logger
 * on its own success-path debug call aborts `start()` after the cache write already succeeded,
 * leaving an inert entry nobody was ever given the state to reach - harmless, but still a
 * logging failure masquerading as this method's own failure. A logger that might throw (a
 * remote log shipper timing out, a full disk) should be wrapped in one that catches its own
 * exceptions before being passed in here, if that failure mode matters to the caller.
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

	/**
	 * Every state this class itself ever generates is `bin2hex(random_bytes($length))` -
	 * lowercase hex only, regardless of `$length`. `consume()` checks a callback's `state`
	 * against this same shape before it is ever used to build a cache key: PSR-16 reserves
	 * `{}()/\@:` in keys, none of which a hex string can ever contain, and an implausibly long
	 * value is rejected outright rather than handed to the cache backend to reject however it
	 * sees fit. 128 comfortably covers any realistic `$length` a caller might pass to `start()`
	 * (128 hex characters is `$length` = 64 bytes) while still rejecting a callback that pads
	 * `state` far past anything this class could have generated.
	 */
	private const MAX_STATE_LENGTH = 128;

	public function __construct(
		private readonly CacheInterface $cache,
		private readonly string $cacheKeySuffix = "",
		private readonly int $ttlSeconds = 600,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @param int<1,max> $length
	 * @throws AuthorizationStateException When the cache write itself fails, or the cache
	 *         backend throws instead of returning `false` - fail closed rather than hand back
	 *         a FlowState pointing at an attempt that was never actually persisted, which
	 *         `consume()` could never find later no matter what the provider echoes back.
	 * @throws \Throwable Whatever the injected logger itself throws, if it throws at all - see
	 *         this class's own docblock. The cache write above has already succeeded by the
	 *         time this method logs, so that failure mode is a logging problem, not this
	 *         method's own, even though it surfaces the same way.
	 */
	public function start(int $length = 16, ?string $codeVerifier = null): FlowState {
		$state = $this->randomToken($length);
		$nonce = $this->randomToken($length);

		try {
			$stored = $this->cache->set($this->flowKey($state), [
				'nonce'         => $nonce,
				'code_verifier' => $codeVerifier,
			], $this->ttlSeconds);
		} catch( CacheException $e ) {
			$this->logger->error('OIDC: cache threw while persisting a new authorization attempt', [
				'state'     => $this->loggableState($state),
				'exception' => $e,
				'security_relevant' => false,
			]);

			throw new AuthorizationStateException('Unable to persist authorization state', state: $this->loggableState($state), previous: $e);
		}

		if( !$stored ) {
			$this->logger->error('OIDC: failed to persist a new authorization attempt', [ 'state' => $this->loggableState($state), 'security_relevant' => false ]);

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
	 *
	 * @throws AuthorizationStateException When the cache backend throws instead of reporting a
	 *         miss - a malformed `state` never reaches the cache at all (see below), so this is
	 *         reserved for the backend genuinely failing on a well-formed key.
	 * @throws \Throwable Whatever the injected logger itself throws, if it throws at all - see
	 *         this class's own docblock. The cache entry has already been deleted above by the
	 *         time any of this method's own logging happens, so a throwing logger here
	 *         interrupts an otherwise-successful match: the caller gets neither a `FlowState`
	 *         nor a clean rejection, and the same callback cannot be retried, since the entry
	 *         backing it is already gone.
	 */
	public function consume(string $state): ?FlowState {
		// $state reaches here straight from an unauthenticated callback, before it is known to
		// match anything - PSR-16 reserves several characters in keys and only requires support
		// for keys up to 64 characters, so a crafted value containing one of those, or simply an
		// implausibly long one, could make a conformant cache backend throw instead of reporting
		// an ordinary miss. Rejecting anything not shaped like this class's own generated state
		// keeps every malformed callback failing the same way every other non-match does,
		// without ever handing an attacker-controlled string to the cache backend at all.
		if( !$this->isValidGeneratedStateFormat($state) ) {
			$this->logger->warning('OIDC: callback state is not shaped like one this class could have generated - rejecting without a cache lookup', [ 'state' => $this->loggableState($state) ]);

			return null;
		}

		$key = $this->flowKey($state);

		try {
			$flow    = $this->cache->get($key);
			$deleted = $this->cache->delete($key);
		} catch( CacheException $e ) {
			$this->logger->error('OIDC: cache threw while consuming an authorization attempt', [
				'state'     => $this->loggableState($state),
				'exception' => $e,
				'security_relevant' => false,
			]);

			throw new AuthorizationStateException('Unable to consume authorization state', state: $this->loggableState($state), previous: $e);
		}

		if( $flow === null ) {
			// warning, not alert: alert is reserved for a configuration choice worth a
			// developer's own review (CurlHttpFetcher's TLS-disabled flag,
			// ClaimsValidator's allowUntrustedAudiences opt-out actually letting an untrusted
			// audience through - that same opt-out logs at warning instead when what it lets
			// through is merely a malformed entry, not a meaningfully untrusted one) - a state
			// that matches nothing is a runtime event, not something anyone configured, even
			// though it is still worth a human's attention. See this method's own docblock for
			// the several distinct things a miss here could mean.
			$this->logger->warning('OIDC: no pending authorization flow found for the given state', [ 'state' => $this->loggableState($state) ]);

			return null;
		}

		if( !is_array($flow) || !is_string($flow['nonce'] ?? null) ) {
			$this->logger->error('OIDC: cached authorization flow entry is not the expected shape', [
				'state' => $this->loggableState($state),
				'type'  => get_debug_type($flow),
				'keys'  => is_array($flow) ? array_keys($flow) : null,
				'security_relevant' => false,
			]);

			return null;
		}

		if( !$deleted ) {
			// PSR-16 delete() is as ambiguous as get() about why it failed - "may not have
			// been cleared" rather than a firm claim, since some backends report false for
			// a key that was already gone, not only for a real error.
			$this->logger->info('OIDC: consumed authorization flow entry may not have been cleared from the cache', [
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

	/**
	 * Whether `$state` is shaped like something `randomToken()` could have produced -
	 * non-empty, no longer than `MAX_STATE_LENGTH`, and hex digits only. `ctype_xdigit()`
	 * accepts both cases even though `randomToken()` only ever generates lowercase - a callback
	 * echoing back an uppercase-hex state is still exactly as safe a cache key, so there is no
	 * reason to reject it just because this class would not have generated it in that case.
	 */
	private function isValidGeneratedStateFormat( string $state ): bool {
		return $state !== '' && strlen($state) <= self::MAX_STATE_LENGTH && ctype_xdigit($state);
	}

	private function loggableState(string $state): string {
		return Truncate::to($state, self::MAX_LOGGED_STATE_LENGTH);
	}

}
