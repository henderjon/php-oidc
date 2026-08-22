<?php

namespace Henderjon\Oidc\Fakes;

use Psr\Clock\ClockInterface;

/**
 * A clock that always returns the same instant, for deterministically
 * testing expiry/nbf/iat handling instead of racing against the wall clock.
 */
final class FixedClock implements ClockInterface {

	public function __construct(
		private readonly \DateTimeImmutable $now,
	) {
	}

	public function now(): \DateTimeImmutable {
		return $this->now;
	}

}
