<?php

namespace Henderjon\Oidc;

use Psr\Clock\ClockInterface;

/**
 * The default clock for IdTokenVerifier and OpenIDConnectClient - just
 * wraps the system clock so tests can inject a fixed one instead.
 */
final class CurrentClock implements ClockInterface {

	public function now(): \DateTimeImmutable {
		return new \DateTimeImmutable;
	}

}
