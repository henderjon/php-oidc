<?php

namespace Oidc;

use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;

/**
 * Forwards a log call to the wrapped logger only when its level is in an explicit allow-list,
 * dropping every other level outright.
 *
 * A conventional "minimum severity" filter cannot express this on its own: set at `debug`, it
 * lets everything through, since `debug` is already PSR-3's lowest severity - there is no
 * threshold that means "debug only." This exists for exactly that case: a caller who wants,
 * say, only this library's debug-level tracing routed somewhere (a separate file, a different
 * verbosity, temporarily on during troubleshooting) without also receiving, or being forced to
 * reconfigure, everything else their own logger already handles.
 *
 * `$allowedLevels` is a discrete set, not a range - any combination is valid, including
 * combinations no linear severity ordering could express together (`debug` and `critical`,
 * say, with everything between them excluded). This class never validates a level against
 * PSR-3's own eight constants (see Psr\Log\LogLevel) - it is a plain string comparison, so
 * `$allowedLevels` can equally well contain PSR-3's own levels, a caller's own custom level
 * ("audit", say), or a mix of both. Nothing here is PSR-3-specific except the interface being
 * decorated.
 *
 * `LogLevels::ALL` is a different, narrower thing from "this array can hold a custom level":
 * it means "every level, without having to name any of them" - the one case a caller cannot
 * reach just by listing levels, custom or not, since it does not require knowing in advance
 * which levels might ever be logged.
 */
final class LogLevelFilterLogger extends AbstractLogger {

	/**
	 * @param list<string> $allowedLevels Any level string this logger might see - one of
	 *                                    Psr\Log\LogLevel's eight constants, a caller's own
	 *                                    custom level, or LogLevels::ALL to match every level
	 *                                    unconditionally without naming any of them.
	 */
	public function __construct(
		private readonly LoggerInterface $logger,
		private readonly array $allowedLevels,
	) {
	}

	public function log( $level, string|\Stringable $message, array $context = [] ): void {
		if( !in_array(LogLevels::ALL, $this->allowedLevels, true) && !in_array($level, $this->allowedLevels, true) ) {
			return;
		}

		$this->logger->log($level, $message, $context);
	}

}
