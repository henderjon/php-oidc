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
 * `$allowedLevels` is a discrete set, not a range - any combination of PSR-3's eight levels
 * (see Psr\Log\LogLevel) is valid, including combinations no linear severity ordering could
 * express together (`debug` and `critical`, say, with everything between them excluded).
 *
 * Include `LogLevels::ALL` in `$allowedLevels` to opt into every level unconditionally,
 * including a level outside PSR-3's own eight constants - a caller with its own non-standard
 * level cannot otherwise be included just by enumerating LogLevel's constants by hand. See
 * LogLevels' own docblock.
 */
final class LogLevelFilterLogger extends AbstractLogger {

	/**
	 * @param list<string> $allowedLevels One or more of Psr\Log\LogLevel's constants, or
	 *                                    LogLevels::ALL to allow every level unconditionally.
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
