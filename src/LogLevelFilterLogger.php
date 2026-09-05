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
 * "Every level, without having to name any of them" - the one case not reachable just by
 * listing levels, custom or not, since it does not require knowing in advance which levels
 * might ever be logged - is not expressible through the constructor at all. Use the `all()`
 * factory for that instead of trying to name a sentinel level in `$allowedLevels`: PSR-3 never
 * restricts a log call's level to its own eight constants, so any string a caller might pick as
 * a stand-in for "everything" is, at least in principle, also a legal level some logger
 * somewhere actually uses - keeping that value out of the constructor's own type entirely, and
 * out of this class's public API, means there is no string a caller could type into
 * `$allowedLevels` by mistake and get "everything" instead of "one specific, oddly-named level."
 */
final class LogLevelFilterLogger extends AbstractLogger {

	private const ALL = '*';

	/**
	 * @param list<string> $allowedLevels Any level string this logger might see - one of
	 *                                    Psr\Log\LogLevel's eight constants or a caller's own
	 *                                    custom level. Use the `all()` factory, not this
	 *                                    constructor, to match every level unconditionally.
	 */
	public function __construct(
		private readonly LoggerInterface $logger,
		private readonly array $allowedLevels,
	) {
	}

	/**
	 * Forwards every level unconditionally, including one outside PSR-3's own eight defined
	 * constants - the one case `$allowedLevels` cannot reach by naming levels, since a caller
	 * defining its own custom level has nothing to name in advance.
	 */
	public static function all( LoggerInterface $logger ): self {
		return new self($logger, [ self::ALL ]);
	}

	public function log( $level, string|\Stringable $message, array $context = [] ): void {
		if( !in_array(self::ALL, $this->allowedLevels, true) && !in_array($level, $this->allowedLevels, true) ) {
			return;
		}

		$this->logger->log($level, $message, $context);
	}

}
