<?php

namespace Oidc;

use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;

/**
 * Forwards a log call to the wrapped logger only when its level satisfies an explicit
 * membership test, dropping every other level outright.
 *
 * A conventional "minimum severity" filter cannot express this on its own: set at `debug`, it
 * lets everything through, since `debug` is already PSR-3's lowest severity - there is no
 * threshold that means "debug only." This exists for exactly that case: a caller who wants,
 * say, only this library's debug-level tracing routed somewhere (a separate file, a different
 * verbosity, temporarily on during troubleshooting) without also receiving, or being forced to
 * reconfigure, everything else their own logger already handles.
 *
 * `$levels` and `$include` together express four distinct patterns, not just one allow-list:
 *
 *   none         new LogLevelFilterLogger($logger, [])
 *                Nothing passes. `$levels` is empty and `$include` defaults true, so no level
 *                can ever satisfy the membership test.
 *
 *   none, except new LogLevelFilterLogger($logger, [ LogLevel::DEBUG ])
 *                The ordinary allow-list case: nothing passes except the levels named.
 *
 *   all          new LogLevelFilterLogger($logger, [], include: false)
 *                Sugar: LogLevelFilterLogger::all($logger)
 *                Everything passes, including a level neither PSR-3 nor the caller has
 *                defined yet. See all()'s own docblock for why it gets a named constructor
 *                instead of callers spelling out an empty deny-list themselves.
 *
 *   all, except  new LogLevelFilterLogger($logger, [ LogLevel::DEBUG ], include: false)
 *                The deny-list case: everything passes except the levels named, including one
 *                that does not exist yet. The mirror image of "none, except."
 *
 * `$levels` is a discrete set, not a range, in either the allow-list or the deny-list case - any
 * combination is valid, including combinations no linear severity ordering could express
 * together (`debug` and `critical` alone, with everything between them excluded). This class
 * never validates a level against PSR-3's own eight constants (see Psr\Log\LogLevel) - it is a
 * plain string comparison, so `$levels` can equally well contain PSR-3's own levels, a caller's
 * own custom level ("audit", say), or a mix of both. Nothing here is PSR-3-specific except the
 * interface being decorated.
 *
 * The default, `$include: true`, fails closed - a level nobody named gets dropped, including
 * one this library or a wrapped logger adds later. `$include: false` fails open - a level
 * nobody named gets forwarded instead. That is a deliberate trade for the specific case it
 * exists for (skip this library's `debug` tracing, forward every other level unconditionally),
 * not a reason to prefer it generally over naming an allow-list directly. `$levels` is
 * deliberately named for neither mode specifically, rather than `$allowedLevels` or
 * `$excludedLevels` - it holds an allow-list when `$include` is true and a deny-list when it is
 * false, and a name tied to one mode would be wrong in the other.
 */
final class LogLevelFilterLogger extends AbstractLogger {

	/**
	 * @param list<string> $levels Any level string this logger might see - one of
	 *                             Psr\Log\LogLevel's eight constants or a caller's own custom
	 *                             level.
	 * @param bool $include When true (the default), $levels is an allow-list: only a level
	 *                       named in it is forwarded. When false, $levels is a deny-list: every
	 *                       level is forwarded except the ones named. See this class's own
	 *                       docblock for the four patterns this combination expresses.
	 */
	public function __construct(
		private readonly LoggerInterface $logger,
		private readonly array $levels,
		private readonly bool $include = true,
	) {
	}

	/**
	 * Forwards every level unconditionally, including one outside PSR-3's own eight defined
	 * constants - the one case an allow-list cannot reach by naming levels, since a caller
	 * defining its own custom level has nothing to name in advance. Sugar for an empty
	 * deny-list - `new LogLevelFilterLogger($logger, [], include: false)` - since "everything
	 * is forwarded because nothing is excluded" is not obviously what that means at a glance.
	 */
	public static function all( LoggerInterface $logger ): self {
		return new self($logger, [], include: false);
	}

	public function log( $level, string|\Stringable $message, array $context = [] ): void {
		if( in_array($level, $this->levels, true) !== $this->include ) {
			return;
		}

		$this->logger->log($level, $message, $context);
	}

}
