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
 * `$levels` is a discrete set, not a range - any combination is valid, including combinations
 * no linear severity ordering could express together (`debug` and `critical`, say, with
 * everything between them excluded). This class never validates a level against PSR-3's own
 * eight constants (see Psr\Log\LogLevel) - it is a plain string comparison, so `$levels` can
 * equally well contain PSR-3's own levels, a caller's own custom level ("audit", say), or a mix
 * of both. Nothing here is PSR-3-specific except the interface being decorated.
 *
 * "Every level, without having to name any of them" - the one case not reachable just by
 * listing levels, custom or not, since it does not require knowing in advance which levels
 * might ever be logged - is not expressible through the constructor at all. Use the `all()`
 * factory for that instead of trying to name a sentinel level in `$levels`: PSR-3 never
 * restricts a log call's level to its own eight constants, so any string a caller might pick as
 * a stand-in for "everything" is, at least in principle, also a legal level some logger
 * somewhere actually uses - keeping that value out of the constructor's own type entirely, and
 * out of this class's public API, means there is no string a caller could type into `$levels`
 * by mistake and get "everything" instead of "one specific, oddly-named level."
 *
 * `allExcept()` is the deny-list dual of `all()` - forward everything except a named few,
 * rather than only a named few. Unlike `all()`, it needs no sentinel: excluding a level is just
 * a plain membership check in the other direction, and works the same way for a custom level as
 * for one of PSR-3's own eight. It inherits the opposite default-safety story from the rest of
 * this class, though, and that is a deliberate trade, not an oversight: the plain allow-list
 * constructor fails closed - a level nobody named gets dropped, including one this library or a
 * wrapped logger adds later - while `allExcept()` fails open - a level nobody named gets
 * forwarded. Reach for it only when that is actually what is wanted (skip this library's
 * `debug` tracing, forward every other level including ones that do not exist yet), not as a
 * shorter way to spell an allow-list a caller could have named directly. `$levels` is
 * deliberately the name of this class's own field in both modes, rather than `$allowedLevels` -
 * it holds an allow-list under the plain constructor and a deny-list under `allExcept()`, and a
 * name tied to one mode would be wrong in the other.
 */
final class LogLevelFilterLogger extends AbstractLogger {

	private const ALL = '*';

	/**
	 * @param list<string> $levels Any level string this logger might see - one of
	 *                             Psr\Log\LogLevel's eight constants or a caller's own custom
	 *                             level. Use the `all()` factory, not this constructor, to
	 *                             match every level unconditionally.
	 * @param bool $include When false, treats $levels as a deny-list instead of an allow-list -
	 *                       set only via the `allExcept()` factory, not directly.
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
	 * defining its own custom level has nothing to name in advance.
	 */
	public static function all( LoggerInterface $logger ): self {
		return new self($logger, [ self::ALL ]);
	}

	/**
	 * Forwards every level except the ones named, including a level neither this library nor
	 * the caller has defined yet - the mirror image of `all()`'s blanket allow, and of the
	 * plain constructor's fail-closed allow-list. See this class's own docblock for why that
	 * fail-open behavior is a deliberate trade, not a bug.
	 *
	 * @param list<string> $excludedLevels
	 */
	public static function allExcept( LoggerInterface $logger, array $excludedLevels ): self {
		return new self($logger, $excludedLevels, include: false);
	}

	public function log( $level, string|\Stringable $message, array $context = [] ): void {
		if( !$this->include ) {
			if( in_array($level, $this->levels, true) ) {
				return;
			}
		} elseif( !in_array(self::ALL, $this->levels, true) && !in_array($level, $this->levels, true) ) {
			return;
		}

		$this->logger->log($level, $message, $context);
	}

}
