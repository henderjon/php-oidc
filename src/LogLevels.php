<?php

namespace Oidc;

/**
 * A level value LogLevelFilterLogger recognizes as "every level, unconditionally" - including
 * levels outside PSR-3's own eight defined constants (Psr\Log\LogLevel). PSR-3 never restricts
 * `$level` to those eight; any string is a legal level for a caller that defines its own. A
 * consumer who wants "let everything through" cannot get there by enumerating LogLevel's own
 * constants by hand - a custom level would still be silently dropped, since it would never
 * appear in that list. `ALL` exists as an explicit escape hatch from that.
 *
 * Not itself a real level - never pass this to a logger's own log()/debug()/etc. methods, only
 * into LogLevelFilterLogger's `$allowedLevels`.
 */
final class LogLevels {

	public const ALL = '*';

}
