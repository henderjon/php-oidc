<?php

namespace Oidc;

/**
 * Partially reveals a sensitive value for a debug log record instead of omitting it outright -
 * enough of the value survives to correlate one log line with another (the same token
 * round-tripping through two collaborators, say) without the full value ever landing in a log
 * store. A value too short for both ends to be shown without overlapping - meeting in the middle
 * would just be the value again - is masked outright instead.
 *
 * Takes a plain `string`, not `?string` - whether a field is optional at all, and what to log
 * when it is absent, is the caller's own call to make (omit the key, log `null`, ...); this
 * class only knows how to shorten a value that exists.
 */
final class Redact {

	private const VISIBLE_CHARS = 5;

	public static function partial( string $value ): string {
		if( $value === '' ) {
			return $value;
		}

		$length = strlen($value);

		if( $length <= self::VISIBLE_CHARS * 2 ) {
			return str_repeat('*', $length);
		}

		return substr($value, 0, self::VISIBLE_CHARS) . '...' . substr($value, -self::VISIBLE_CHARS);
	}

}
