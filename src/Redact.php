<?php

namespace Oidc;

/**
 * Partially reveals a sensitive value for a debug log record instead of omitting it outright -
 * enough of the value survives to correlate one log line with another (the same token
 * round-tripping through two collaborators, say) without the full value ever landing in a log
 * store. Every character not revealed is replaced with its own `*`, so the output's length
 * still matches the input's - useful on its own as a rough length signal, and consistent across
 * every tier below rather than a fixed separator that would hide how much was actually cut.
 *
 * How much is revealed scales with length, in four tiers (`$n` = VISIBLE_CHARS):
 *  - `length <= $n`: nothing - the whole value is too short to reveal any of it without
 *    revealing most of it.
 *  - `$n < length <= $n*2`: the last 3 characters only - enough to recognize a value across two
 *    log lines without giving away enough to matter for a value this short.
 *  - `$n*2 < length <= $n*3`: the last `$n` characters.
 *  - `length > $n*3`: the first `$n` characters and the last `$n` characters, with the middle
 *    masked.
 *  Checked in this order as a plain if/elseif chain, so `length == $n*3` lands in the third
 *  tier (last `$n` only), not the fourth - the two tiers' own boundaries overlap by exactly that
 *  one length, and checking top-to-bottom is what resolves it.
 *
 * Takes a plain `string`, not `?string` - whether a field is optional at all, and what to log
 * when it is absent, is the caller's own call to make (omit the key, log `null`, ...); this
 * class only knows how to shorten a value that exists.
 */
final class Redact {

	private const VISIBLE_CHARS = 5;

	public static function partial( string $value ): string {
		$length = strlen($value);

		if( $length <= self::VISIBLE_CHARS ) {
			return str_repeat('*', $length);
		}

		if( $length <= self::VISIBLE_CHARS * 2 ) {
			return self::maskedPrefix($value, 3);
		}

		if( $length <= self::VISIBLE_CHARS * 3 ) {
			return self::maskedPrefix($value, self::VISIBLE_CHARS);
		}

		$hiddenLength = $length - self::VISIBLE_CHARS * 2;

		return substr($value, 0, self::VISIBLE_CHARS) . str_repeat('*', $hiddenLength) . substr($value, -self::VISIBLE_CHARS);
	}

	/**
	 * Masks every character except the last `$visible`, one `*` per hidden character.
	 */
	private static function maskedPrefix( string $value, int $visible ): string {
		return str_repeat('*', strlen($value) - $visible) . substr($value, -$visible);
	}

}
