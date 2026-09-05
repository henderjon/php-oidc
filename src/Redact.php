<?php

namespace Oidc;

/**
 * Partially reveals a sensitive value for a debug log record instead of omitting it outright -
 * enough of the value survives to correlate one log line with another (the same token
 * round-tripping through two collaborators, say) without the full value ever landing in a log
 * store.
 *
 * How much is revealed scales with length, in five tiers (`$n` = VISIBLE_CHARS):
 *  - `length <= $n`: nothing - the whole value is too short to reveal any of it without
 *    revealing most of it. One `*` per character, so the output's length still matches the
 *    input's here.
 *  - `$n < length <= $n*2`: the last 3 characters only - enough to recognize a value across two
 *    log lines without giving away enough to matter for a value this short. Masked prefix is
 *    one `*` per hidden character, same reasoning as the first tier.
 *  - `$n*2 < length <= $n*3`: the last `$n` characters, masked prefix likewise one `*` per
 *    hidden character.
 *  - `$n*3 < length <= LONG_VALUE_THRESHOLD`: the first `$n` characters and the last `$n`
 *    characters, with a fixed `MASK_LENGTH`-character mask in between - not one `*` per hidden
 *    character here, deliberately: a very long value would otherwise produce a wall of
 *    asterisks that adds nothing past confirming "this was long," so the mask length is capped
 *    regardless of how much longer the value actually is.
 *  - `length > LONG_VALUE_THRESHOLD`: the same first-`$n`-and-last shape, but with
 *    `LONG_VALUE_TRAILING_VISIBLE_CHARS` revealed at the end instead of `$n` - a long enough
 *    value (a JWT, say) can afford a bit more of its tail to be shown without meaningfully
 *    weakening what the redaction is for.
 *  Checked top to bottom as a plain if/elseif chain, so `length == $n*3` lands in the third
 *  tier (last `$n` only), not the fourth - the third and fourth tiers' own boundaries overlap by
 *  exactly that one length, and checking top-to-bottom is what resolves it.
 *
 * Takes a plain `string`, not `?string` - whether a field is optional at all, and what to log
 * when it is absent, is the caller's own call to make (omit the key, log `null`, ...); this
 * class only knows how to shorten a value that exists.
 */
final class Redact {

	private const VISIBLE_CHARS = 5;

	/**
	 * Fixed middle-mask length whenever both a prefix and a suffix are revealed - see the class
	 * docblock's fourth and fifth tiers. Not scaled to the value's own length, unlike the masked
	 * prefix in the second and third tiers.
	 */
	private const MASK_LENGTH = 5;

	private const LONG_VALUE_THRESHOLD = 32;

	private const LONG_VALUE_TRAILING_VISIBLE_CHARS = 8;

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

		if( $length <= self::LONG_VALUE_THRESHOLD ) {
			return self::firstAndLast($value, self::VISIBLE_CHARS);
		}

		return self::firstAndLast($value, self::LONG_VALUE_TRAILING_VISIBLE_CHARS);
	}

	/**
	 * Masks every character except the last `$visible`, one `*` per hidden character.
	 */
	private static function maskedPrefix( string $value, int $visible ): string {
		return str_repeat('*', strlen($value) - $visible) . substr($value, -$visible);
	}

	/**
	 * Reveals the first VISIBLE_CHARS characters and the last `$trailingVisible`, with a fixed
	 * MASK_LENGTH-character mask in between regardless of how much is actually hidden.
	 */
	private static function firstAndLast( string $value, int $trailingVisible ): string {
		return substr($value, 0, self::VISIBLE_CHARS) . str_repeat('*', self::MASK_LENGTH) . substr($value, -$trailingVisible);
	}

}
