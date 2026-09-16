<?php

namespace Oidc;

/**
 * Caps a string at a maximum length for a log record (or anything else with a size budget),
 * appending `...(truncated)` when it had to cut something off.
 *
 * Not a confidentiality tool - nothing here is hidden, only shortened. The full value, up to
 * the cap, is still fully visible; see `Redact` for the separate concern of obscuring a
 * sensitive value while keeping enough to correlate log lines. This exists for values that are
 * still fully attacker-controlled and unvalidated at the point they get logged (an authorization
 * callback's `state`, `error`, or `error_description` - none of them checked against anything
 * yet), so a crafted, arbitrarily large value cannot bloat or flood a log record just because
 * this library chose to log it before validating its shape.
 *
 * Cuts with `mb_strcut()`, not `substr()`: `substr()` operates on bytes, not UTF-8 codepoints,
 * and can split a multi-byte character in half at the cut point. A `state`/`error`/
 * `error_description` crafted to land a multi-byte character across the cutoff produces an
 * invalid UTF-8 byte sequence - confirmed directly, not assumed: `json_encode()` on a context
 * array containing one returns `false` for the *entire* record, not just that field, which for a
 * JSON-formatting logger means losing the whole log line this class exists to protect in the
 * first place. `mb_strcut()` cuts at the same byte length but backs off to the start of
 * whichever character would otherwise straddle it, so the result is always valid UTF-8.
 */
final class Truncate {

	/**
	 * @param int $maxLength A negative value is clamped to 0 rather than left to trigger
	 *                        substr()'s own negative-length meaning ("all but the last N
	 *                        characters") - not what a caller reaching for a max length wants,
	 *                        and not distinguishable from a real bug in whatever computed it.
	 */
	public static function to( string $value, int $maxLength ): string {
		$maxLength = max(0, $maxLength);

		return strlen($value) > $maxLength
			? mb_strcut($value, 0, $maxLength) . '...(truncated)'
			: $value;
	}

}
