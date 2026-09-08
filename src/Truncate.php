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
 */
final class Truncate {

	public static function to( string $value, int $maxLength ): string {
		return strlen($value) > $maxLength
			? substr($value, 0, $maxLength) . '...(truncated)'
			: $value;
	}

}
