<?php

namespace Oidc;

/**
 * What a provider sent back to the redirect URL - an authorization code
 * (code flow), an ID token (implicit flow), or an error - parsed from a
 * plain params array instead of reading superglobals directly.
 */
final class IncomingAuthorizationResponse {

	// The callback endpoint is public and unauthenticated - `error`/`error_description` reach
	// this class straight from the query string, with no prior state check. 255 fits
	// comfortably within a typical narrow string database column, while still leaving room
	// for a real diagnostic message - callers logging or persisting these values should not
	// need a truncation step of their own on top of this one.
	private const MAX_ERROR_FIELD_LENGTH = 255;

	public readonly ?string $code;

	public readonly ?string $idToken;

	public readonly ?string $accessToken;

	public readonly ?string $state;

	public readonly ?string $error;

	public readonly ?string $errorDescription;

	/**
	 * RFC 6749 §4.1.2.1: OPTIONAL, a URI identifying a human-readable web page describing the
	 * error, meant for a developer to follow, not text to show inline - kept separate from
	 * errorSummary()'s prose rather than folded into it.
	 */
	public readonly ?string $errorUri;

	/**
	 * @param array<string,mixed> $params The `$GET` or `$POST` array for the callback request.
	 */
	public function __construct( array $params ) {
		$this->code             = self::stringOrNull($params['code'] ?? null);
		$this->idToken          = self::stringOrNull($params['id_token'] ?? null);
		$this->accessToken      = self::stringOrNull($params['access_token'] ?? null);
		$this->state            = self::stringOrNull($params['state'] ?? null);
		$this->error            = self::truncated(self::stringOrNull($params['error'] ?? null));
		$this->errorDescription = self::truncated(self::stringOrNull($params['error_description'] ?? null));
		$this->errorUri         = self::truncated(self::stringOrNull($params['error_uri'] ?? null));
	}

	public function hasError(): bool {
		return $this->error !== null;
	}

	/**
	 * A single ready-to-log string for the provider's `error` (and
	 * `error_description`, if given), or null when there is no error.
	 */
	public function errorSummary(): ?string {
		if( $this->error === null ) {
			return null;
		}

		return $this->errorDescription !== null
			? "{$this->error}: {$this->errorDescription}"
			: $this->error;
	}

	/**
	 * Every field read here is a protocol value with a defined string shape - never legitimately
	 * an array. PHP parses a repeated query parameter (`?state[]=x`) into one, and casting that
	 * with `(string)` used to emit an `Array to string conversion` warning and silently turn it
	 * into the literal string `"Array"`, which then flowed into state/code/token lookups as if
	 * it were a real value. Checking `is_string()` first treats an array, or any other
	 * non-string scalar, the same as if the field had been absent - null, not a coerced guess.
	 */
	private static function stringOrNull( mixed $value ): ?string {
		return is_string($value) ? $value : null;
	}

	private static function truncated( ?string $value ): ?string {
		return $value === null ? null : Truncate::to($value, self::MAX_ERROR_FIELD_LENGTH);
	}

}
