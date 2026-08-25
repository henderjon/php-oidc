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
	 * @param array<string,mixed> $params The `$GET` or `$POST` array for the callback request.
	 */
	public function __construct( array $params ) {
		$this->code             = self::stringOrNull($params['code'] ?? null);
		$this->idToken          = self::stringOrNull($params['id_token'] ?? null);
		$this->accessToken      = self::stringOrNull($params['access_token'] ?? null);
		$this->state            = self::stringOrNull($params['state'] ?? null);
		$this->error            = self::truncated(self::stringOrNull($params['error'] ?? null));
		$this->errorDescription = self::truncated(self::stringOrNull($params['error_description'] ?? null));
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

	private static function stringOrNull( mixed $value ): ?string {
		return $value === null ? null : (string)$value;
	}

	private static function truncated( ?string $value ): ?string {
		return $value !== null && strlen($value) > self::MAX_ERROR_FIELD_LENGTH
			? substr($value, 0, self::MAX_ERROR_FIELD_LENGTH) . '...(truncated)'
			: $value;
	}

}
