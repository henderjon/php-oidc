<?php

namespace Oidc;

/**
 * What a provider sent back to the redirect URL - an authorization code
 * (code flow), an ID token (implicit flow), or an error - parsed from a
 * plain params array instead of reading superglobals directly.
 */
final class IncomingAuthorizationResponse {

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
		$this->error            = self::stringOrNull($params['error'] ?? null);
		$this->errorDescription = self::stringOrNull($params['error_description'] ?? null);
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

}
