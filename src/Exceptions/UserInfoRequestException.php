<?php

namespace Oidc\Exceptions;

/**
 * Thrown when the userinfo endpoint cannot be reached or returns an
 * unusable response.
 */
class UserInfoRequestException extends OpenIDConnectException {

	public function __construct(
		string $message = '',
		private readonly ?int $httpStatus = null,
		private readonly ?string $rawBody = null,
		?string $state = null,
		?\Throwable $previous = null,
	) {
		parent::__construct($message, $state, $previous);
	}

	/**
	 * The response's HTTP status, when a response was actually received -
	 * null for a transport failure that never reached the server.
	 */
	public function getHttpStatus(): ?int {
		return $this->httpStatus;
	}

	/**
	 * The response's raw body, when a response was actually received - null for a transport
	 * failure that never reached the server. For a signed (`application/jwt`) response that
	 * failed further signature or claims validation, this is the same JWT that failed -
	 * decoding it (it need not be signature-valid to decode) shows every claim it carried at
	 * once, not just whichever one the specific check that failed happened to log.
	 */
	public function getRawBody(): ?string {
		return $this->rawBody;
	}

}
